package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

type TransportInfo struct {
	Protocol string `json:"protocol"`
	Version  string `json:"version,omitempty"`
	Length   int    `json:"length,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

type GameProtocolInfo struct {
	Layer       string `json:"layer"`
	Codec       string `json:"codec"`
	Encryption  string `json:"encryption,omitempty"`
	KeyRequired bool   `json:"key_required"`
	Detail      string `json:"detail"`
}

type GameFrameInfo struct {
	Marker           string   `json:"marker"`
	Command          uint64   `json:"command,omitempty"`
	CommandName      string   `json:"command_name,omitempty"`
	ProtocolCategory string   `json:"protocol_category,omitempty"`
	SchemaStatus     string   `json:"schema_status,omitempty"`
	SchemaSide       string   `json:"schema_side,omitempty"`
	PayloadOffset    int      `json:"payload_offset"`
	PrintableFields  []string `json:"printable_fields,omitempty"`
	DecodeStatus     string   `json:"decode_status"`
	Decoded          any      `json:"decoded,omitempty"`
	Payload          any      `json:"payload,omitempty"`
	// PlainPayloadHex is the complete decrypted inner payload after the
	// outer game package. It is retained byte-for-byte for future re-encoding
	// and custom WebSocket test messages; Payload is only its schema view.
	PlainPayloadHex string `json:"plain_payload_hex,omitempty"`
	CryptoMethod    int    `json:"crypto_method,omitempty"`
	CryptoLength    int    `json:"crypto_length,omitempty"`
	payloadBytes    []byte
}

func (f GameFrameInfo) DecodedValue(name string) any {
	if f.Decoded == nil {
		return nil
	}
	if obj, ok := f.Decoded.(map[string]any); ok {
		return obj[name]
	}
	return nil
}

type GameCrypto struct {
	Method int
	Key    []byte
}

// InferGameProtocol documents the protocol stack proven by the bundled Unity WASM.
// It deliberately does not guess a plaintext payload without a captured session key.
func InferGameProtocol() GameProtocolInfo {
	return GameProtocolInfo{
		Layer:       "websocket-binary -> game-session -> sproto",
		Codec:       "sproto request/response",
		Encryption:  "Skynet crypt DES/DH session encryption",
		KeyRequired: true,
		Detail:      "WASM contains sproto encode/decode and crypt desencode/desdecode/dhsecret; session key is required before decoding frames",
	}
}

func classifyTransportPayload(body []byte) (TransportInfo, bool) {
	if len(body) < 5 {
		return TransportInfo{}, false
	}
	typeName := map[byte]string{20: "change-cipher-spec", 21: "tls-alert", 22: "handshake", 23: "application-data", 24: "heartbeat"}[body[0]]
	if typeName == "" || body[1] != 3 || body[2] > 4 {
		return TransportInfo{}, false
	}
	length := int(body[3])<<8 | int(body[4])
	// A game frame may start with 0x15, the same value as TLS Alert. Only call
	// it TLS when the complete record declared by the TLS header is present.
	// Captured game frames such as 15 03 01 3c 51 ... declare an impossible
	// 15441-byte TLS record while the WebSocket message is only a few hundred
	// bytes long.
	if length > len(body)-5 {
		return TransportInfo{}, false
	}
	minor := map[byte]string{0: "SSL 3.0", 1: "TLS 1.0", 2: "TLS 1.1", 3: "TLS 1.2", 4: "TLS 1.3"}
	version := minor[body[2]]
	if version == "" {
		version = fmt.Sprintf("TLS record 0x%02x%02x", body[1], body[2])
	}
	detail := "TLS record payload is protected; session keys are required for plaintext"
	if typeName == "tls-alert" {
		detail = "TLS Alert record; not an application protocol message"
	}
	return TransportInfo{Protocol: typeName, Version: version, Length: length, Detail: detail}, true
}

// analyzeGameFrame extracts only facts observable from the captured bytes. It
// does not label arbitrary integers as sproto fields; full field decoding needs
// the session codec/key and is therefore reported explicitly as pending.
func analyzeGameFrame(body []byte) (GameFrameInfo, bool) {
	return analyzeGameFrameWithCrypto(body, nil)
}

func analyzeGameFrameWithCrypto(body []byte, crypto *GameCrypto) (GameFrameInfo, bool) {
	// Current captures use 0x0d/0x15/0x1d/0x55/0x5d as valid first pack
	// control bytes. They all share the low-bit Sproto pack shape; validate by
	// actually unpacking below instead of maintaining a brittle marker list.
	if len(body) < 3 {
		return GameFrameInfo{}, false
	}
	info := GameFrameInfo{Marker: fmt.Sprintf("0x%02x", body[0]), PayloadOffset: 1, DecodeStatus: "sproto pack detected"}
	if unpacked, ok := unpackSproto(body); ok {
		decoded, consumed, decodeOK := decodeSprotoObject(unpacked)
		if decodeOK {
			info.Decoded = decoded
			info.DecodeStatus = "sproto unpack successful"
			if command, ok := decoded["type"].(int); ok {
				info.Command = uint64(command)
			}
			if consumed < len(unpacked) {
				payloadBytes := unpacked[consumed:]
				if ud, ok := decoded["ud"].(map[string]any); ok {
					if method, ok := integerValue(ud["crypt_method"]); ok {
						info.CryptoMethod = method
					}
					if length, ok := integerValue(ud["crypt_length"]); ok {
						info.CryptoLength = length
					}
				}
				if crypto != nil && info.CryptoMethod > 0 && len(crypto.Key) > 0 {
					// crypt_length belongs to the inner package userdata and is not
					// the number of bytes to decrypt in the following payload. The
					// bundled client applies the session transform to the complete
					// payload; limiting it to crypt_length leaves the tail as the
					// repeated encrypted pattern (a29fcaab) seen in long responses.
					payloadBytes = cryptPayload(payloadBytes, info.CryptoMethod, crypto.Key)
					info.DecodeStatus = "sproto package and encrypted payload decrypted"
				} else if info.CryptoMethod > 0 {
					info.DecodeStatus = "sproto package decoded; session-key-required"
				}
				info.PlainPayloadHex = hex.EncodeToString(payloadBytes)
				payload, decodedBytes, payloadOK := decodePayloadCandidates(payloadBytes)
				if payloadOK {
					info.payloadBytes = append([]byte(nil), decodedBytes...)
					info.Payload = payload
					if info.CryptoMethod == 0 {
						info.DecodeStatus = "sproto package and payload decoded"
					}
				} else {
					info.PlainPayloadHex = hex.EncodeToString(payloadBytes)
					info.Payload = map[string]any{"raw_hex": hex.EncodeToString(payloadBytes), "decode_status": "payload-unrecognized-or-encrypted"}
				}
			}
			if containsFatalUnrecognizedPayload(info.Payload) {
				info.DecodeStatus = "sproto package decoded; payload encrypted-or-unknown"
			}
		}
	}
	for i := 2; i < len(body); {
		start := i
		for i < len(body) && (body[i] >= 0x20 && body[i] <= 0x7e) {
			i++
		}
		if i-start >= 4 {
			text := strings.TrimSpace(string(body[start:i]))
			if text != "" && !allDigits(text) {
				info.PrintableFields = append(info.PrintableFields, text)
			}
		}
		if i == start {
			i++
		}
	}
	return info, true
}

func decodePayloadCandidates(data []byte) (map[string]any, []byte, bool) {
	if decoded, _, ok := decodeSprotoObject(data); ok {
		return decoded, data, true
	}
	if unpacked, ok := unpackSproto(data); ok {
		if decoded, _, ok := decodeSprotoObject(unpacked); ok {
			return decoded, unpacked, true
		}
	}
	return nil, nil, false
}

func integerValue(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case uint64:
		return int(n), true
	default:
		return 0, false
	}
}

func cryptPayload(src []byte, method int, key []byte) []byte {
	if len(src) == 0 || len(key) == 0 {
		return src
	}
	out := append([]byte(nil), src...)
	switch method {
	case 1:
		for i := range out {
			out[i] ^= key[i%len(key)]
		}
	case 2:
		return rc4Crypt(out, key)
	}
	return out
}

func rc4Crypt(src, key []byte) []byte {
	var s [256]byte
	for i := range s {
		s[i] = byte(i)
	}
	j := 0
	for i := 0; i < 256; i++ {
		j = (j + int(s[i]) + int(key[i%len(key)])) & 255
		s[i], s[j] = s[j], s[i]
	}
	out := make([]byte, len(src))
	i, j := 0, 0
	for n, b := range src {
		i = (i + 1) & 255
		j = (j + int(s[i])) & 255
		s[i], s[j] = s[j], s[i]
		out[n] = b ^ s[(int(s[i])+int(s[j]))&255]
	}
	return out
}

func annotateGameFrame(frame *GameFrameInfo, commands map[uint64]ProtocolCommand) {
	annotateGameFrameDirection(frame, commands, "")
}

func annotateGameFrameDirection(frame *GameFrameInfo, commands map[uint64]ProtocolCommand, direction string) {
	if frame == nil || frame.Command == 0 {
		return
	}
	if commands == nil {
		frame.SchemaStatus = "current-schema-unavailable"
		return
	}
	if command, ok := commandForDirection(frame.Command, direction, commands); ok {
		frame.CommandName = command.Name
		frame.ProtocolCategory = command.Category
		frame.SchemaStatus = "schema-command-matched"
	} else {
		frame.SchemaStatus = "current-schema-command-not-found"
	}
}

func decodeCommandPayload(frame *GameFrameInfo, command ProtocolCommand, direction string) {
	if frame == nil || len(frame.payloadBytes) == 0 {
		return
	}
	fields := command.ReqFields
	rootType := command.ReqType
	frame.SchemaSide = "request"
	if direction == "response" && len(command.RspFields) > 0 {
		fields = command.RspFields
		rootType = command.RspType
		frame.SchemaSide = "response"
	}
	if len(fields) == 0 && rootType != "" {
		if rootFields, ok := schemaFieldsForType(rootType); ok {
			fields = rootFields
		}
	}
	names := make(map[int]string, len(fields))
	types := make(map[string]string, len(fields))
	for _, field := range fields {
		var tag int
		if _, err := fmt.Sscan(field.Tag, &tag); err == nil {
			names[tag] = field.Name
			types[field.Name] = strings.TrimSpace(strings.SplitN(field.Type, "#", 2)[0])
		}
	}
	if decoded, _, ok := decodeSprotoObjectNamedBusiness(frame.payloadBytes, names); ok {
		normalizeTypedFields(decoded, types)
		normalizeKnownNested(decoded, command.Name)
		frame.Payload = decoded
		if !containsUnrecognizedPayload(decoded) {
			frame.DecodeStatus = "sproto payload plaintext decoded"
		}
	}
}

func schemaFieldsForType(typ string) ([]Field, bool) {
	base := normalizeEncodeType(strings.TrimPrefix(strings.TrimSpace(typ), "*"))
	fields, ok := schemaRegistry[base]
	if !ok && strings.Contains(base, ".") {
		// A command field may refer to a globally declared type while a nested
		// field was qualified relative to its owner. Try the exact qualified
		// name only; never fall back to an unrelated same-named local type.
		fields, ok = schemaRegistry[base]
	}
	return fields, ok
}

// normalizeKnownNested applies the extracted current-version schema to the
// long encrypted save_client_data payload. The generic decoder cannot infer
// named fields for user-defined nested types, and would otherwise expose
// valid bytes under misleading tag/type names.
func normalizeKnownNested(value map[string]any, commandName string) {
	if commandName != "save_client_data" {
		return
	}
	data, ok := value["data"].(map[string]any)
	if !ok {
		return
	}
	if _, exists := data["law_point"]; !exists {
		if v, exists := data["type"]; exists {
			data["law_point"] = v
			delete(data, "type")
		}
		if v, exists := data["tag_0"]; exists {
			data["law_point"] = v
			delete(data, "tag_0")
		}
	}
	if v, exists := data["law_point"]; exists {
		data["law_point"] = normalizeIntegerBlob(v)
	}
	if raw, exists := data["session"]; exists {
		data["survivor"] = decodeSurvivorBlob(raw)
		delete(data, "session")
	} else if raw, exists := data["tag_1"]; exists {
		data["survivor"] = normalizeSurvivorList(raw)
		delete(data, "tag_1")
	}
}

func decodeSurvivorBlob(v any) any {
	if obj, ok := v.(map[string]any); ok {
		if x, exists := obj["type"]; exists {
			obj["sid"] = normalizeIntegerBlob(x)
			delete(obj, "type")
		}
		if x, exists := obj["session"]; exists {
			obj["survivor"] = normalizeSurvivorList(x)
			delete(obj, "session")
		}
		return obj
	}
	s, ok := v.(string)
	if !ok {
		return normalizeSurvivorList(v)
	}
	raw, err := hex.DecodeString(s)
	if err != nil {
		raw = []byte(s)
	}
	var items []any
	for len(raw) >= 4 {
		length := int(binary.LittleEndian.Uint32(raw[:4]))
		raw = raw[4:]
		if length <= 0 || length > len(raw) {
			break
		}
		decoded, consumed, ok := decodeSprotoObjectNamed(raw[:length], map[int]string{0: "sid", 1: "res601", 2: "res602", 3: "res603", 4: "res604", 5: "res607"})
		if !ok || consumed != length {
			break
		}
		normalizeSurvivorFields(decoded)
		items = append(items, decoded)
		raw = raw[length:]
	}
	if len(items) > 0 && len(raw) == 0 {
		return items
	}
	return map[string]any{"raw_hex": hex.EncodeToString(raw), "decode_status": "nested-client-data-unrecognized"}
}

func normalizeSurvivorFields(value map[string]any) {
	value["sid"] = normalizeIntegerBlob(value["sid"])
	for _, name := range []string{"res601", "res602", "res603", "res604", "res607"} {
		if s, ok := value[name].(string); ok && len(s) == 16 {
			if raw, err := hex.DecodeString(s); err == nil {
				value[name] = math.Float64frombits(binary.LittleEndian.Uint64(raw))
				continue
			}
		}
		obj, ok := value[name].(map[string]any)
		if !ok {
			continue
		}
		s, ok := obj["raw_hex"].(string)
		if !ok {
			continue
		}
		raw, err := hex.DecodeString(s)
		if err == nil && len(raw) == 8 {
			value[name] = math.Float64frombits(binary.LittleEndian.Uint64(raw))
		}
	}
}

func normalizeIntegerBlob(v any) any {
	obj, ok := v.(map[string]any)
	if !ok {
		return v
	}
	s, ok := obj["raw_hex"].(string)
	if !ok {
		return v
	}
	raw, err := hex.DecodeString(s)
	if err != nil {
		return v
	}
	if len(raw) == 4 {
		return int(int32(binary.LittleEndian.Uint32(raw)))
	}
	if len(raw) == 8 {
		return int64(binary.LittleEndian.Uint64(raw))
	}
	return v
}

func normalizeSurvivorList(v any) any {
	if obj, ok := v.(map[string]any); ok {
		if _, exists := obj["raw_hex"]; exists {
			return obj
		}
		for key, child := range obj {
			if strings.HasPrefix(key, "tag_") {
				delete(obj, key)
				obj[strings.TrimPrefix(key, "tag_")] = child
			}
		}
		return obj
	}
	if list, ok := v.([]any); ok {
		for _, item := range list {
			normalizeSurvivorList(item)
		}
	}
	return v
}

func normalizeTypedFields(value map[string]any, types map[string]string) {
	for name, typ := range types {
		v, exists := value[name]
		if !exists {
			continue
		}
		base := strings.TrimSpace(strings.TrimPrefix(typ, "*"))
		if idx := strings.IndexByte(base, '('); idx >= 0 {
			base = base[:idx]
		}
		base = strings.TrimSuffix(base, "()")
		if s, ok := v.(string); ok && strings.HasPrefix(strings.TrimSpace(typ), "*") && base == "string" {
			raw := []byte(s)
			out := make([]any, 0)
			left := raw
			for len(left) >= 4 {
				n := int(binary.LittleEndian.Uint32(left[:4]))
				left = left[4:]
				if n > len(left) {
					out = nil
					break
				}
				out = append(out, string(left[:n]))
				left = left[n:]
			}
			if out != nil && len(left) == 0 {
				value[name] = out
				continue
			}
		}
		obj, ok := v.(map[string]any)
		if !ok || obj["raw_hex"] == nil {
			continue
		}
		raw, err := hex.DecodeString(fmt.Sprint(obj["raw_hex"]))
		if err != nil {
			continue
		}
		if len(raw) == 0 {
			if strings.HasPrefix(strings.TrimSpace(typ), "*") {
				value[name] = []any{}
			} else if _, known := schemaFieldsForType(typ); known {
				value[name] = map[string]any{}
			} else if base == "string" || base == "binary" {
				value[name] = ""
			}
			continue
		}
		switch {
		case (strings.HasPrefix(base, "integer") || base == "boolean") && len(raw) == 4:
			value[name] = int(int32(binary.LittleEndian.Uint32(raw)))
		case strings.HasPrefix(base, "integer") && len(raw) == 8:
			value[name] = int64(binary.LittleEndian.Uint64(raw))
		case base == "double" && len(raw) == 8:
			value[name] = math.Float64frombits(binary.LittleEndian.Uint64(raw))
		case base == "string" && !strings.HasPrefix(strings.TrimSpace(typ), "*"):
			value[name] = string(raw)
		case strings.HasPrefix(strings.TrimSpace(typ), "*") && (base == "integer" || base == "boolean" || base == "double"):
			value[name] = normalizeSchemaValue(raw, typ)
		default:
			value[name] = normalizeSchemaValue(raw, typ)
		}
		continue
	}
}

func normalizeSchemaValue(raw []byte, typ string) any {
	base := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(typ), "*"))
	isList := strings.HasPrefix(strings.TrimSpace(typ), "*")
	if idx := strings.IndexByte(base, '('); idx >= 0 {
		base = base[:idx]
	}
	base = strings.TrimSuffix(base, "()")
	if isList && len(raw) == 0 {
		return []any{}
	}
	fields, ok := schemaFieldsForType(base)
	if !ok {
		if isList && base == "string" {
			out := make([]any, 0)
			left := raw
			for len(left) >= 4 {
				n := int(binary.LittleEndian.Uint32(left[:4]))
				left = left[4:]
				if n < 0 || n > len(left) {
					return map[string]any{"raw_hex": hex.EncodeToString(raw), "decode_status": "string-array-unrecognized"}
				}
				out = append(out, string(left[:n]))
				left = left[n:]
			}
			if len(left) == 0 {
				return out
			}
		}
		if isList && (base == "integer" || base == "double") && len(raw) >= 1 {
			width := int(raw[0])
			raw = raw[1:]
			if (width == 4 || width == 8) && len(raw)%width == 0 {
				out := make([]any, 0, len(raw)/width)
				for len(raw) > 0 {
					if width == 4 {
						out = append(out, int(int32(binary.LittleEndian.Uint32(raw[:4]))))
					} else if base == "double" {
						out = append(out, math.Float64frombits(binary.LittleEndian.Uint64(raw[:8])))
					} else {
						out = append(out, int64(binary.LittleEndian.Uint64(raw[:8])))
					}
					raw = raw[width:]
				}
				return out
			}
		}
		if isList && base == "boolean" {
			out := make([]any, len(raw))
			for i, b := range raw {
				out[i] = b != 0
			}
			return out
		}
		if len(raw) == 0 {
			return ""
		}
		if base == "binary" || base == "userdata" || isList {
			return hex.EncodeToString(raw)
		}
		if generic, consumed, valid := decodeSprotoObject(raw); valid && consumed == len(raw) {
			normalizeGenericNested(generic)
			return generic
		}
		return map[string]any{"raw_hex": hex.EncodeToString(raw), "decode_status": "schema-type-not-found"}
	}
	names := map[int]string{}
	for _, f := range fields {
		var tag int
		if _, err := fmt.Sscan(f.Tag, &tag); err == nil {
			names[tag] = f.Name
		}
	}
	decodeOne := func(blob []byte) (map[string]any, bool) {
		if unpacked, unpackOK := unpackSproto(blob); unpackOK {
			if obj, consumed, ok := decodeSprotoObjectNamedBusiness(unpacked, names); ok && onlyZeroPadding(unpacked[consumed:]) {
				return obj, true
			}
		}
		obj, consumed, ok := decodeSprotoObjectNamedBusiness(blob, names)
		if ok && consumed == len(blob) {
			return obj, true
		}
		return nil, false
	}
	if isList {
		var out []any
		// sproto.c decode_array: integer/double arrays contain a dword
		// payload length, one byte element width, then packed values.
		if base == "integer" || base == "boolean" || base == "double" {
			if len(raw) >= 1 {
				width := int(raw[0])
				raw = raw[1:]
				if (base == "boolean" && width == 1) || (base != "boolean" && (width == 4 || width == 8)) {
					if len(raw)%width == 0 {
						for len(raw) > 0 {
							if width == 1 {
								out = append(out, raw[0] != 0)
							} else if width == 4 {
								out = append(out, int(int32(binary.LittleEndian.Uint32(raw[:4]))))
							} else {
								out = append(out, math.Float64frombits(binary.LittleEndian.Uint64(raw[:8])))
							}
							raw = raw[width:]
						}
						return out
					}
				}
			}
			return map[string]any{"raw_hex": hex.EncodeToString(raw), "decode_status": "scalar-array-unrecognized"}
		}
		for len(raw) >= 4 {
			n := int(binary.LittleEndian.Uint32(raw[:4]))
			raw = raw[4:]
			if n <= 0 || n > len(raw) {
				break
			}
			obj, ok := decodeOne(raw[:n])
			if !ok {
				break
			}
			fieldTypes := map[string]string{}
			for _, f := range fields {
				fieldTypes[f.Name] = f.Type
			}
			normalizeTypedFields(obj, fieldTypes)
			out = append(out, obj)
			raw = raw[n:]
		}
		if len(out) > 0 && len(raw) == 0 {
			return out
		}
		// Scalar lists are emitted as a sequence of fixed-width values by the
		// game. Decode those directly when no element framing is present.
		if base == "integer" || base == "boolean" {
			if len(raw)%4 == 0 {
				out := make([]any, 0, len(raw)/4)
				for len(raw) > 0 {
					out = append(out, int(int32(binary.LittleEndian.Uint32(raw[:4]))))
					raw = raw[4:]
				}
				return out
			}
		}
		return map[string]any{"raw_hex": hex.EncodeToString(raw), "decode_status": "array-unrecognized"}
	}
	if obj, ok := decodeOne(raw); ok {
		fieldTypes := map[string]string{}
		for _, f := range fields {
			fieldTypes[f.Name] = f.Type
		}
		normalizeTypedFields(obj, fieldTypes)
		return obj
	}
	if base == "bind_info" {
		if text := extractPrintableSegments(raw); len(text) > 0 {
			return map[string]any{"plaintext_segments": text, "decode_status": "plaintext-extracted-schema-unmatched"}
		}
	}
	if unpacked, unpackOK := unpackSproto(raw); unpackOK {
		if obj, consumed, ok := decodeSprotoObjectNamedBusiness(unpacked, names); ok && onlyZeroPadding(unpacked[consumed:]) {
			fieldTypes := map[string]string{}
			for _, f := range fields {
				fieldTypes[f.Name] = f.Type
			}
			normalizeTypedFields(obj, fieldTypes)
			return obj
		}
	}
	return map[string]any{"raw_hex": hex.EncodeToString(raw), "decode_status": "nested-unrecognized"}
}

func extractPrintableSegments(raw []byte) []string {
	var out []string
	start := -1
	flush := func(end int) {
		if start >= 0 && end-start >= 2 {
			out = append(out, string(raw[start:end]))
		}
		start = -1
	}
	for i, b := range raw {
		if b >= 0x20 && b <= 0x7e {
			if start < 0 {
				start = i
			}
		} else {
			flush(i)
		}
	}
	flush(len(raw))
	return out
}

func onlyZeroPadding(data []byte) bool {
	for _, b := range data {
		if b != 0 {
			return false
		}
	}
	return true
}

func normalizeGenericNested(value map[string]any) {
	for key, child := range value {
		switch x := child.(type) {
		case map[string]any:
			if raw, ok := x["raw_hex"].(string); ok {
				if bytes, err := hex.DecodeString(raw); err == nil {
					if nested, consumed, valid := decodeSprotoObject(bytes); valid && consumed == len(bytes) {
						normalizeGenericNested(nested)
						value[key] = nested
					}
				}
			} else {
				normalizeGenericNested(x)
			}
		case []any:
			for _, item := range x {
				if obj, ok := item.(map[string]any); ok {
					normalizeGenericNested(obj)
				}
			}
		}
	}
}

// unpackSproto reverses cloudwu sproto's zero-run packing. 0xff is an
// extension marker followed by the number of additional eight-byte segments.
func unpackSproto(src []byte) ([]byte, bool) {
	out := make([]byte, 0, len(src)*2)
	for i := 0; i < len(src); {
		h := src[i]
		i++
		if h == 0xff {
			if i >= len(src) {
				return nil, false
			}
			segments := int(src[i]) + 1
			i++
			if i+segments*8 > len(src) {
				return nil, false
			}
			out = append(out, src[i:i+segments*8]...)
			i += segments * 8
			continue
		}
		for bit := 0; bit < 8; bit++ {
			if h&(1<<bit) != 0 {
				if i >= len(src) {
					return nil, false
				}
				out = append(out, src[i])
				i++
			} else {
				out = append(out, 0)
			}
		}
	}
	return out, true
}

// packSproto mirrors the verified game-side sproto_pack algorithm. It is used when
// a complete plaintext payload is later re-embedded into a WebSocket message.
func packSproto(src []byte) []byte {
	out := make([]byte, 0, len(src)+len(src)/8+2)
	for i := 0; i < len(src); {
		end := i + 8
		if end > len(src) {
			end = len(src)
		}
		var seg [8]byte
		copy(seg[:], src[i:end])
		nz := 0
		for _, b := range seg {
			if b != 0 {
				nz++
			}
		}
		if nz == 8 {
			count := 0
			for count < 256 && i+count*8+8 <= len(src) {
				part := src[i+count*8 : i+count*8+8]
				n := 0
				for _, b := range part {
					if b != 0 {
						n++
					}
				}
				if count > 0 && n < 6 {
					break
				}
				count++
			}
			out = append(out, 0xff, byte(count-1))
			out = append(out, src[i:i+count*8]...)
			i += count * 8
			continue
		}
		header := byte(0)
		values := make([]byte, 0, nz)
		for bit, b := range seg {
			if b != 0 {
				header |= 1 << bit
				values = append(values, b)
			}
		}
		out = append(out, header)
		out = append(out, values...)
		i += 8
	}
	return out
}

func decodeSprotoObject(data []byte) (map[string]any, int, bool) {
	return decodeSprotoObjectNamed(data, nil)
}

func decodeSprotoObjectNamedBusiness(data []byte, names map[int]string) (map[string]any, int, bool) {
	return decodeSprotoObjectNamedMode(data, names, false)
}

func decodeSprotoObjectNamed(data []byte, names map[int]string) (map[string]any, int, bool) {
	return decodeSprotoObjectNamedMode(data, names, true)
}

func decodeSprotoObjectNamedMode(data []byte, names map[int]string, transport bool) (map[string]any, int, bool) {
	if len(data) < 2 {
		return nil, 0, false
	}
	fn := int(binary.LittleEndian.Uint16(data[:2]))
	if fn < 0 || fn > 1024 || len(data) < 2+fn*2 {
		return nil, 0, false
	}
	result := map[string]any{}
	stream := data[2+fn*2:]
	consumed := 2 + fn*2
	tag := -1
	for i := 0; i < fn; i++ {
		raw := int(binary.LittleEndian.Uint16(data[2+i*2:]))
		tag++
		if raw&1 != 0 {
			tag += raw / 2
			continue
		}
		value := raw/2 - 1
		name := fmt.Sprintf("tag_%d", tag)
		if named := names[tag]; named != "" {
			name = named
		} else if transport {
			switch tag {
			case 0:
				name = "type"
			case 1:
				name = "session"
			case 2:
				name = "ud"
			}
		}
		if value >= 0 {
			result[name] = value
			continue
		}
		if len(stream) < 4 {
			return nil, 0, false
		}
		length := int(binary.LittleEndian.Uint32(stream[:4]))
		stream = stream[4:]
		if length < 0 || length > len(stream) {
			return nil, 0, false
		}
		blob := stream[:length]
		stream = stream[length:]
		consumed += 4 + length
		if !transport {
			result[name] = map[string]any{"raw_hex": hex.EncodeToString(blob)}
			continue
		}
		if transport && tag == 1 {
			if session, ok := decodePackageSession(blob); ok {
				result[name] = session
				continue
			}
		}
		if transport && tag == 2 {
			if len(blob) == 0 {
				result[name] = ""
			} else if nested, nestedConsumed, ok := decodeSprotoObjectNamed(blob, map[int]string{0: "crypt_method", 1: "crypt_length"}); ok && nestedConsumed == len(blob) {
				result[name] = nested
			} else {
				result[name] = map[string]any{"raw_hex": hex.EncodeToString(blob), "decode_status": "payload-unrecognized-or-encrypted"}
			}
		} else if len(blob) == 0 {
			result[name] = ""
		} else if nested, nestedConsumed, ok := decodeSprotoObjectNamedMode(blob, nil, transport); ok && nestedConsumed == len(blob) {
			// Payload fields can themselves contain an unpacked sproto object.
			result[name] = nested
		} else if printable := strings.TrimSpace(string(blob)); printable != "" && isLikelyText(blob, printable) {
			result[name] = printable
		} else if packed, unpackOK := unpackSproto(blob); unpackOK {
			if nested, consumed, decodeOK := decodeSprotoObject(packed); decodeOK && consumed == len(packed) {
				result[name] = nested
			} else {
				result[name] = map[string]any{"raw_hex": hex.EncodeToString(blob), "decode_status": "payload-unrecognized-or-encrypted"}
			}
		} else if printable := strings.TrimSpace(string(blob)); printable != "" && isLikelyText(blob, printable) {
			result[name] = printable
		} else {
			result[name] = hex.EncodeToString(blob)
		}
	}
	return result, consumed, true
}

func decodeSessionTimestamp(blob []byte) (string, bool) {
	if len(blob) != 4 {
		return "", false
	}
	seconds := binary.LittleEndian.Uint32(blob)
	// Evidence from the current capture shows session field 1dc2866a is a
	// little-endian Unix timestamp. Restrict this interpretation to plausible
	// contemporary timestamps so ordinary four-byte session values remain raw.
	if seconds < 946684800 || seconds > 4102444800 {
		return "", false
	}
	// The current protocol's session timestamp is observed as a server-time
	// value with the low byte in the 0x1d range. Reject unrelated four-byte
	// binary values instead of presenting them as time.
	if blob[0] < 0x10 || blob[0] > 0x2f || blob[1] != 0xc2 || blob[3] != 0x6a {
		return "", false
	}
	return time.Unix(int64(seconds), 0).In(time.Local).Format("2006-01-02 15:04:05"), true
}

// decodePackageSession follows the sproto C integer representation used by
// .package.session. Four-byte values are ordinary unsigned 32-bit integers;
// only the historically observed timestamp-shaped values are rendered as a
// local time string. Debug-injected high sessions must remain numeric so they
// can match the pending command table.
func decodePackageSession(blob []byte) (any, bool) {
	if session, ok := decodeSessionTimestamp(blob); ok {
		return session, true
	}
	if len(blob) == 4 {
		return int(binary.LittleEndian.Uint32(blob)), true
	}
	return nil, false
}

func isPrintable(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) || r == '\uFFFD' {
			return false
		}
	}
	return true
}

func isLikelyText(raw []byte, s string) bool {
	if !utf8.Valid(raw) || !isPrintable(s) {
		return false
	}
	if len(raw) == 0 {
		return false
	}
	// Arbitrary encrypted bytes can form valid UTF-8 by chance. Protocol text
	// fields observed in the game are ASCII; require a strong ASCII signal for
	// short/binary-looking blobs and keep genuine UTF-8 text intact.
	ascii := 0
	for _, b := range raw {
		if b >= 0x20 && b <= 0x7e {
			ascii++
		}
	}
	return ascii*100 >= len(raw)*70
}

func containsUnrecognizedPayload(v any) bool {
	switch x := v.(type) {
	case map[string]any:
		if _, ok := x["raw_hex"]; ok {
			return true
		}
		if status, ok := x["decode_status"].(string); ok && status != "" {
			return true
		}
		for _, child := range x {
			if containsUnrecognizedPayload(child) {
				return true
			}
		}
	case []any:
		for _, child := range x {
			if containsUnrecognizedPayload(child) {
				return true
			}
		}
	}
	return false
}

func containsFatalUnrecognizedPayload(v any) bool {
	obj, ok := v.(map[string]any)
	if !ok {
		return false
	}
	if _, raw := obj["raw_hex"]; raw {
		return true
	}
	if status, exists := obj["decode_status"].(string); exists && status != "" && len(obj) <= 2 {
		return true
	}
	return false
}

func allDigits(s string) bool {
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return s != ""
}
