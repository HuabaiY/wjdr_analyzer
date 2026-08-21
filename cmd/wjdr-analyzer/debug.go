package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"strconv"
	"strings"
)

type debugRequest struct {
	RecordID uint64          `json:"record_id"`
	Payload  json.RawMessage `json:"payload"`
}
type debugResult struct {
	OK       bool   `json:"ok"`
	RecordID uint64 `json:"record_id"`
	Command  string `json:"command"`
	WireHex  string `json:"wire_hex,omitempty"`
	Error    string `json:"error,omitempty"`
}

func (a *Analyzer) nextPackageSession(session string, command uint64) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.packageMax == nil {
		a.packageMax = make(map[string]int)
	}
	if a.debugSessionSeq == nil {
		a.debugSessionSeq = make(map[string]int)
	}
	if a.pending == nil {
		a.pending = make(map[string]map[int]uint64)
	}
	// Debug requests use a separate high range so the game's own request
	// counter can continue unchanged. Responses in this range are consumed by
	// the analyzer and are not forwarded to the game client.
	a.debugSessionSeq[session]++
	max := 1_000_000_000 + a.debugSessionSeq[session]
	if a.pending[session] == nil {
		a.pending[session] = make(map[int]uint64)
	}
	a.pending[session][max] = command
	if a.injectedSessions == nil {
		a.injectedSessions = make(map[string]map[int]struct{})
	}
	if a.injectedSessions[session] == nil {
		a.injectedSessions[session] = make(map[int]struct{})
	}
	a.injectedSessions[session][max] = struct{}{}
	return max
}

func (a *Analyzer) isInjectedResponse(session string, body []byte) bool {
	unpacked, ok := unpackSproto(body)
	if !ok {
		return false
	}
	decoded, _, ok := decodeSprotoObject(unpacked)
	if !ok {
		return false
	}
	n, ok := integerValue(normalizeIntegerBlob(decoded["session"]))
	if !ok {
		n, ok = integerValue(normalizeIntegerBlob(decoded["tag_1"]))
	}
	if !ok {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	_, exists := a.injectedSessions[session][n]
	if exists {
		delete(a.injectedSessions[session], n)
	}
	return exists
}

func (a *Analyzer) debugSend(raw []byte) (debugResult, error) {
	var req debugRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return debugResult{}, fmt.Errorf("invalid debug request: %w", err)
	}
	if req.RecordID == 0 || len(req.Payload) == 0 {
		return debugResult{}, fmt.Errorf("record_id and payload are required")
	}
	record, err := a.recordByID(req.RecordID)
	if err != nil {
		return debugResult{}, err
	}
	if record.Kind != "websocket-frame" || record.Direction != "request" {
		return debugResult{}, fmt.Errorf("debug send requires a captured request frame")
	}
	frame := record.GameFrame
	if frame == nil || frame.Command == 0 {
		return debugResult{}, fmt.Errorf("request has no decoded command")
	}
	command, ok := commandForDirection(frame.Command, "request", a.commands)
	if !ok || command.Category != "req" {
		return debugResult{}, fmt.Errorf("request schema not found for command %d", frame.Command)
	}
	var payload map[string]any
	if err := json.Unmarshal(req.Payload, &payload); err != nil {
		return debugResult{}, fmt.Errorf("payload must be a JSON object: %w", err)
	}
	plain, err := encodeSchemaObject(payload, command.ReqFields)
	if err != nil {
		return debugResult{}, err
	}
	// Prove the edited JSON survives the complete schema codec before writing
	// to the live socket. This catches unsupported nested/list representations
	// without sending a malformed request to the game server.
	check := GameFrameInfo{payloadBytes: plain}
	decodeCommandPayload(&check, command, "request")
	if containsUnrecognizedPayload(check.Payload) || !jsonEqualNormalized(payload, check.Payload) {
		return debugResult{}, fmt.Errorf("payload schema roundtrip mismatch: decoded=%s", mustJSON(check.Payload))
	}
	a.mu.Lock()
	session := a.wsSessions[record.Session]
	crypto, hasCrypto := a.cryptoAt[record.ID]
	if !hasCrypto {
		crypto, hasCrypto = a.crypto[record.Session]
	}
	a.mu.Unlock()
	if session == nil {
		return debugResult{}, fmt.Errorf("WSS session %s is no longer active", record.Session)
	}
	sessionID := a.nextPackageSession(record.Session, frame.Command)
	if frame.CryptoMethod == 0 {
		outer, err := encodePackage(frame.Command, sessionID, nil)
		if err != nil {
			return debugResult{}, err
		}
		wire := packSproto(append(outer, plain...))
		if err := session.SendBinaryToServer(wire); err != nil {
			return debugResult{}, fmt.Errorf("write real WSS: %w", err)
		}
		return debugResult{OK: true, RecordID: req.RecordID, Command: command.Name, WireHex: hex.EncodeToString(wire)}, nil
	}
	if !hasCrypto || len(crypto.Key) == 0 {
		return debugResult{}, fmt.Errorf("session %s has no current encryption key", record.Session)
	}
	method := frame.CryptoMethod
	if method == 0 {
		method = crypto.Method
	}
	if method == 0 {
		return debugResult{}, fmt.Errorf("request %d has no proven encryption method", req.RecordID)
	}
	userdata, _ := encodeSchemaObject(map[string]any{"crypt_method": method, "crypt_length": len(plain)}, []Field{{Name: "crypt_method", Tag: "0", Type: "integer"}, {Name: "crypt_length", Tag: "1", Type: "integer"}})
	outer, err := encodePackage(frame.Command, sessionID, userdata)
	if err != nil {
		return debugResult{}, err
	}
	// Captured requests prove crypt_length is the exact schema object length.
	// The apparent extra byte after decryption is outer Sproto block padding,
	// not an additional inner pack layer, so encrypt the raw schema object.
	wire := packSproto(append(outer, cryptPayload(plain, method, crypto.Key)...))
	if err := session.SendBinaryToServer(wire); err != nil {
		return debugResult{}, fmt.Errorf("write real WSS: %w", err)
	}
	return debugResult{OK: true, RecordID: req.RecordID, Command: command.Name, WireHex: hex.EncodeToString(wire)}, nil
}

func encodePackage(command uint64, session int, userdata []byte) ([]byte, error) {
	fields := map[int]any{0: int(command), 1: session}
	if len(userdata) > 0 {
		fields[2] = userdata
	}
	return encodeRawFields(fields)
}

func jsonEqualNormalized(a, b any) bool {
	left, err1 := json.Marshal(a)
	right, err2 := json.Marshal(b)
	if err1 != nil || err2 != nil {
		return false
	}
	var lv, rv any
	if json.Unmarshal(left, &lv) != nil || json.Unmarshal(right, &rv) != nil {
		return false
	}
	return reflect.DeepEqual(lv, rv)
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(b)
}

func encodeSchemaObject(value map[string]any, fields []Field) ([]byte, error) {
	byName := map[string]Field{}
	for _, f := range fields {
		byName[f.Name] = f
	}
	raw := map[int]any{}
	for name, v := range value {
		f, ok := byName[name]
		if !ok {
			return nil, fmt.Errorf("unknown schema field %q", name)
		}
		tag, _ := strconv.Atoi(f.Tag)
		enc, err := encodeTypedValue(v, f.Type)
		if err != nil {
			return nil, fmt.Errorf("field %s: %w", name, err)
		}
		raw[tag] = enc
	}
	return encodeRawFields(raw)
}

func encodeTypedValue(v any, typ string) (any, error) {
	t := strings.TrimSpace(typ)
	if strings.HasPrefix(t, "*") {
		arr, ok := v.([]any)
		if !ok {
			return nil, fmt.Errorf("expected array")
		}
		base := normalizeEncodeType(strings.TrimPrefix(t, "*"))
		if base == "integer" || base == "boolean" {
			width := 4
			out := []byte{byte(width)}
			for _, item := range arr {
				n, ok := integerValue(item)
				if !ok {
					if f, fok := item.(float64); fok && f == float64(int(f)) {
						n, ok = int(f), true
					}
				}
				if !ok {
					if b, bok := item.(bool); bok {
						if b {
							n = 1
						}
						ok = true
					}
				}
				if !ok {
					return nil, fmt.Errorf("expected scalar array")
				}
				var raw [4]byte
				binary.LittleEndian.PutUint32(raw[:], uint32(int32(n)))
				out = append(out, raw[:]...)
			}
			return out, nil
		}
		if base == "double" {
			out := []byte{8}
			for _, item := range arr {
				f, ok := item.(float64)
				if !ok {
					if n, nok := integerValue(item); nok {
						f, ok = float64(n), true
					}
				}
				if !ok {
					return nil, fmt.Errorf("expected double array")
				}
				var raw [8]byte
				binary.LittleEndian.PutUint64(raw[:], math.Float64bits(f))
				out = append(out, raw[:]...)
			}
			return out, nil
		}
		out := make([][]byte, 0, len(arr))
		for _, item := range arr {
			b, err := encodeTypedValue(item, base)
			if err != nil {
				return nil, err
			}
			rb, ok := b.([]byte)
			if !ok {
				return nil, fmt.Errorf("array element unsupported")
			}
			out = append(out, rb)
		}
		return encodeArrayRaw(out), nil
	}
	base := normalizeEncodeType(t)
	switch base {
	case "integer":
		n, ok := integerValue(v)
		if !ok {
			if f, fok := v.(float64); fok && f == float64(int(f)) {
				n, ok = int(f), true
			}
		}
		if !ok {
			return nil, fmt.Errorf("expected integer")
		}
		return n, nil
	case "double":
		if f, ok := v.(float64); ok {
			return f, nil
		}
		if n, ok := integerValue(v); ok {
			return float64(n), nil
		}
		return nil, fmt.Errorf("expected double")
	case "boolean":
		b, ok := v.(bool)
		if !ok {
			if f, fok := v.(float64); fok && (f == 0 || f == 1) {
				b, ok = f == 1, true
			}
		}
		if !ok {
			return nil, fmt.Errorf("expected boolean")
		}
		if b {
			return 1, nil
		}
		return 0, nil
	case "string":
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("expected string")
		}
		return []byte(s), nil
	case "binary", "userdata":
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("expected hex string")
		}
		b, err := hex.DecodeString(s)
		if err != nil {
			return nil, err
		}
		return b, nil
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("expected object for %s", base)
	}
	f, ok := schemaFieldsForType(base)
	if !ok {
		return nil, fmt.Errorf("schema type %s not found", base)
	}
	return encodeSchemaObject(obj, f)
}

func normalizeEncodeType(typ string) string {
	typ = strings.TrimSpace(typ)
	if i := strings.IndexByte(typ, '('); i >= 0 {
		typ = typ[:i]
	}
	return strings.TrimSpace(typ)
}

func encodeArrayRaw(items [][]byte) []byte {
	out := make([]byte, 0)
	for _, b := range items {
		var n [4]byte
		binary.LittleEndian.PutUint32(n[:], uint32(len(b)))
		out = append(out, n[:]...)
		out = append(out, b...)
	}
	return out
}
func encodeRawFields(fields map[int]any) ([]byte, error) {
	max := -1
	for tag := range fields {
		if tag > max {
			max = tag
		}
	}
	if max < 0 {
		return []byte{0, 0}, nil
	}
	head := make([]byte, 2+(max+1)*2)
	binary.LittleEndian.PutUint16(head, uint16(max+1))
	stream := []byte{}
	for tag := 0; tag <= max; tag++ {
		v, ok := fields[tag]
		if !ok {
			binary.LittleEndian.PutUint16(head[2+tag*2:], 1)
			continue
		}
		switch x := v.(type) {
		case int:
			if x >= 0 && x < 0x7fff {
				binary.LittleEndian.PutUint16(head[2+tag*2:], uint16((x+1)*2))
			} else {
				binary.LittleEndian.PutUint16(head[2+tag*2:], 0)
				var n [4]byte
				if int64(x) >= math.MinInt32 && uint64(x) <= math.MaxUint32 {
					var raw [4]byte
					binary.LittleEndian.PutUint32(raw[:], uint32(x))
					binary.LittleEndian.PutUint32(n[:], 4)
					stream = append(stream, n[:]...)
					stream = append(stream, raw[:]...)
				} else {
					var raw [8]byte
					binary.LittleEndian.PutUint64(raw[:], uint64(int64(x)))
					binary.LittleEndian.PutUint32(n[:], 8)
					stream = append(stream, n[:]...)
					stream = append(stream, raw[:]...)
				}
			}
		case []byte:
			binary.LittleEndian.PutUint16(head[2+tag*2:], 0)
			var n [4]byte
			binary.LittleEndian.PutUint32(n[:], uint32(len(x)))
			stream = append(stream, n[:]...)
			stream = append(stream, x...)
		case float64:
			binary.LittleEndian.PutUint16(head[2+tag*2:], 0)
			var raw [8]byte
			binary.LittleEndian.PutUint64(raw[:], math.Float64bits(x))
			var n [4]byte
			binary.LittleEndian.PutUint32(n[:], uint32(len(raw)))
			stream = append(stream, n[:]...)
			stream = append(stream, raw[:]...)
		default:
			return nil, fmt.Errorf("unsupported value for tag %d", tag)
		}
	}
	return append(head, stream...), nil
}
