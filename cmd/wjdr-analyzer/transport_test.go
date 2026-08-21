package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDebugCaptureFrame(t *testing.T) {
	if os.Getenv("DEBUG_CAPTURE") == "" {
		t.Skip()
	}
	base := captureFixtureDir(t)
	for _, name := range []string{"00000180_request.bin", "00000191_response.bin", "00000198_response.bin", "00000343_request.bin", "00000347_response.bin"} {
		b, err := os.ReadFile(filepath.Join(base, name))
		if err != nil {
			t.Fatal(err)
		}
		f, ok := analyzeGameFrame(b)
		fmt.Printf("%s ok=%v command=%d decoded=%#v payload=%#v crypto=%d/%d status=%s\n", name, ok, f.Command, f.Decoded, f.Payload, f.CryptoMethod, f.CryptoLength, f.DecodeStatus)
		if name == "00000343_request.bin" {
			for _, key := range [][]byte{{0xd8, 0xc0, 0x93, 0xb1}, []byte("d8c093b1")} {
				g, _ := analyzeGameFrameWithCrypto(b, &GameCrypto{Method: 1, Key: key})
				fmt.Printf("key=%x => %#v status=%s\n", key, g.Payload, g.DecodeStatus)
			}
		}
	}
}

func TestDebugCurrentSession3001(t *testing.T) {
	if os.Getenv("DEBUG_CAPTURE") == "" {
		t.Skip()
	}
	base := captureFixtureDir(t)
	b, err := os.ReadFile(filepath.Join(base, "00003151_request.bin"))
	if err != nil {
		t.Fatal(err)
	}
	f, ok := analyzeGameFrameWithCrypto(b, &GameCrypto{Method: 1, Key: []byte{0x9c, 0x0e, 0x71, 0xc9}})
	if !ok {
		t.Fatal("not frame")
	}
	decodeCommandPayload(&f, ProtocolCommand{ID: 3001, Name: "save_client_data", ReqFields: []Field{{Name: "data", Tag: "0", Type: "client_data"}}}, "request")
	if containsFatalUnrecognizedPayload(f.Payload) {
		t.Fatalf("payload not decoded: %#v status=%s", f.Payload, f.DecodeStatus)
	}
	data := f.Payload.(map[string]any)["data"].(map[string]any)
	if data["law_point"] != 50000 {
		t.Fatalf("law_point=%#v", data["law_point"])
	}
	survivors := data["survivor"].([]any)
	if len(survivors) != 4 {
		t.Fatalf("survivor count=%d", len(survivors))
	}
	if survivors[0].(map[string]any)["sid"] != 1 {
		t.Fatalf("first survivor=%#v", survivors[0])
	}
	f.Payload = f.Payload
	t.Logf("payload bytes=%x", f.payloadBytes)
	if d, c, ok := decodeSprotoObjectNamed(f.payloadBytes[8:], map[int]string{0: "sid", 1: "res601", 2: "res602", 3: "res603", 4: "res604", 5: "res607"}); ok {
		t.Logf("nested=%#v consumed=%d", d, c)
	}
	t.Logf("decoded=%#v payload=%#v status=%s", f.Decoded, f.Payload, f.DecodeStatus)
}

func TestCurrentCaptureEncryptedFramesDecodeWithSessionKeys(t *testing.T) {
	// The capture directory is intentionally replaceable via the UI. The full
	// chronological WSS audit below validates every currently present encrypted
	// frame; keep this test only when its historical fixture sessions exist.
	keys := map[string][]byte{"S00014": {0x9c, 0x0e, 0x71, 0xc9}, "S00062": {0x9c, 0xc8, 0x05, 0xa7}}
	base := captureFixtureDir(t)
	lines, err := os.ReadFile(filepath.Join(base, "index.jsonl"))
	if err != nil {
		t.Skip()
	}
	decoded := 0
	for _, line := range bytes.Split(lines, []byte{'\n'}) {
		var r struct {
			Session string         `json:"session"`
			Data    string         `json:"data_file"`
			Frame   *GameFrameInfo `json:"game_frame"`
		}
		if json.Unmarshal(line, &r) != nil || r.Frame == nil || r.Frame.CryptoMethod != 1 {
			continue
		}
		body, err := os.ReadFile(filepath.Join(base, r.Data))
		if err != nil {
			t.Fatal(err)
		}
		f, ok := analyzeGameFrameWithCrypto(body, &GameCrypto{Method: 1, Key: keys[r.Session]})
		if !ok {
			continue
		}
		if !containsFatalUnrecognizedPayload(f.Payload) {
			decoded++
		}
	}
	if decoded == 0 {
		t.Skip("historical encrypted fixtures were cleared")
	}
}

func TestCurrentCaptureEachProtocolUpTo50(t *testing.T) {
	base := captureFixtureDir(t)
	lines, err := os.ReadFile(base + "/index.jsonl")
	if err != nil {
		t.Skip()
	}
	commands, err := loadCommands("../../protocol/generated")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loadSchema("../../protocol/generated"); err != nil {
		t.Fatal(err)
	}
	commandMap := make(map[uint64]ProtocolCommand, len(commands))
	for _, c := range commands {
		commandMap[c.ID] = c
	}
	type row struct {
		Session   string `json:"session"`
		Data      string `json:"data_file"`
		Direction string `json:"direction"`
		Host      string `json:"host"`
		Kind      string `json:"kind"`
	}
	var rows []row
	crypto := make(map[string]GameCrypto)
	for _, line := range bytes.Split(lines, []byte{'\n'}) {
		var r row
		if json.Unmarshal(line, &r) != nil || r.Data == "" || r.Kind != "websocket-frame" || r.Host != "gofcn-gatewayws-prod.campfiregames.cn" {
			continue
		}
		body, e := os.ReadFile(base + "/" + r.Data)
		if e != nil {
			continue
		}
		f, ok := analyzeGameFrame(body)
		if !ok {
			continue
		}
		annotateGameFrame(&f, commandMap)
		if r.Session != "" {
			capture := &Analyzer{crypto: crypto}
			capture.captureCrypto(r.Session, f)
		}
		rows = append(rows, r)
	}
	seen := make(map[uint64]int)
	fail := make(map[uint64]string)
	unencrypted := 0
	replay := &Analyzer{crypto: make(map[string]GameCrypto), pending: make(map[string]map[int]uint64)}
	for _, r := range rows {
		body, e := os.ReadFile(base + "/" + r.Data)
		if e != nil {
			continue
		}
		var c *GameCrypto
		if x, ok := replay.crypto[r.Session]; ok {
			c = &x
		}
		f, ok := analyzeGameFrameWithCrypto(body, c)
		if !ok {
			continue
		}
		annotateGameFrame(&f, commandMap)
		replay.correlateFrame(r.Session, r.Direction, &f)
		cmd, exists := commandMap[f.Command]
		if !exists {
			replay.captureCrypto(r.Session, f)
			continue
		}
		if seen[f.Command] >= 50 {
			continue
		}
		seen[f.Command]++
		decodeCommandPayload(&f, cmd, r.Direction)
		replay.captureCrypto(r.Session, f)
		if f.CryptoMethod > 0 && c == nil {
			unencrypted++
			t.Logf("encrypted frame missing key session=%s id=%s command=%d", r.Session, r.Data, f.Command)
		} else if containsFatalUnrecognizedPayload(f.Payload) {
			fail[f.Command] = f.DecodeStatus
		}
	}
	if len(fail) > 0 {
		for id, status := range fail {
			t.Errorf("protocol %d failed within first 50 samples: %s", id, status)
		}
	}
	if unencrypted > 0 {
		for session, c := range crypto {
			t.Logf("session key %s=%x", session, c.Key)
		}
		t.Fatalf("WSS encrypted samples without session key: %d", unencrypted)
	}
	if len(seen) < 20 {
		t.Fatalf("too few protocols tested: %d", len(seen))
	}
	t.Logf("validated protocols=%d samples=%d encrypted-without-key=%d", len(seen), len(rows), unencrypted)
}

func TestAuditAllLatestWSS(t *testing.T) {
	base := captureFixtureDir(t)
	lines, err := os.ReadFile(base + "/index.jsonl")
	if err != nil {
		t.Skip()
	}
	commands, err := loadCommands("../../protocol/generated")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loadSchema("../../protocol/generated"); err != nil {
		t.Fatal(err)
	}
	cm := map[uint64]ProtocolCommand{}
	for _, c := range commands {
		cm[c.ID] = c
	}
	// Keep explicit fields because compact tags cannot be shared across fields.
	type rec struct {
		ID        uint64 `json:"id"`
		Session   string `json:"session"`
		Data      string `json:"data_file"`
		Direction string `json:"direction"`
		Host      string `json:"host"`
		Kind      string `json:"kind"`
	}
	var rows []rec
	for _, line := range bytes.Split(lines, []byte{'\n'}) {
		var r rec
		if json.Unmarshal(line, &r) == nil && r.Kind == "websocket-frame" && r.Host == "gofcn-gatewayws-prod.campfiregames.cn" {
			rows = append(rows, r)
		}
	}
	a := &Analyzer{crypto: map[string]GameCrypto{}, pending: map[string]map[int]uint64{}}
	fails := []string{}
	decoded := 0
	encrypted := 0
	for _, r := range rows {
		body, e := os.ReadFile(base + "/" + r.Data)
		if e != nil {
			fails = append(fails, fmt.Sprintf("%d read", r.ID))
			continue
		}
		var cp *GameCrypto
		if c, ok := a.crypto[r.Session]; ok {
			cp = &c
		}
		f, ok := analyzeGameFrameWithCrypto(body, cp)
		if !ok {
			fails = append(fails, fmt.Sprintf("%d frame", r.ID))
			continue
		}
		a.correlateFrame(r.Session, r.Direction, &f)
		annotateGameFrameDirection(&f, cm, r.Direction)
		if c, ok := commandForDirection(f.Command, r.Direction, cm); ok {
			decodeCommandPayload(&f, c, r.Direction)
		}
		if f.CryptoMethod > 0 {
			encrypted++
			if cp == nil {
				fails = append(fails, fmt.Sprintf("%d %d missing-key", r.ID, f.Command))
				continue
			}
		}
		a.captureCrypto(r.Session, f)
		if containsUnrecognizedPayload(f.Payload) {
			fails = append(fails, fmt.Sprintf("%d %d %s payload=%#v", r.ID, f.Command, f.DecodeStatus, f.Payload))
		} else {
			decoded++
		}
	}
	t.Logf("all-wss=%d decoded=%d encrypted=%d failures=%d", len(rows), decoded, encrypted, len(fails))
	for _, f := range fails {
		t.Log(f)
	}
	if len(fails) > 0 {
		t.Fatalf("latest WSS full audit failures=%d", len(fails))
	}
}

func TestDebugCurrentWSSKeys(t *testing.T) {
	if os.Getenv("DEBUG_CAPTURE") == "" {
		t.Skip()
	}
	base := captureFixtureDir(t)
	for _, name := range []string{"00000198_response.bin", "00002602_response.bin", "00002997_response.bin", "00003437_response.bin", "00003644_response.bin"} {
		b, err := os.ReadFile(filepath.Join(base, name))
		if err != nil {
			continue
		}
		f, ok := analyzeGameFrame(b)
		if !ok {
			continue
		}
		fmt.Printf("%s command=%d payload=%#v key=%x method=%d ok=%v\n", name, f.Command, f.Payload, func() []byte { k, _, _ := findCryptoMaterial(f.Payload, f.Command); return k }(), f.CryptoMethod, ok)
	}
}

func TestClearHistoryRemovesCapturedFilesAndKeepsAnalyzerReady(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "00000001_request.bin"), []byte{1, 2, 3}, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "00000002_response.bin"), []byte{4, 5, 6}, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.jsonl"), []byte("record\n"), 0644); err != nil {
		t.Fatal(err)
	}
	a := &Analyzer{Dir: dir, records: []Record{{ID: 1, Data: "00000001_request.bin"}}, crypto: map[string]GameCrypto{"S": {}}, cryptoAt: map[uint64]GameCrypto{1: {}}, pending: map[string]map[int]uint64{"S": {}}, writeQueue: make(chan captureJob, 1)}
	if err := a.clearHistory(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "00000001_request.bin")); !os.IsNotExist(err) {
		t.Fatalf("capture still exists: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "00000002_response.bin")); !os.IsNotExist(err) {
		t.Fatalf("unloaded historical capture still exists: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "index.jsonl"))
	if err != nil || len(b) != 0 {
		t.Fatalf("index not cleared: %q %v", b, err)
	}
	if len(a.records) != 0 || a.clearing {
		t.Fatalf("analyzer not reset: %#v", a.records)
	}
}

func TestClassifyTLSAlert(t *testing.T) {
	info, ok := classifyTransportPayload([]byte{0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x28})
	if !ok || info.Protocol != "tls-alert" || info.Version != "TLS 1.0" || info.Length != 2 {
		t.Fatalf("unexpected: %#v %v", info, ok)
	}
}

func TestDecodePrefersPlainTextOverFalseNestedObject(t *testing.T) {
	data := []byte{1, 0, 0, 0, 8, 0, 0, 0, '4', '8', 'b', '6', 'c', '4', '0', '4'}
	decoded, consumed, ok := decodeSprotoObject(data)
	if !ok || consumed != len(data) || decoded["type"] != "48b6c404" {
		t.Fatalf("unexpected: %#v consumed=%d ok=%v", decoded, consumed, ok)
	}
}

func TestDecodeSessionTimestampAsOriginalValue(t *testing.T) {
	value, ok := decodeSessionTimestamp([]byte{0x1d, 0xc2, 0x86, 0x6a})
	if !ok || value != "2026-08-20 17:00:13" {
		t.Fatalf("unexpected session timestamp: %q %v", value, ok)
	}
}

func TestGameMarker15IsNotTLS(t *testing.T) {
	_, ok := classifyTransportPayload([]byte{0x15, 0x03, 0x01, 0x3c, 0x51, 0x06, 0x02, 0x04})
	if ok {
		t.Fatal("game frame with marker 0x15 was classified as TLS")
	}
}

func TestGameMarker19UsesSprotoPackValidation(t *testing.T) {
	body, err := hex.DecodeString("1903086a51060204fd1caaa29fcaaea27f9fcaaf2879d5ba")
	if err != nil {
		t.Fatal(err)
	}
	frame, ok := analyzeGameFrameWithCrypto(body, &GameCrypto{Method: 1, Key: []byte{0xab, 0xa2, 0x9f, 0xca}})
	if !ok || frame.Command != 1023 || containsUnrecognizedPayload(frame.Payload) {
		t.Fatalf("marker 0x19 frame not decoded: ok=%v frame=%#v", ok, frame)
	}
}

func TestEncryptedPayloadDecryptsBeyondCryptLength(t *testing.T) {
	body, err := hex.DecodeString("1503016651060204fd0ea9a29dcaaba2ff0385caaba29dcaaba29fcaafa29fcae293a2d8a3a29fcaa8a20bcbbfa29bca0000")
	if err != nil {
		t.Fatal(err)
	}
	frame, ok := analyzeGameFrameWithCrypto(body, &GameCrypto{Method: 1, Key: []byte{0xab, 0xa2, 0x9f, 0xca}})
	want, _ := hex.DecodeString("0200020000001a0000000200000000000400000049313d12080000000300940114000400aba2")
	if !ok || frame.CryptoLength != 6 || !bytes.Equal(frame.payloadBytes, want) {
		t.Fatalf("complete payload was not decrypted: ok=%v got=%x want=%x", ok, frame.payloadBytes, want)
	}
}

func TestPlainPayloadHexRetainsCompleteDecryptedBytes(t *testing.T) {
	body, err := hex.DecodeString("1503016651060204fd0ea9a29dcaaba2ff0385caaba29dcaaba29fcaafa29fcae293a2d8a3a29fcaa8a20bcbbfa29bca0000")
	if err != nil {
		t.Fatal(err)
	}
	frame, ok := analyzeGameFrameWithCrypto(body, &GameCrypto{Method: 1, Key: []byte{0xab, 0xa2, 0x9f, 0xca}})
	if !ok || frame.PlainPayloadHex != hex.EncodeToString(frame.payloadBytes) {
		t.Fatalf("plain payload evidence missing or truncated: %#v", frame)
	}
	b, err := json.Marshal(frame)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(b, &wire); err != nil {
		t.Fatal(err)
	}
	if got, _ := wire["plain_payload_hex"].(string); got != frame.PlainPayloadHex {
		t.Fatalf("plain payload was not exposed in frame JSON: %q", got)
	}
}

func TestUnpackSprotoSegment(t *testing.T) {
	unpacked, ok := unpackSproto([]byte{0x05, 0xaa, 0xbb})
	if !ok || len(unpacked) != 8 || unpacked[0] != 0xaa || unpacked[2] != 0xbb {
		t.Fatalf("unexpected unpacked bytes: %x", unpacked)
	}
}

func TestCryptPayloadXOR(t *testing.T) {
	plain := []byte("plaintext")
	key := []byte{0x12, 0x34, 0x56}
	ciphertext := cryptPayload(plain, 1, key)
	if got := string(cryptPayload(ciphertext, 1, key)); got != string(plain) {
		t.Fatalf("xor round trip = %q", got)
	}
}

func TestCryptPayloadRC4KnownVector(t *testing.T) {
	ciphertext := cryptPayload([]byte("Plaintext"), 2, []byte("Key"))
	if got := hex.EncodeToString(ciphertext); got != "bbf316e8d940af0ad3" {
		t.Fatalf("rc4 vector = %s", got)
	}
	if got := string(cryptPayload(ciphertext, 2, []byte("Key"))); got != "Plaintext" {
		t.Fatalf("rc4 round trip = %q", got)
	}
}

func TestEncryptedPackageBecomesNamedPlaintext(t *testing.T) {
	key := []byte{0x12, 0x34, 0x56}
	payload := packForTest(sprotoObjectForTest(map[int]any{0: 7}))
	ciphertext := cryptPayload(payload, 1, key)
	userdata := sprotoObjectForTest(map[int]any{0: 1, 1: len(ciphertext)})
	outer := append(sprotoObjectForTest(map[int]any{0: 22, 2: userdata}), ciphertext...)
	frame, ok := analyzeGameFrameWithCrypto(packForTest(outer), &GameCrypto{Method: 1, Key: key})
	if !ok {
		t.Fatal("encrypted frame was not recognized")
	}
	command := ProtocolCommand{ID: 22, Name: "heartbeat", ReqFields: []Field{{Name: "message", Tag: "0", Type: "integer"}}}
	decodeCommandPayload(&frame, command, "request")
	decoded, ok := frame.Payload.(map[string]any)
	if !ok || decoded["message"] != 7 || containsUnrecognizedPayload(decoded) {
		t.Fatalf("unexpected plaintext: %#v status=%s", frame.Payload, frame.DecodeStatus)
	}
}

func TestHighPackageSessionRemainsNumeric(t *testing.T) {
	outer, err := encodeRawFields(map[int]any{0: 22, 1: 1_000_000_001})
	if err != nil {
		t.Fatal(err)
	}
	decoded, _, ok := decodeSprotoObjectNamed(outer, nil)
	if !ok {
		t.Fatal("package decode failed")
	}
	session, ok := integerValue(decoded["session"])
	if !ok || session != 1_000_000_001 {
		t.Fatalf("session=%#v", decoded["session"])
	}
}

func TestPackageCryptoMetadataUsesProtocolNames(t *testing.T) {
	key := []byte{0x12, 0x34, 0x56}
	payload := packForTest(sprotoObjectForTest(map[int]any{0: 7}))
	ciphertext := cryptPayload(payload, 1, key)
	userdata := sprotoObjectForTest(map[int]any{0: 1, 1: len(ciphertext)})
	outer := append(sprotoObjectForTest(map[int]any{0: 22, 2: userdata}), ciphertext...)
	frame, ok := analyzeGameFrameWithCrypto(packForTest(outer), &GameCrypto{Method: 1, Key: key})
	if !ok || frame.CryptoMethod != 1 || frame.CryptoLength != len(ciphertext) {
		t.Fatalf("metadata not decoded: %#v", frame)
	}
}

func TestRawHexNeverBecomesDecodedPreview(t *testing.T) {
	frame := GameFrameInfo{Payload: map[string]any{"raw_hex": "deadbeef", "decode_status": "payload-unrecognized-or-encrypted"}}
	if preview, ok := plaintextPreview(frame); ok || preview != "" {
		t.Fatalf("raw hex leaked into decoded preview: %q", preview)
	}
}

func TestPlaintextPreviewMatchesNativeSprotoPayload(t *testing.T) {
	frame := GameFrameInfo{
		Decoded:         map[string]any{"type": 1023, "session": 7},
		PlainPayloadHex: "01020304",
		Payload:         map[string]any{"uids": []any{1, 2}},
	}
	preview, ok := plaintextPreview(frame)
	if !ok || strings.Contains(preview, `"type"`) || strings.Contains(preview, `"session"`) || !strings.Contains(preview, `"uids"`) {
		t.Fatalf("incomplete plaintext preview: %s", preview)
	}
}

func TestSessionKeyStoredBeforePerFrameCryptoMethod(t *testing.T) {
	a := &Analyzer{crypto: make(map[string]GameCrypto)}
	a.captureCrypto("S1", GameFrameInfo{Command: 33, Payload: map[string]any{"secret_key": "d8c093b1"}})
	got, ok := a.crypto["S1"]
	if !ok || hex.EncodeToString(got.Key) != "d8c093b1" || got.Method != 0 {
		t.Fatalf("session key was discarded: %#v", got)
	}
}

func sprotoObjectForTest(fields map[int]any) []byte {
	maxTag := 0
	for tag := range fields {
		if tag > maxTag {
			maxTag = tag
		}
	}
	head := make([]byte, 2+(maxTag+1)*2)
	binary.LittleEndian.PutUint16(head, uint16(maxTag+1))
	stream := make([]byte, 0)
	for tag := 0; tag <= maxTag; tag++ {
		value, ok := fields[tag]
		if !ok {
			binary.LittleEndian.PutUint16(head[2+tag*2:], 1)
			continue
		}
		switch v := value.(type) {
		case int:
			binary.LittleEndian.PutUint16(head[2+tag*2:], uint16((v+1)*2))
		case []byte:
			var length [4]byte
			binary.LittleEndian.PutUint32(length[:], uint32(len(v)))
			stream = append(stream, length[:]...)
			stream = append(stream, v...)
		}
	}
	return append(head, stream...)
}

func packForTest(src []byte) []byte {
	out := make([]byte, 0, len(src)+len(src)/8+1)
	for offset := 0; offset < len(src); offset += 8 {
		headerPos := len(out)
		out = append(out, 0)
		for bit := 0; bit < 8 && offset+bit < len(src); bit++ {
			if src[offset+bit] != 0 {
				out[headerPos] |= 1 << bit
				out = append(out, src[offset+bit])
			}
		}
	}
	return out
}
