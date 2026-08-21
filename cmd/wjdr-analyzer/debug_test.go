package main

import (
	"bytes"
	"testing"
)

func TestEncodeSchemaObjectRoundTrip(t *testing.T) {
	fields := []Field{{Name: "uid", Tag: "0", Type: "integer"}, {Name: "name", Tag: "1", Type: "string"}}
	wire, err := encodeSchemaObject(map[string]any{"uid": float64(287279141), "name": "tester"}, fields)
	if err != nil {
		t.Fatal(err)
	}
	decoded, _, ok := decodeSprotoObjectNamedBusiness(wire, map[int]string{0: "uid", 1: "name"})
	if !ok {
		t.Fatal("encoded object could not be decoded")
	}
	normalizeTypedFields(decoded, map[string]string{"uid": "integer", "name": "string"})
	uid, ok := integerValue(decoded["uid"])
	if !ok || uid != 287279141 || decoded["name"] != "tester" {
		t.Fatalf("round trip mismatch: %#v", decoded)
	}
}

func TestNotifyResponseUsesRequestSchemaSide(t *testing.T) {
	payload, err := encodeSchemaObject(map[string]any{"servertime": 7}, []Field{{Name: "servertime", Tag: "1", Type: "integer"}})
	if err != nil {
		t.Fatal(err)
	}
	frame := GameFrameInfo{payloadBytes: payload}
	decodeCommandPayload(&frame, ProtocolCommand{Name: "game_init", Category: "notify", ReqFields: []Field{{Name: "servertime", Tag: "1", Type: "integer"}}}, "response")
	if frame.SchemaSide != "request" {
		t.Fatalf("schema side = %s", frame.SchemaSide)
	}
}

func TestEmptyRequestSchemaEncodesHeartbeatWireShape(t *testing.T) {
	plain, err := encodeSchemaObject(map[string]any{}, nil)
	if err != nil || len(plain) != 2 {
		t.Fatalf("empty request = %x err=%v", plain, err)
	}
	outer, err := encodePackage(22, 56, nil)
	if err != nil {
		t.Fatal(err)
	}
	wire := packSproto(append(outer, plain...))
	if len(wire) == 0 {
		t.Fatal("empty heartbeat wire")
	}
	frame, ok := analyzeGameFrame(wire)
	if !ok || frame.Command != 22 {
		t.Fatalf("heartbeat frame = %#v", frame)
	}
}

func TestEncryptedRequestUsesPackedInnerPayload(t *testing.T) {
	// This is the exact shape captured for players_base_info id=7440:
	// crypt_length=13 and the packed inner payload is 14 bytes.
	fields := []Field{{Name: "uids", Tag: "0", Type: "*integer"}}
	plain, err := encodeSchemaObject(map[string]any{"uids": []any{float64(287344038)}}, fields)
	if err != nil {
		t.Fatal(err)
	}
	crypto := GameCrypto{Method: 1, Key: []byte("capture-key")}
	userdata, err := encodeSchemaObject(map[string]any{"crypt_method": crypto.Method, "crypt_length": len(plain)}, []Field{{Name: "crypt_method", Tag: "0", Type: "integer"}, {Name: "crypt_length", Tag: "1", Type: "integer"}})
	if err != nil {
		t.Fatal(err)
	}
	outer, err := encodePackage(1023, 39, userdata)
	if err != nil {
		t.Fatal(err)
	}
	wire := packSproto(append(outer, cryptPayload(plain, crypto.Method, crypto.Key)...))
	frame, ok := analyzeGameFrameWithCrypto(wire, &crypto)
	if !ok || frame.Command != 1023 || frame.CryptoLength != 13 || len(plain) != 13 || len(frame.payloadBytes) < len(plain) {
		t.Fatalf("encrypted frame = %#v", frame)
	}
	decoded, _, ok := decodeSprotoObjectNamedBusiness(frame.payloadBytes, map[int]string{0: "uids"})
	if !ok {
		t.Fatalf("inner payload decode failed: %x", frame.payloadBytes)
	}
	normalizeTypedFields(decoded, map[string]string{"uids": "*integer"})
	if !jsonEqualNormalized(decoded, map[string]any{"uids": []any{287344038}}) {
		t.Fatalf("inner payload mismatch decoded=%#v bytes=%x", decoded, frame.payloadBytes)
	}
}

func TestNextPackageSessionRegistersCustomRequest(t *testing.T) {
	a := &Analyzer{pending: map[string]map[int]uint64{"S": {41: 22}}, packageMax: map[string]int{"S": 41}}
	got := a.nextPackageSession("S", 1234)
	if got != 1_000_000_001 || a.pending["S"][got] != 1234 {
		t.Fatalf("session=%d pending=%#v", got, a.pending["S"])
	}
	if _, ok := a.injectedSessions["S"][got]; !ok {
		t.Fatalf("injected session not registered: %#v", a.injectedSessions)
	}
}

func TestInjectedResponseIsConsumedOnce(t *testing.T) {
	a := &Analyzer{injectedSessions: map[string]map[int]struct{}{"S": {1_000_000_001: {}}}}
	outer, err := encodePackage(0, 1_000_000_001, nil)
	if err != nil {
		t.Fatal(err)
	}
	wire := packSproto(outer)
	if !a.isInjectedResponse("S", wire) {
		unpacked, _ := unpackSproto(wire)
		decoded, _, _ := decodeSprotoObject(unpacked)
		t.Fatalf("injected response was not recognized: %#v", decoded)
	}
	if a.isInjectedResponse("S", wire) {
		t.Fatal("injected response must only be consumed once")
	}
}

func TestCapturedRequestMethodWorksWithLoginKeyWithoutCachedMethod(t *testing.T) {
	frame := GameFrameInfo{CryptoMethod: 1}
	crypto := GameCrypto{Key: []byte("439eed8d")}
	method := frame.CryptoMethod
	if method == 0 {
		method = crypto.Method
	}
	if method != 1 || len(crypto.Key) == 0 {
		t.Fatalf("method=%d key=%x", method, crypto.Key)
	}
	plain := []byte{0, 0}
	cipher := cryptPayload(plain, method, crypto.Key)
	if got := cryptPayload(cipher, method, crypto.Key); !bytes.Equal(got, plain) {
		t.Fatalf("roundtrip=%x", got)
	}
}
