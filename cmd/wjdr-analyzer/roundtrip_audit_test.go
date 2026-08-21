package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

func TestAuditLatestWSSByteRoundTrip(t *testing.T) {
	base := captureFixtureDir(t)
	lines, err := os.ReadFile(base + "/index.jsonl")
	if err != nil {
		t.Skip()
	}
	type rec struct {
		ID        uint64 `json:"id"`
		Session   string `json:"session"`
		Data      string `json:"data_file"`
		Direction string `json:"direction"`
		Host      string `json:"host"`
		Kind      string `json:"kind"`
	}
	a := &Analyzer{crypto: map[string]GameCrypto{}, pending: map[string]map[int]uint64{}}
	var encrypted, reversible, innerPacked, representationChanged, packedExact int
	for _, line := range bytes.Split(lines, []byte{'\n'}) {
		var r rec
		if json.Unmarshal(line, &r) != nil || r.Kind != "websocket-frame" || r.Host != "gofcn-gatewayws-prod.campfiregames.cn" || r.Data == "" {
			continue
		}
		body, err := os.ReadFile(base + "/" + r.Data)
		if err != nil {
			t.Fatal(err)
		}
		var cp *GameCrypto
		if c, ok := a.crypto[r.Session]; ok {
			cp = &c
		}
		unpacked, outerOK := unpackSproto(body)
		if outerOK {
			repacked := packSproto(unpacked)
			if !bytes.Equal(repacked, body) {
				t.Fatalf("id=%d sproto pack roundtrip\n got=%x\nwant=%x", r.ID, repacked, body)
			}
			packedExact++
		}
		outer, consumed, decodedOuter := decodeSprotoObject(unpacked)
		f, ok := analyzeGameFrameWithCrypto(body, cp)
		if !ok {
			t.Fatalf("id=%d frame", r.ID)
		}
		a.correlateFrame(r.Session, r.Direction, &f)
		if f.CryptoMethod > 0 && cp != nil {
			encrypted++
			if !outerOK || !decodedOuter {
				t.Fatalf("id=%d outer", r.ID)
			}
			cipher := unpacked[consumed:]
			plainWire := cryptPayload(cipher, f.CryptoMethod, cp.Key)
			if !bytes.Equal(cryptPayload(plainWire, f.CryptoMethod, cp.Key), cipher) {
				t.Fatalf("id=%d crypto roundtrip", r.ID)
			}
			reversible++
			if p, ok := unpackSproto(plainWire); ok {
				if _, _, objectOK := decodeSprotoObject(p); objectOK {
					innerPacked++
				}
			}
			if !bytes.Equal(plainWire, f.payloadBytes) {
				representationChanged++
				fmt.Printf("representation id=%d wire=%d retained=%d outer=%#v\n", r.ID, len(plainWire), len(f.payloadBytes), outer)
			}
		}
		a.captureCrypto(r.Session, f)
	}
	t.Logf("packed-exact=%d encrypted=%d reversible=%d inner-packed=%d retained-representation-changed=%d", packedExact, encrypted, reversible, innerPacked, representationChanged)
}
