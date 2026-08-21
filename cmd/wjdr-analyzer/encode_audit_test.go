package main

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestCurrentDecodedRequestsReencodeBySchema(t *testing.T) {
	base := captureFixtureDir(t)
	f, err := os.Open(filepath.Join(base, "index.jsonl"))
	if err != nil {
		t.Skip()
	}
	defer f.Close()
	commands, err := loadCommands(filepath.Join("..", "..", "protocol", "generated"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loadSchema(filepath.Join("..", "..", "protocol", "generated")); err != nil {
		t.Fatal(err)
	}
	cm := map[uint64]ProtocolCommand{}
	for _, command := range commands {
		cm[command.ID] = command
	}
	type row struct {
		Direction string         `json:"direction"`
		Kind      string         `json:"kind"`
		GameFrame *GameFrameInfo `json:"game_frame"`
	}
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 64*1024), 8*1024*1024)
	checked := 0
	for s.Scan() {
		var r row
		if json.Unmarshal(s.Bytes(), &r) != nil || r.Kind != "websocket-frame" || r.Direction != "request" || r.GameFrame == nil || r.GameFrame.Command == 0 || containsUnrecognizedPayload(r.GameFrame.Payload) {
			continue
		}
		command, ok := commandForDirection(r.GameFrame.Command, "request", cm)
		if !ok || command.Category != "req" {
			continue
		}
		payload, ok := r.GameFrame.Payload.(map[string]any)
		if !ok {
			continue
		}
		types := make(map[string]string, len(command.ReqFields))
		for _, field := range command.ReqFields {
			types[field.Name] = field.Type
		}
		// index.jsonl may contain payload JSON produced by an older decoder.
		// Apply the current schema normalization before auditing the current
		// encoder, matching decodeHistoryRecord's live UI behavior.
		normalizeTypedFields(payload, types)
		wire, err := encodeSchemaObject(payload, command.ReqFields)
		if err != nil {
			t.Errorf("%s encode: %v", command.Name, err)
			continue
		}
		frame := GameFrameInfo{payloadBytes: wire}
		decodeCommandPayload(&frame, command, "request")
		if !reflect.DeepEqual(normalizeJSON(payload), normalizeJSON(frame.Payload)) {
			t.Errorf("%s roundtrip\nwant=%#v\ngot=%#v", command.Name, payload, frame.Payload)
			continue
		}
		checked++
	}
	if err := s.Err(); err != nil {
		t.Fatal(err)
	}
	if checked == 0 {
		t.Fatal("no decoded requests checked")
	}
	t.Logf("schema re-encode checked=%d", checked)
}

func normalizeJSON(v any) any {
	b, _ := json.Marshal(v)
	var out any
	_ = json.Unmarshal(b, &out)
	return out
}
