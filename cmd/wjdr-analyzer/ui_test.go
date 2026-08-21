package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadCaptureSequenceDoesNotReplayHistory(t *testing.T) {
	dir := t.TempDir()
	index := "{\"id\":7,\"kind\":\"websocket-frame\",\"data_file\":\"00000007_request.bin\"}\n{\"id\":19}\n"
	if err := os.WriteFile(filepath.Join(dir, "index.jsonl"), []byte(index), 0644); err != nil {
		t.Fatal(err)
	}
	a := &Analyzer{Dir: dir}
	a.loadCaptureSequence()
	if a.seq != 19 {
		t.Fatalf("capture sequence=%d", a.seq)
	}
	if len(a.records) != 0 {
		t.Fatalf("historical records were replayed: %d", len(a.records))
	}
}

func TestEnqueueWriteDropsHTTPRecords(t *testing.T) {
	a := &Analyzer{writeQueue: make(chan captureJob, 2)}
	a.enqueueWrite(Record{Kind: "http"}, []byte("request"))
	a.enqueueWrite(Record{Kind: "http-decoded"}, []byte("response"))
	if got := len(a.writeQueue); got != 0 {
		t.Fatalf("HTTP records entered capture queue: %d", got)
	}
	a.enqueueWrite(Record{Kind: "websocket-frame"}, []byte("frame"))
	if got := len(a.writeQueue); got != 1 {
		t.Fatalf("WebSocket frame was not queued: %d", got)
	}
}

func TestRecordSummaryDropsLargePayloadWithoutMutatingSource(t *testing.T) {
	source := Record{
		Data:           "00000001_request.bin",
		Preview:        "large preview",
		RawPreview:     "raw preview",
		DecodedPreview: "decoded preview",
		GameFrame: &GameFrameInfo{
			Command:          22,
			CommandName:      "test_command",
			ProtocolCategory: "test",
			DecodeStatus:     "decoded",
			Payload:          map[string]any{"large": "payload"},
			Decoded:          map[string]any{"large": "decoded"},
			PlainPayloadHex:  "deadbeef",
		},
	}

	summary := recordSummary(source)
	if summary.Data != "" || summary.Preview != "" || summary.RawPreview != "" || summary.DecodedPreview != "" {
		t.Fatal("summary retained large record fields")
	}
	if summary.GameFrame == nil || summary.GameFrame.CommandName != "test_command" || summary.GameFrame.ProtocolCategory != "test" {
		t.Fatal("summary lost protocol metadata")
	}
	if summary.GameFrame.Payload != nil || summary.GameFrame.Decoded != nil || summary.GameFrame.PlainPayloadHex != "" {
		t.Fatal("summary retained full game payload")
	}
	if source.GameFrame.Payload == nil || source.GameFrame.Decoded == nil || source.GameFrame.PlainPayloadHex == "" {
		t.Fatal("summary mutated the source record")
	}
}
