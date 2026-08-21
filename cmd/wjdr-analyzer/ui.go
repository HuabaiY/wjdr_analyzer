package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

//go:embed web/*
var webFiles embed.FS

type HistoryPage struct {
	Items    []Record `json:"items"`
	Total    int      `json:"total"`
	Page     int      `json:"page"`
	PageSize int      `json:"page_size"`
	LatestID uint64   `json:"latest_id"`
}
type EventPage struct {
	Items    []Record `json:"items"`
	Total    int      `json:"total"`
	LatestID uint64   `json:"latest_id"`
}

func (a *Analyzer) historyPage(page, size int) HistoryPage {
	page, size = normalizePage(page, size)
	a.mu.Lock()
	total := len(a.records)
	latestID := uint64(0)
	if total > 0 {
		latestID = a.records[total-1].ID
	}
	start := total - page*size - size
	if start < 0 {
		start = 0
	}
	end := total - page*size
	if end < 0 {
		end = 0
	}
	if end < start {
		end = start
	}
	items := make([]Record, 0, end-start)
	for _, item := range a.records[start:end] {
		// Keep Data until lazy decoding finishes; recordSummary removes it only
		// after protocol metadata has been derived.
		item.Headers = nil
		items = append(items, item)
	}
	a.mu.Unlock()
	for i := range items {
		a.decodeHistoryRecord(&items[i])
		items[i] = recordSummary(items[i])
	}
	return HistoryPage{Items: items, Total: total, Page: page, PageSize: size, LatestID: latestID}
}

func (a *Analyzer) recordByID(id uint64) (Record, error) {
	a.mu.Lock()
	var item *Record
	for i := len(a.records) - 1; i >= 0; i-- {
		if a.records[i].ID == id {
			copy := a.records[i]
			copy.Headers = nil
			item = &copy
			break
		}
	}
	a.mu.Unlock()
	if item == nil {
		return Record{}, fmt.Errorf("record %d not found", id)
	}
	a.decodeHistoryRecord(item)
	return *item, nil
}

func (a *Analyzer) rawByID(id uint64) (string, error) {
	a.mu.Lock()
	var dataFile string
	for i := len(a.records) - 1; i >= 0; i-- {
		if a.records[i].ID == id {
			dataFile = a.records[i].Data
			break
		}
	}
	a.mu.Unlock()
	if dataFile == "" || filepath.Base(dataFile) != dataFile {
		return "", fmt.Errorf("record %d has no raw payload", id)
	}
	body, err := os.ReadFile(filepath.Join(a.Dir, dataFile))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", body), nil
}

func (a *Analyzer) eventPage(afterID uint64, limit int) EventPage {
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	a.mu.Lock()
	total := len(a.records)
	latestID := afterID
	if total > 0 {
		latestID = a.records[total-1].ID
	}
	start := total
	for i := total - 1; i >= 0; i-- {
		if a.records[i].ID <= afterID {
			break
		}
		start = i
	}
	if total-start > limit {
		start = total - limit
	}
	items := make([]Record, 0, total-start)
	for _, item := range a.records[start:] {
		items = append(items, recordSummary(item))
	}
	a.mu.Unlock()
	return EventPage{Items: items, Total: total, LatestID: latestID}
}

func recordSummary(item Record) Record {
	item.Headers = nil
	item.Data = ""
	item.Preview = ""
	item.RawPreview = ""
	item.DecodedPreview = ""
	if item.GameFrame != nil {
		frame := *item.GameFrame
		frame.Decoded = nil
		frame.Payload = nil
		frame.PlainPayloadHex = ""
		item.GameFrame = &frame
	}
	return item
}

func normalizePage(page, size int) (int, int) {
	if page < 0 {
		page = 0
	}
	if size <= 0 || size > 100 {
		size = 100
	}
	return page, size
}

func embeddedPage() (string, error) {
	html, err := webFiles.ReadFile("web/index.html")
	if err != nil {
		return "", err
	}
	css, err := webFiles.ReadFile("web/app.css")
	if err != nil {
		return "", err
	}
	js, err := webFiles.ReadFile("web/app.js")
	if err != nil {
		return "", err
	}
	page := strings.Replace(string(html), `<link rel="stylesheet" href="app.css">`, "<style>"+string(css)+"</style>", 1)
	page = strings.Replace(page, `<script src="app.js"></script>`, "<script>"+string(js)+"</script>", 1)
	return page, nil
}

func (a *Analyzer) nativeAPI(request string) (string, error) {
	var args []json.RawMessage
	if err := json.Unmarshal([]byte(request), &args); err != nil || len(args) == 0 {
		return "", fmt.Errorf("invalid native request")
	}
	var route string
	_ = json.Unmarshal(args[0], &route)
	method := "GET"
	if len(args) > 1 {
		_ = json.Unmarshal(args[1], &method)
	}
	var value any
	switch {
	case route == "/api/debug/send" && method == "POST":
		var body string
		if len(args) < 3 {
			return "", fmt.Errorf("debug body is required")
		}
		if err := json.Unmarshal(args[2], &body); err != nil {
			return "", err
		}
		value, err := a.debugSend([]byte(body))
		if err != nil {
			b, _ := json.Marshal(debugResult{OK: false, Error: err.Error()})
			return string(b), nil
		}
		b, err := json.Marshal(value)
		return string(b), err
	case strings.HasPrefix(route, "/api/history") && !strings.HasPrefix(route, "/api/history/clear"):
		var page, size int
		q := strings.Split(strings.TrimPrefix(route, "/api/history?"), "&")
		for _, p := range q {
			kv := strings.SplitN(p, "=", 2)
			if len(kv) != 2 {
				continue
			}
			if kv[0] == "page" {
				_, _ = fmt.Sscanf(kv[1], "%d", &page)
			}
			if kv[0] == "size" {
				_, _ = fmt.Sscanf(kv[1], "%d", &size)
			}
		}
		value = a.historyPage(page, size)
	case strings.HasPrefix(route, "/api/record?id="):
		var id uint64
		_, _ = fmt.Sscanf(strings.TrimPrefix(route, "/api/record?id="), "%d", &id)
		value, _ = a.recordByID(id)
	case strings.HasPrefix(route, "/api/raw?id="):
		var id uint64
		_, _ = fmt.Sscanf(strings.TrimPrefix(route, "/api/raw?id="), "%d", &id)
		value, _ = a.rawByID(id)
	case strings.HasPrefix(route, "/api/events?"):
		var after uint64
		_, _ = fmt.Sscanf(strings.TrimPrefix(route, "/api/events?after="), "%d", &after)
		value = a.eventPage(after, 100)
	case route == "/api/history/clear" && method == "POST":
		if err := a.clearHistory(); err != nil {
			return "", err
		}
		value = map[string]bool{"ok": true}
	default:
		return "", fmt.Errorf("unsupported native route %s", route)
	}
	b, err := json.Marshal(value)
	return string(b), err
}
