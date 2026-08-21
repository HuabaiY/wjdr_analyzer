package main

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	gamemitm "github.com/husanpao/game-mitm"
	"github.com/husanpao/game-mitm/gosysproxy"
)

type Analyzer struct {
	Dir              string
	Filter           string
	mu               sync.Mutex
	seq              uint64
	clients          map[chan Record]struct{}
	wsSessions       map[string]*gamemitm.Session
	records          []Record
	sessions         map[*http.Request]string
	sessionSeq       uint64
	schemas          []Schema
	commands         map[uint64]ProtocolCommand
	crypto           map[string]GameCrypto
	cryptoAt         map[uint64]GameCrypto
	pending          map[string]map[int]uint64
	packageMax       map[string]int
	debugSessionSeq  map[string]int
	injectedSessions map[string]map[int]struct{}
	writeQueue       chan captureJob
	clearing         bool
}

type captureJob struct {
	record Record
	body   []byte
}

type Record struct {
	Time           time.Time         `json:"time"`
	Direction      string            `json:"direction"`
	Host           string            `json:"host"`
	URL            string            `json:"url,omitempty"`
	Kind           string            `json:"kind"`
	Size           int               `json:"size"`
	Data           string            `json:"data_file"`
	ID             uint64            `json:"id"`
	Preview        string            `json:"preview,omitempty"`
	RawPreview     string            `json:"raw_preview,omitempty"`
	DecodedPreview string            `json:"decoded_preview,omitempty"`
	Protocol       string            `json:"protocol,omitempty"`
	Transport      *TransportInfo    `json:"transport,omitempty"`
	GameProtocol   *GameProtocolInfo `json:"game_protocol,omitempty"`
	GameFrame      *GameFrameInfo    `json:"game_frame,omitempty"`
	MessageType    int               `json:"message_type,omitempty"`
	Status         int               `json:"status,omitempty"`
	Session        string            `json:"session"`
	Method         string            `json:"method,omitempty"`
	Path           string            `json:"path,omitempty"`
	Headers        http.Header       `json:"headers,omitempty"`
}

func main() {
	port := flag.Int("port", 12311, "MITM proxy port")
	out := flag.String("out", "runtime/captures/default", "capture directory")
	filter := flag.String("filter", "campfiregames.cn|gofcn", "host filter regular expression")
	schema := flag.String("schema", "protocol/generated", "generated current-version sproto directory")
	caDir := flag.String("ca-dir", "runtime/ca", "certificate authority directory")
	systemProxy := flag.Bool("system-proxy", true, "route Windows system traffic through the MITM proxy")
	flag.Parse()
	if err := ensurePortAvailable(*port); err != nil {
		fatalStartup("MITM 端口", *port, err)
	}
	*out = absolutePath(*out)
	*caDir = absolutePath(*caDir)
	*schema = resolveProjectPath(*schema)
	a := &Analyzer{Dir: *out, Filter: *filter, clients: make(map[chan Record]struct{}), wsSessions: make(map[string]*gamemitm.Session), sessions: make(map[*http.Request]string), crypto: make(map[string]GameCrypto), cryptoAt: make(map[uint64]GameCrypto), pending: make(map[string]map[int]uint64), packageMax: make(map[string]int), debugSessionSeq: make(map[string]int), injectedSessions: make(map[string]map[int]struct{})}
	a.writeQueue = make(chan captureJob, 2048)
	go a.captureWorker()
	a.commands = make(map[uint64]ProtocolCommand)
	if err := os.MkdirAll(a.Dir, 0755); err != nil {
		panic(err)
	}
	if *schema != "" {
		if items, err := loadSchema(*schema); err == nil {
			a.schemas = items
		}
		if commands, err := loadCommands(*schema); err == nil {
			for _, command := range commands {
				a.commands[command.ID] = command
			}
			if data, err := json.MarshalIndent(commands, "", "  "); err == nil {
				_ = os.WriteFile(filepath.Join(a.Dir, "protocol-commands.json"), data, 0644)
			}
		}
		if err := writeSchemaIndex(*schema, filepath.Join(a.Dir, "schema-index.json")); err != nil {
			fmt.Printf("schema index skipped: %v\n", err)
		}
	}
	protocolReport := filepath.Join(a.Dir, "game-protocol.json")
	if data, err := json.MarshalIndent(InferGameProtocol(), "", "  "); err == nil {
		_ = os.WriteFile(protocolReport, data, 0644)
	}
	a.loadCaptureSequence()
	proxy := gamemitm.NewProxyWithCADir(*caDir)
	proxy.SetPort(*port)
	// game-mitm's verbose mode hex-logs every WSS frame synchronously. Large
	// game responses can then block the forwarding goroutine and make the game
	// appear stuck. Capture records remain available through the analyzer queue;
	// transport logging must stay off in production.
	proxy.SetVerbose(false)
	proxy.OnRequest(gamemitm.All).Do(a.http("request"))
	proxy.OnResponse(gamemitm.All).Do(a.http("response"))
	proxy.OnConnected(gamemitm.All).Do(a.connected)
	if *systemProxy {
		bypass := "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*"
		if err := gosysproxy.SetGlobalProxy(fmt.Sprintf("127.0.0.1:%d", *port), bypass); err != nil {
			panic(fmt.Errorf("enable system proxy: %w", err))
		}
		defer func() {
			if err := gosysproxy.Off(); err != nil {
				fmt.Printf("restore system proxy failed: %v\n", err)
			}
		}()
		fmt.Printf("system proxy enabled: 127.0.0.1:%d\n", *port)
	}
	fmt.Printf("wjdr analyzer MITM listening on :%d, captures=%s\n", *port, *out)
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		if err := proxy.Start(); err != nil {
			fmt.Printf("proxy stopped: %v\n", err)
		}
	}()
	uiDone := make(chan error, 1)
	go func() {
		if err := runDesktop(a); err != nil {
			fmt.Printf("desktop UI stopped: %v\n", err)
			uiDone <- err
			return
		}
		// Closing the native window is a normal application exit. It must stop
		// the MITM too; otherwise the main goroutine would wait forever while
		// the EXE remains in the background.
		uiDone <- nil
	}()
	select {
	case <-signalChan:
	case <-uiDone:
	}
}

func ensurePortAvailable(port int) error {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return err
	}
	return ln.Close()
}

func fatalStartup(kind string, port int, err error) {
	fmt.Fprintf(os.Stderr, "无法启动：%s %d 已被占用或不可用：%v\n请关闭已有 wjdr-analyzer 实例后重试。\n", kind, port, err)
	os.Exit(2)
}

func (a *Analyzer) match(host string) bool {
	if a.Filter == "" {
		return true
	}
	ok, err := regexp.MatchString(a.Filter, host)
	return err == nil && ok
}

func (a *Analyzer) http(direction string) gamemitm.Handle {
	return func(body []byte, ctx *gamemitm.ProxyCtx) []byte {
		if ctx.Req == nil || !ctx.IsWebSocket || !a.match(ctx.Req.Host) {
			return body
		}
		kind := "websocket-frame"
		r := Record{Time: time.Now(), Direction: direction, Host: ctx.Req.Host, URL: ctx.Req.URL.String(), Kind: kind, Size: len(body), MessageType: ctx.MessageType, Session: a.sessionFor(ctx.Req), Method: ctx.Req.Method, Path: ctx.Req.URL.RequestURI()}
		if ctx.Resp != nil {
			r.Status = ctx.Resp.StatusCode
		}
		if ctx.IsWebSocket && ctx.WSSession != nil {
			a.mu.Lock()
			a.wsSessions[r.Session] = ctx.WSSession
			a.mu.Unlock()
		}
		a.enqueueWrite(r, body)
		if direction == "response" && ctx.IsWebSocket && a.isInjectedResponse(r.Session, body) {
			return nil
		}
		return body
	}
}

func resolveProjectPath(value string) string {
	if filepath.IsAbs(value) || value == "" {
		return value
	}
	if _, err := os.Stat(value); err == nil {
		return value
	}
	exe, err := os.Executable()
	if err != nil {
		return value
	}
	root := filepath.Dir(filepath.Dir(exe))
	candidate := filepath.Join(root, value)
	if _, err := os.Stat(candidate); err == nil {
		return candidate
	}
	return value
}

func absolutePath(value string) string {
	if value == "" || filepath.IsAbs(value) {
		return value
	}
	p, err := filepath.Abs(value)
	if err != nil {
		return value
	}
	return p
}

func decodeHTTPBody(body []byte, encoding string) ([]byte, string) {
	encoding = strings.ToLower(strings.TrimSpace(encoding))
	switch encoding {
	case "gzip", "x-gzip":
		reader, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, ""
		}
		defer reader.Close()
		out, err := io.ReadAll(reader)
		if err != nil {
			return nil, ""
		}
		return out, "gzip"
	case "deflate":
		reader := flate.NewReader(bytes.NewReader(body))
		defer reader.Close()
		out, err := io.ReadAll(reader)
		if err != nil {
			return nil, ""
		}
		return out, "deflate"
	default:
		return nil, ""
	}
}

func (a *Analyzer) connected(body []byte, ctx *gamemitm.ProxyCtx) []byte {
	if ctx.Req != nil && a.match(ctx.Req.Host) {
		a.enqueueWrite(Record{Time: time.Now(), Direction: "connected", Host: ctx.Req.Host, URL: ctx.Req.URL.String(), Kind: "websocket", Size: 0, Session: a.sessionFor(ctx.Req), Method: ctx.Req.Method, Path: ctx.Req.URL.RequestURI(), Headers: ctx.Req.Header.Clone()}, nil)
	}
	return body
}

func (a *Analyzer) write(r Record, body []byte) {
	a.mu.Lock()
	a.seq++
	r.ID = a.seq
	currentCrypto, hasCrypto := a.crypto[r.Session]
	a.mu.Unlock()
	base := fmt.Sprintf("%08d_%s", a.seq, strings.ReplaceAll(r.Direction, "/", "_"))
	if len(body) > 0 {
		name := base + ".bin"
		if err := os.WriteFile(filepath.Join(a.Dir, name), body, 0644); err != nil {
			return
		}
		r.Data = name
		r.RawPreview = protocolRawPreview(r.Kind, body)
		r.Preview = r.RawPreview
		if transport, ok := classifyTransportPayload(body); ok {
			r.Transport = &transport
			r.Protocol = transport.Protocol
			r.Preview = fmt.Sprintf("%s %s (%d B): %s", transport.Protocol, transport.Version, transport.Length, transport.Detail)
		}
		if r.Kind == "websocket-frame" && len(body) <= 2*1024*1024 {
			var crypto *GameCrypto
			if hasCrypto {
				crypto = &currentCrypto
			}
			if frame, ok := analyzeGameFrameWithCrypto(body, crypto); ok {
				a.mu.Lock()
				a.correlateFrame(r.Session, r.Direction, &frame)
				a.mu.Unlock()
				annotateGameFrameDirection(&frame, a.commands, r.Direction)
				if command, ok := commandForDirection(frame.Command, r.Direction, a.commands); ok {
					decodeCommandPayload(&frame, command, r.Direction)
				}
				a.mu.Lock()
				a.captureCrypto(r.Session, frame)
				a.mu.Unlock()
				r.GameFrame = &frame
				if decoded, ok := plaintextPreview(frame); ok {
					r.DecodedPreview = decoded
					r.Preview = decoded
				}
			}
		}
		if r.Kind == "websocket-frame" && len(body) > 2*1024*1024 {
			r.Protocol = "websocket-frame"
			r.Preview = fmt.Sprintf("large frame (%d B); deferred decode", len(body))
		}
		if strings.HasPrefix(r.Preview, "{") || strings.HasPrefix(r.Preview, "[") {
			if r.Kind != "websocket-frame" {
				r.Protocol = "json"
			}
		}
	}
	f, err := os.OpenFile(filepath.Join(a.Dir, "index.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	_ = json.NewEncoder(f).Encode(r)
	a.mu.Lock()
	defer a.mu.Unlock()
	a.records = append(a.records, r)
	if len(a.records) > 5000 {
		a.records = append([]Record(nil), a.records[len(a.records)-5000:]...)
	}
	for c := range a.clients {
		select {
		case c <- recordSummary(r):
		default:
		}
	}
}

func (a *Analyzer) enqueueWrite(r Record, body []byte) {
	if strings.HasPrefix(r.Kind, "http") {
		return
	}
	if a.writeQueue == nil {
		a.write(r, body)
		return
	}
	a.mu.Lock()
	clearing := a.clearing
	a.mu.Unlock()
	if clearing {
		return
	}
	// Keep the proxy callback bounded in both time and memory. The capture file
	// still receives the full frame, but a pathological burst must not make the
	// forwarding path wait for an unbounded copy or queue allocation.
	if len(body) > 8*1024*1024 {
		return
	}
	copyBody := append([]byte(nil), body...)
	select {
	case a.writeQueue <- captureJob{record: r, body: copyBody}:
	default:
		// Never block the proxy/game connection. Dropped analysis is visible in
		// the UI only as a missing record; network forwarding remains healthy.
	}
}

func (a *Analyzer) clearHistory() error {
	a.mu.Lock()
	a.clearing = true
	a.mu.Unlock()
	for {
		select {
		case <-a.writeQueue:
		default:
			goto drained
		}
	}
drained:
	entries, err := os.ReadDir(a.Dir)
	if err != nil && !os.IsNotExist(err) {
		a.mu.Lock()
		a.clearing = false
		a.mu.Unlock()
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || !isCaptureDataFile(entry.Name()) {
			continue
		}
		if err := os.Remove(filepath.Join(a.Dir, entry.Name())); err != nil && !os.IsNotExist(err) {
			a.mu.Lock()
			a.clearing = false
			a.mu.Unlock()
			return err
		}
	}
	if err := os.WriteFile(filepath.Join(a.Dir, "index.jsonl"), nil, 0644); err != nil {
		a.mu.Lock()
		a.clearing = false
		a.mu.Unlock()
		return err
	}
	a.mu.Lock()
	a.seq = 0
	a.records = nil
	a.crypto = make(map[string]GameCrypto)
	a.cryptoAt = make(map[uint64]GameCrypto)
	a.pending = make(map[string]map[int]uint64)
	a.debugSessionSeq = make(map[string]int)
	a.injectedSessions = make(map[string]map[int]struct{})
	a.clearing = false
	a.mu.Unlock()
	return nil
}

func isCaptureDataFile(name string) bool {
	if filepath.Ext(name) != ".bin" || len(name) < 14 || name[8] != '_' {
		return false
	}
	for _, c := range name[:8] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func (a *Analyzer) captureWorker() {
	for job := range a.writeQueue {
		a.write(job.record, job.body)
	}
}

func (a *Analyzer) correlateFrame(session, direction string, frame *GameFrameInfo) {
	if frame == nil {
		return
	}
	packageSession, ok := integerValue(frame.DecodedValue("session"))
	if !ok || session == "" {
		return
	}
	if a.pending[session] == nil {
		a.pending[session] = make(map[int]uint64)
	}
	if a.packageMax == nil {
		a.packageMax = make(map[string]int)
	}
	if direction == "request" && frame.Command > 0 {
		a.pending[session][packageSession] = frame.Command
		if packageSession > a.packageMax[session] {
			a.packageMax[session] = packageSession
		}
		return
	}
	if packageSession > a.packageMax[session] {
		a.packageMax[session] = packageSession
	}
	if direction == "response" && frame.Command == 0 {
		frame.Command = a.pending[session][packageSession]
	}
}

func plaintextPreview(frame GameFrameInfo) (string, bool) {
	if frame.Payload == nil || containsFatalUnrecognizedPayload(frame.Payload) {
		return "", false
	}
	// The decoded preview is the command's native request/response object.
	// Package metadata and complete bytes remain separate GameFrame fields.
	decoded, err := json.Marshal(frame.Payload)
	if err != nil {
		return "", false
	}
	return string(decoded), true
}

func (a *Analyzer) captureCrypto(session string, frame GameFrameInfo) {
	if session == "" || frame.Payload == nil {
		return
	}
	key, method, ok := findCryptoMaterial(frame.Payload, frame.Command)
	if !ok || len(key) == 0 {
		return
	}
	if method == 0 {
		if current, exists := a.crypto[session]; exists {
			method = current.Method
		}
	}
	a.crypto[session] = GameCrypto{Method: method, Key: append([]byte(nil), key...)}
}

func findCryptoMaterial(payload any, command uint64) ([]byte, int, bool) {
	obj, ok := payload.(map[string]any)
	if !ok {
		return nil, 0, false
	}
	keyValue, hasKey := obj["tag_14"]
	methodValue := obj["tag_16"]
	if namedKey, exists := obj["secret_key"]; exists {
		keyValue, hasKey = namedKey, true
	}
	if namedMethod, exists := obj["crypt_method"]; exists {
		methodValue = namedMethod
	}
	if command == 33 {
		if value, exists := obj["tag_7"]; exists {
			keyValue, hasKey = value, true
		}
		if namedKey, exists := obj["secret_key"]; exists {
			keyValue, hasKey = namedKey, true
		}
	}
	key, ok := byteValue(keyValue)
	method, methodOK := integerValue(methodValue)
	return key, method, hasKey && ok && (methodOK || command == 33)
}

func byteValue(v any) ([]byte, bool) {
	if obj, ok := v.(map[string]any); ok {
		if raw, exists := obj["raw_hex"]; exists {
			return byteValue(raw)
		}
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return nil, false
	}
	if decoded, err := hex.DecodeString(s); err == nil {
		return decoded, true
	}
	return []byte(s), true
}

func (a *Analyzer) sessionFor(req *http.Request) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if id, ok := a.sessions[req]; ok {
		return id
	}
	a.sessionSeq++
	id := fmt.Sprintf("S%05d", a.sessionSeq)
	a.sessions[req] = id
	return id
}

func (a *Analyzer) loadCaptureSequence() {
	f, err := os.Open(filepath.Join(a.Dir, "index.jsonl"))
	if err != nil {
		return
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for s.Scan() {
		var item struct {
			ID uint64 `json:"id"`
		}
		if json.Unmarshal(s.Bytes(), &item) == nil && item.ID > a.seq {
			a.seq = item.ID
		}
	}
}

func (a *Analyzer) decodeHistoryRecord(r *Record) {
	if r == nil || r.Kind != "websocket-frame" || r.Data == "" {
		return
	}
	body, err := os.ReadFile(filepath.Join(a.Dir, r.Data))
	if err != nil {
		return
	}
	if r.RawPreview == "" {
		r.RawPreview = protocolRawPreview(r.Kind, body)
	}
	// Always decode from the captured .bin again. Historical index entries may
	// contain a stale decoder result (including raw_hex) from an older schema or
	// key-discovery algorithm; that cache must never mask the current decoder.
	var crypto *GameCrypto
	a.mu.Lock()
	c, cryptoOK := a.cryptoAt[r.ID]
	if !cryptoOK {
		c, cryptoOK = a.crypto[r.Session]
	}
	a.mu.Unlock()
	if cryptoOK {
		crypto = &c
	}
	frame, ok := analyzeGameFrameWithCrypto(body, crypto)
	if !ok {
		return
	}
	a.mu.Lock()
	a.correlateFrame(r.Session, r.Direction, &frame)
	a.mu.Unlock()
	annotateGameFrameDirection(&frame, a.commands, r.Direction)
	if command, ok := commandForDirection(frame.Command, r.Direction, a.commands); ok {
		decodeCommandPayload(&frame, command, r.Direction)
	}
	a.mu.Lock()
	a.captureCrypto(r.Session, frame)
	a.mu.Unlock()
	r.GameFrame = &frame
	if decoded, ok := plaintextPreview(frame); ok {
		r.DecodedPreview = decoded
		r.Preview = decoded
	} else {
		r.DecodedPreview = ""
	}
}

func protocolRawPreview(kind string, body []byte) string {
	if kind != "websocket-frame" {
		return preview(body)
	}
	const max = 96
	end := min(len(body), max)
	value := fmt.Sprintf("%x", body[:end])
	if len(body) > max {
		value += "..."
	}
	return value
}

func preview(body []byte) string {
	const max = 180
	text := strings.TrimSpace(string(body))
	if len(text) > max {
		return text[:max] + "..."
	}
	for _, r := range text {
		if r < 32 && r != '\t' && r != '\n' && r != '\r' {
			return fmt.Sprintf("hex:%x", body[:min(len(body), 48)])
		}
	}
	return text
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (a *Analyzer) subscribe() chan Record {
	c := make(chan Record, 32)
	a.mu.Lock()
	a.clients[c] = struct{}{}
	a.mu.Unlock()
	return c
}
func (a *Analyzer) unsubscribe(c chan Record) {
	a.mu.Lock()
	delete(a.clients, c)
	close(c)
	a.mu.Unlock()
}
