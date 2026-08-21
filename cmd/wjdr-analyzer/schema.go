package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type Schema struct {
	Name   string  `json:"name"`
	Line   int     `json:"line"`
	Fields []Field `json:"fields"`
}

type Field struct {
	Name string `json:"name"`
	Tag  string `json:"tag"`
	Type string `json:"type"`
	Line int    `json:"line"`
}

type ProtocolCommand struct {
	Name      string  `json:"name"`
	ID        uint64  `json:"id"`
	HasReq    bool    `json:"has_request"`
	HasRsp    bool    `json:"has_response"`
	Line      int     `json:"line"`
	Category  string  `json:"category"`
	ReqFields []Field `json:"request_fields,omitempty"`
	RspFields []Field `json:"response_fields,omitempty"`
	ReqType   string  `json:"request_type,omitempty"`
	RspType   string  `json:"response_type,omitempty"`
}

var schemaRegistry = map[string][]Field{}
var commandVariants = map[uint64][]ProtocolCommand{}

var schemaStart = regexp.MustCompile(`^\s*\.([A-Za-z_][A-Za-z0-9_]*)\s*\{`)
var fieldLine = regexp.MustCompile(`^\s*([A-Za-z_][A-Za-z0-9_]*)\s+([0-9]+)\s*:\s*([^#]+)`)
var commandLine = regexp.MustCompile(`^\s*((?:(req|notify|notfiy|watch|rsp)_[A-Za-z0-9_]+)|(loginauth))\s+([0-9]+)\s*\{`)
var sectionTypeLine = regexp.MustCompile(`^\s*(request|response)\s+([A-Za-z_][A-Za-z0-9_]*)\s*$`)

func schemaFiles(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return []string{path}, nil
	}
	files, err := filepath.Glob(filepath.Join(path, "*.sproto"))
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no sproto files in %s", path)
	}
	return files, nil
}

func loadSchema(path string) ([]Schema, error) {
	// Schema files are loaded more than once by tests and by the runtime. Do
	// not retain definitions from a previous load, otherwise same-named local
	// structures can silently overwrite the current version.
	schemaRegistry = map[string][]Field{}
	files, err := schemaFiles(path)
	if err != nil {
		return nil, err
	}
	var all []Schema
	for _, file := range files {
		f, e := os.Open(file)
		if e != nil {
			return nil, e
		}
		items, e := parseSchema(f)
		f.Close()
		if e != nil {
			return nil, e
		}
		qualifyLocalSchemaTypes(items)
		all = append(all, items...)
		for _, item := range items {
			schemaRegistry[item.Name] = append([]Field(nil), item.Fields...)
			// Local definitions are referenced by their short name in sproto.
			// Keep a conservative alias for uniquely identifiable definitions.
			if strings.HasSuffix(item.Name, ".base") && hasSchemaFields(item.Fields, "lv", "status", "furniture") {
				schemaRegistry["base"] = append([]Field(nil), item.Fields...)
			}
		}
		// Most referenced types are globally unique even when local types are
		// stored with a qualified name. Add only unambiguous short-name aliases;
		// ambiguous names must not be guessed.
		counts := map[string]int{}
		for _, item := range items {
			short := item.Name
			if idx := strings.LastIndexByte(short, '.'); idx >= 0 {
				short = short[idx+1:]
			}
			counts[short]++
		}
		for _, item := range items {
			short := item.Name
			if idx := strings.LastIndexByte(short, '.'); idx >= 0 {
				short = short[idx+1:]
			}
			if counts[short] == 1 {
				schemaRegistry[short] = append([]Field(nil), item.Fields...)
			}
		}
	}
	return all, nil
}

func qualifyLocalSchemaTypes(items []Schema) {
	known := make(map[string]bool, len(items))
	for _, item := range items {
		known[item.Name] = true
	}
	for i := range items {
		for j := range items[i].Fields {
			field := &items[i].Fields[j]
			raw := strings.TrimSpace(field.Type)
			prefix := ""
			if strings.HasPrefix(raw, "*") {
				prefix = "*"
				raw = strings.TrimPrefix(raw, "*")
			}
			suffix := ""
			if idx := strings.IndexByte(raw, '('); idx >= 0 {
				suffix = raw[idx:]
				raw = raw[:idx]
			}
			candidate := items[i].Name + "." + strings.TrimSuffix(raw, "()")
			if known[candidate] {
				field.Type = prefix + candidate + suffix
			}
		}
	}
}

func hasSchemaFields(fields []Field, names ...string) bool {
	set := make(map[string]bool, len(fields))
	for _, f := range fields {
		set[f.Name] = true
	}
	for _, name := range names {
		if !set[name] {
			return false
		}
	}
	return true
}

func parseSchema(r io.Reader) ([]Schema, error) {
	var all []Schema
	type frame struct {
		name  string
		depth int
		index int
	}
	var stack []frame
	s := bufio.NewScanner(r)
	line := 0
	for s.Scan() {
		line++
		code := strings.SplitN(s.Text(), "#", 2)[0]
		text := strings.TrimSpace(code)
		depth := strings.Count(code, "{") - strings.Count(code, "}")
		if m := schemaStart.FindStringSubmatch(text); m != nil {
			if len(stack) == 0 && len(code) != len(strings.TrimLeft(code, " \t")) {
				// This is a command-local structure. It must not overwrite a
				// global type with the same short name. Command-local types are
				// resolved by their command context instead.
				continue
			}
			name := m[1]
			if len(stack) > 0 {
				name = stack[len(stack)-1].name + "." + name
			}
			all = append(all, Schema{Name: name, Line: line})
			stack = append(stack, frame{name: name, depth: len(stack) + 1, index: len(all) - 1})
		} else if len(stack) > 0 && text != "" {
			current := &all[stack[len(stack)-1].index]
			if m := fieldLine.FindStringSubmatch(text); m != nil {
				current.Fields = append(current.Fields, Field{Name: m[1], Tag: m[2], Type: strings.TrimSpace(m[3]), Line: line})
			}
		}
		if len(stack) > 0 {
			// A closing brace may close several empty inline blocks. Pop after
			// recording fields so the parent resumes on the next line.
			for len(stack) > 0 && strings.Count(code, "}") > 0 {
				stack = stack[:len(stack)-1]
				if strings.Count(code, "}") == 1 {
					break
				}
			}
		}
		_ = depth
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	return all, nil
}

func loadCommands(path string) ([]ProtocolCommand, error) {
	commandVariants = map[uint64][]ProtocolCommand{}
	files, err := schemaFiles(path)
	if err != nil {
		return nil, err
	}
	var all []ProtocolCommand
	for _, file := range files {
		f, e := os.Open(file)
		if e != nil {
			return nil, e
		}
		items, e := parseCommands(f)
		f.Close()
		if e != nil {
			return nil, e
		}
		all = append(all, items...)
		for _, command := range items {
			commandVariants[command.ID] = append(commandVariants[command.ID], command)
		}
	}
	return all, nil
}

func commandForDirection(id uint64, direction string, fallback map[uint64]ProtocolCommand) (ProtocolCommand, bool) {
	variants := commandVariants[id]
	for _, command := range variants {
		if direction == "request" && command.Category == "req" {
			return command, true
		}
		if direction == "response" && command.Category == "rsp" {
			return command, true
		}
	}
	if direction == "request" {
		for _, command := range variants {
			if command.Category == "notify" {
				continue
			}
			return command, true
		}
	}
	if command, ok := fallback[id]; ok {
		return command, true
	}
	return ProtocolCommand{}, false
}

func parseCommands(r io.Reader) ([]ProtocolCommand, error) {
	s := bufio.NewScanner(r)
	line := 0
	var out []ProtocolCommand
	for s.Scan() {
		line++
		text := strings.TrimSpace(s.Text())
		m := commandLine.FindStringSubmatch(text)
		if m == nil {
			continue
		}
		var id uint64
		if _, err := fmt.Sscan(m[4], &id); err != nil {
			continue
		}
		depth, hasReq, hasRsp := 1, false, false
		section := ""
		sectionDepth := 0
		var reqFields, rspFields []Field
		var reqType, rspType string
		for s.Scan() {
			line++
			t := strings.TrimSpace(s.Text())
			code := strings.SplitN(t, "#", 2)[0]
			if strings.HasPrefix(strings.TrimSpace(code), "request") {
				hasReq = true
				if typed := sectionTypeLine.FindStringSubmatch(strings.TrimSpace(code)); typed != nil {
					reqType = typed[2]
				}
				section = "request"
				sectionDepth = depth + strings.Count(code, "{")
			}
			if strings.HasPrefix(strings.TrimSpace(code), "response") {
				hasRsp = true
				if typed := sectionTypeLine.FindStringSubmatch(strings.TrimSpace(code)); typed != nil {
					rspType = typed[2]
				}
				section = "response"
				sectionDepth = depth + strings.Count(code, "{")
			}
			if depth == sectionDepth {
				if fieldMatch := fieldLine.FindStringSubmatch(strings.TrimSpace(code)); fieldMatch != nil {
					field := Field{Name: fieldMatch[1], Tag: fieldMatch[2], Type: strings.TrimSpace(fieldMatch[3]), Line: line}
					if section == "request" {
						reqFields = append(reqFields, field)
					} else if section == "response" {
						rspFields = append(rspFields, field)
					}
				}
			}
			depth += strings.Count(code, "{") - strings.Count(code, "}")
			if section != "" && depth < sectionDepth {
				section = ""
			}
			if depth <= 0 {
				break
			}
		}
		category := m[2]
		if category == "" {
			category = "transport"
		}
		name := strings.TrimPrefix(m[1], m[2]+"_")
		out = append(out, ProtocolCommand{Name: name, ID: id, HasReq: hasReq, HasRsp: hasRsp, Line: line, Category: category, ReqFields: reqFields, RspFields: rspFields, ReqType: reqType, RspType: rspType})
	}
	return out, s.Err()
}

func writeSchemaItems(items []Schema, out string) error {
	b, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(out, b, 0644)
}

func writeSchemaIndex(path, out string) error {
	items, err := loadSchema(path)
	if err != nil {
		return err
	}
	if err := writeSchemaItems(items, out); err != nil {
		return err
	}
	fmt.Printf("schema indexed: %d structures -> %s\n", len(items), out)
	return nil
}
