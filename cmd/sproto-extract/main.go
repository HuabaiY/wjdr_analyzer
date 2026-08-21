package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"unicode/utf8"
)

var commandPattern = regexp.MustCompile(`(?m)^(req|notify|notfiy|watch|rsp|loginauth)_[A-Za-z0-9_]+\s+[0-9]+\s*\{`)

type moduleSpec struct {
	name       string
	output     string
	minimumCmd int
}

func main() {
	in := flag.String("in", "", "extracted NETEASE Lua package (required)")
	out := flag.String("out", "protocol/generated", "generated sproto directory")
	flag.Parse()
	if *in == "" {
		fatal(fmt.Errorf("-in is required"))
	}

	container, err := os.ReadFile(*in)
	if err != nil {
		fatal(err)
	}
	specs := []moduleSpec{
		{name: "game_proto_game_proto_c2s", output: "c2s.sproto", minimumCmd: 1800},
		{name: "game_proto_game_proto_s2c", output: "s2c.sproto", minimumCmd: 1000},
	}
	if err := os.MkdirAll(*out, 0755); err != nil {
		fatal(err)
	}
	for _, spec := range specs {
		source, count, err := extractModule(container, spec)
		if err != nil {
			fatal(err)
		}
		path := filepath.Join(*out, spec.output)
		if err := os.WriteFile(path, source, 0644); err != nil {
			fatal(err)
		}
		fmt.Printf("generated %s: %d bytes, %d commands\n", path, len(source), count)
	}
}

func extractModule(container []byte, spec moduleSpec) ([]byte, int, error) {
	name := []byte(spec.name)
	pos := bytes.LastIndex(container, name)
	if pos < 0 {
		return nil, 0, fmt.Errorf("module not found: %s", spec.name)
	}
	lengthPos := align4(pos + len(name) + 1)
	if lengthPos+4 > len(container) {
		return nil, 0, fmt.Errorf("invalid module header: %s", spec.name)
	}
	length := int(binary.LittleEndian.Uint32(container[lengthPos : lengthPos+4]))
	dataPos := lengthPos + 4
	if length <= 0 || dataPos+length > len(container) {
		return nil, 0, fmt.Errorf("invalid module length %d: %s", length, spec.name)
	}
	decoded := make([]byte, length)
	for i, b := range container[dataPos : dataPos+length] {
		decoded[i] = b ^ 0x66
	}
	start := bytes.Index(decoded, []byte(".item {"))
	end := bytes.LastIndexByte(decoded, '}')
	if start < 0 || end < start {
		return nil, 0, fmt.Errorf("sproto source boundary not found: %s", spec.name)
	}
	source := append([]byte(nil), decoded[start:end+1]...)
	source = append(source, '\n')
	if !utf8.Valid(source) {
		return nil, 0, fmt.Errorf("decoded source is not UTF-8: %s", spec.name)
	}
	count := len(commandPattern.FindAll(source, -1))
	if count < spec.minimumCmd {
		return nil, count, fmt.Errorf("incomplete module %s: got %d commands, require at least %d", spec.name, count, spec.minimumCmd)
	}
	return source, count, nil
}

func align4(v int) int { return (v + 3) &^ 3 }

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
