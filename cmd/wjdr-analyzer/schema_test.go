package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadSchema(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "test.sproto")
	if err := os.WriteFile(p, []byte(".demo {\n id 0 : integer\n name 1 : string # comment\n}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	items, err := loadSchema(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || len(items[0].Fields) != 2 || items[0].Fields[1].Type != "string" {
		t.Fatalf("unexpected schema: %#v", items)
	}
}

func TestParseCurrentCategorizedCommands(t *testing.T) {
	commands, err := parseCommands(strings.NewReader("req_heartbeat 22 {\n request {\n token 0 : string\n }\n response {\n time 1 : integer\n }\n}\n"))
	if err != nil || len(commands) != 1 || commands[0].Name != "heartbeat" || commands[0].ID != 22 || !commands[0].HasReq || !commands[0].HasRsp || len(commands[0].ReqFields) != 1 || commands[0].ReqFields[0].Name != "token" || len(commands[0].RspFields) != 1 || commands[0].RspFields[0].Name != "time" {
		t.Fatalf("unexpected commands: %#v err=%v", commands, err)
	}
}

func TestCurrentLoginCryptoFields(t *testing.T) {
	commands, err := loadCommands("../../protocol/generated")
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range commands {
		if command.ID != 1 || command.Category != "transport" {
			continue
		}
		foundKey, foundMethod := false, false
		for _, field := range command.RspFields {
			foundKey = foundKey || (field.Name == "secret_key" && field.Tag == "14")
			foundMethod = foundMethod || (field.Name == "crypt_method" && field.Tag == "16")
		}
		if foundKey && foundMethod {
			return
		}
	}
	t.Fatal("loginauth response crypto fields were not indexed")
}
