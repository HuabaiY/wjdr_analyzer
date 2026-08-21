module github.com/HuabaiY/wjdr_analyzer

go 1.20

require github.com/husanpao/game-mitm v0.0.0-00010101000000-000000000000

require (
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/jchv/go-webview2 v0.0.0-20260205173254-56598839c808 // indirect
	github.com/jchv/go-winloader v0.0.0-20250406163304-c1995be93bd1 // indirect
	github.com/pierrec/lz4/v4 v4.1.22 // indirect
	golang.org/x/sys v0.0.0-20210218145245-beda7e5e158e // indirect
)

replace github.com/husanpao/game-mitm => ./third_party/game-mitm
