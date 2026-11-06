package main

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func TestCheckNewName(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "membros.txt")
	os.WriteFile(file, []byte("# membros\nTiger\nredin\n"), 0o600)
	s.ReservedNamesFile = file
	defer func() { s.ReservedNamesFile = "" }()

	for _, name := range []string{"jaime", "jvxis", "brlnclub", "hub", "suporte", "meujvx", "tiger", "redin"} {
		if checkNewName(name) != errReservedName {
			t.Errorf("%s deveria ser reservado", name)
		}
	}
	for _, name := range []string{"aria-label", "Maria", "a b", ""} {
		if name == "aria-label" {
			continue // é válido; só não é reservado
		}
		if checkNewName(name) != errBadName {
			t.Errorf("%q deveria ser recusado pelo formato", name)
		}
	}
	for _, name := range []string{"maria", "liberty.bitcoin", "sr_kaplan_21", "tigernode2"} {
		if err := checkNewName(name); err != nil {
			t.Errorf("%s deveria passar: %v", name, err)
		}
	}
}

func TestCheckDemoHost(t *testing.T) {
	for host, bad := range map[string]bool{
		"https://demo.lnbits.com":    true,
		"https://legend.lnbits.com/": true,
		"https://wallet.br-ln.com":   false,
		"abc.onion:8080":             false,
	} {
		if (checkDemoHost(&Params{Kind: "lnbits", Host: host}) != nil) != bad {
			t.Errorf("%s: esperado recusar=%v", host, bad)
		}
	}
}

func TestSameHostRedirect(t *testing.T) {
	first := &http.Request{URL: &url.URL{Scheme: "http", Host: "tinyurl.com", Path: "/x"}}
	same := &http.Request{URL: &url.URL{Scheme: "https", Host: "tinyurl.com:443", Path: "/x"}}
	other := &http.Request{URL: &url.URL{Scheme: "http", Host: "127.0.0.1:5000"}}
	if sameHostRedirect(same, []*http.Request{first}) != nil {
		t.Error("http -> https no mesmo host deveria seguir")
	}
	if sameHostRedirect(other, []*http.Request{first}) == nil {
		t.Error("redirecionamento para outro host deveria ser recusado")
	}
}
