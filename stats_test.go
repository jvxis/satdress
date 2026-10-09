package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cockroachdb/pebble"
)

func openTestDB(t *testing.T) func() {
	dir, _ := os.MkdirTemp("", "satdress-stats")
	var err error
	db, err = pebble.Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	s.Domain, s.Secret = "pay.example", "x"
	return func() { db.Close(); db = nil; os.RemoveAll(dir) }
}

func put(t *testing.T, name string, p Params) {
	data, _ := json.Marshal(p)
	if err := db.Set([]byte(getID(name, "pay.example")), data, pebble.Sync); err != nil {
		t.Fatal(err)
	}
}

func TestUseIsCountedPerDayAndListed(t *testing.T) {
	defer openTestDB(t)()
	nostrKey, nostrPubkey = key(5), xOnly(key(5))
	defer func() { nostrKey, nostrPubkey = nil, "" }()
	put(t, "ana", Params{Kind: "lnd", Host: "https://abcdef.onion:8080", Key: "SEGREDO-MACAROON", CreatedAt: 200})
	put(t, "bia", Params{Kind: "lnbits", Host: "https://lnbits.example", Key: "SEGREDO-LNBITS"})

	day := time.Date(2026, 10, 1, 12, 0, 0, 0, brasilia)
	statsNow = func() time.Time { return day }
	recordUse("ana", "pay.example", "invoice")
	recordUse("ana", "pay.example", "zap")
	day = time.Date(2026, 10, 9, 12, 0, 0, 0, brasilia)
	recordUse("ana", "pay.example", "invoice")
	recordUse("ana", "pay.example", "outra coisa")
	day = time.Date(2026, 11, 5, 12, 0, 0, 0, brasilia) // 30 dias: de 6/10 em diante (1/10 fica fora, 9/10 dentro)
	defer func() { statsNow = time.Now }()

	list := listAddresses()
	if len(list) != 2 || list[0].Address != "ana@pay.example" {
		t.Fatalf("lista %+v", list)
	}
	a, b := list[0], list[1]
	if !a.Tor || !a.Zaps || a.Kind != "lnd" || a.CreatedAt != 200 || a.InvoicesTotal != 2 || a.ZapsTotal != 1 ||
		a.Invoices30d != 1 || a.Zaps30d != 0 || a.LastUsed != "2026-10-09" {
		t.Fatalf("ana %+v", a)
	}
	if b.Tor || !b.Zaps || b.InvoicesTotal != 0 || b.LastUsed != "" {
		t.Fatalf("bia %+v", b)
	}
	out, _ := json.Marshal(list)
	for _, secret := range []string{"SEGREDO", "onion", "lnbits.example", "host", "key"} {
		if strings.Contains(string(out), secret) {
			t.Fatalf("vazou %q: %s", secret, out)
		}
	}
}

func TestAdminRouteNeedsTokenLoopbackAndNoProxy(t *testing.T) {
	defer openTestDB(t)()
	put(t, "ana", Params{Kind: "lnd", Host: "https://x.onion", Key: "k"})
	call := func(remote, token string, headers map[string]string) int {
		r := httptest.NewRequest("GET", "/admin/addresses", nil)
		r.RemoteAddr = remote
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		handleAdminAddresses(w, r)
		return w.Code
	}
	s.AdminToken = ""
	if call("127.0.0.1:5000", "", nil) != 404 {
		t.Fatal("sem ADMIN_TOKEN configurado respondeu")
	}
	s.AdminToken = "t0ken"
	defer func() { s.AdminToken = "" }()
	if call("127.0.0.1:5000", "errado", nil) != 404 || call("127.0.0.1:5000", "", nil) != 404 {
		t.Fatal("token errado ou ausente respondeu")
	}
	if call("203.0.113.9:5000", "t0ken", nil) != 404 {
		t.Fatal("respondeu para fora da máquina")
	}
	if call("127.0.0.1:5000", "t0ken", map[string]string{"X-Forwarded-For": "203.0.113.9"}) != 404 {
		t.Fatal("respondeu por trás do nginx")
	}
	if call("127.0.0.1:5000", "t0ken", nil) != 200 || call("[::1]:5000", "t0ken", nil) != 200 {
		t.Fatal("pedido certo recusado")
	}
}
