package main

import (
	"context"
	"errors"
	"net"
	"testing"
)

func fakeLookup(answers map[string][]string) func(context.Context, string) ([]net.IPAddr, error) {
	return func(_ context.Context, name string) ([]net.IPAddr, error) {
		ips, ok := answers[name]
		if !ok {
			return nil, errors.New("no such host")
		}
		var out []net.IPAddr
		for _, ip := range ips {
			out = append(out, net.IPAddr{IP: net.ParseIP(ip)})
		}
		return out, nil
	}
}

func TestCheckPublicHost(t *testing.T) {
	lookup := fakeLookup(map[string][]string{
		"wallet.br-ln.com": {"209.145.59.4"},
		"localhost":        {"127.0.0.1", "::1"},
		"interno.example":  {"8.8.8.8", "10.0.0.5"}, // um dos endereços é privado: recusa
	})
	cases := []struct {
		kind, host string
		ok         bool
	}{
		// o que os usuários de verdade usam
		{"lnd", "https://abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz23.onion:8080", true},
		{"lnbits", "https://wallet.br-ln.com", true},
		{"lnd", "https://209.145.59.4:8080", true},
		{"lnpay", "", true},
		// o que a sondagem de 23/10/2026 tentou
		{"lnbits", "http://127.0.0.1:3000", false},
		{"lnd", "http://127.0.0.1:9737", false},
		{"lnbits", "http://10.147.17.32:9737", false},
		{"lnbits", "http://localhost:8080", false},
		{"lnd", "https://[::1]:8080", false},
		{"lnbits", "http://100.96.108.7:5000", false}, // Tailscale
		{"lnbits", "http://192.168.0.10", false},
		{"lnbits", "http://169.254.169.254/latest", false},
		{"lnbits", "http://0.0.0.0:5000", false},
		{"commando", "127.0.0.1:9735", false},
		{"lnbits", "http://interno.example", false},
		{"lnbits", "http://nao-existe.example", false},
		{"lnbits", "", false},
	}
	for _, c := range cases {
		err := checkPublicHost(&Params{Kind: c.kind, Host: c.host}, lookup)
		if (err == nil) != c.ok {
			t.Errorf("%s %q: err=%v, want ok=%v", c.kind, c.host, err, c.ok)
		}
	}
}
