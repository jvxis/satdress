package main

import (
	"context"
	"errors"
	"net"
	"net/url"
	"strings"
	"time"
)

// O cadastro (/grab) gera uma fatura de teste no node que o usuário informa. Em 23/10/2026 alguém usou
// isso para sondar a rede interna da VPS: 127.0.0.1 em várias portas, um IP privado e o IP do HUB, e o
// texto do erro de cada tentativa dizia o que havia lá. Agora o node do cadastro tem de ser público ou
// .onion (que vai pelo Tor). A regra vale só para cadastrar ou atualizar: os endereços já cadastrados
// seguem como estão.

var errHostNotPublic = errors.New("node host must be a public address or a .onion")

// cgnat é 100.64.0.0/10: CGNAT das operadoras e a rede do Tailscale.
var cgnat = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

func hostName(host string) string {
	host = strings.TrimSpace(host)
	if strings.Contains(host, "://") {
		if u, err := url.Parse(host); err == nil {
			return u.Hostname()
		}
		return ""
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return strings.Trim(host, "[]")
}

func publicIP(ip net.IP) bool {
	return ip.IsGlobalUnicast() && !ip.IsPrivate() && !cgnat.Contains(ip)
}

// checkPublicHost recusa node que não seja público ou .onion. lookup resolve o nome (nos testes, um falso).
func checkPublicHost(params *Params, lookup func(context.Context, string) ([]net.IPAddr, error)) error {
	if params.Kind == "lnpay" {
		return nil // fala com a API do LNPay, não com um host do usuário
	}
	name := strings.ToLower(hostName(params.Host))
	if name == "" {
		return errHostNotPublic
	}
	if strings.HasSuffix(name, ".onion") {
		return nil
	}
	if ip := net.ParseIP(name); ip != nil {
		if !publicIP(ip) {
			return errHostNotPublic
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := lookup(ctx, name)
	if err != nil || len(addrs) == 0 {
		return errors.New("could not resolve the node host")
	}
	for _, addr := range addrs {
		if !publicIP(addr.IP) {
			return errHostNotPublic
		}
	}
	return nil
}
