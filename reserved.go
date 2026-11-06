package main

import (
	"bufio"
	"errors"
	"net/http"
	"os"
	"regexp"
	"strings"
)

// Em 06/11/2026 um robô cadastrou jaime@, jvxis@, hub@ e brlnclub@ apontando para carteiras dele no
// demo.lnbits.com: no nosso domínio, parecem endereços do clube. Agora um nome novo não pode imitar o
// clube nem um membro, e o demo do LNbits não serve de carteira. Endereços que já existem seguem
// funcionando e o dono continua podendo atualizá-los com o PIN.

var errReservedName = errors.New(
	"Esse nome é reservado ao clube BR⚡LN. Se ele é seu, fale com o suporte do clube. / " +
		"This name is reserved for the BR⚡LN club. If it is yours, ask the club's support.")

var errBadName = errors.New(
	"Use de 1 a 64 letras minúsculas, números, ponto, hífen ou sublinhado. / " +
		"Use 1 to 64 lowercase letters, digits, dot, hyphen or underscore.")

var errDemoHost = errors.New(
	"Carteiras de demonstração do LNbits não podem receber aqui. / LNbits demo wallets are not accepted.")

var validName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// Pedaços que nenhum nome novo pode conter: o Jaime e o clube.
var reservedFragments = []string{"jaime", "jvx", "brln", "br-ln", "brlightning", "lightningclub"}

// Nomes de serviço do clube e do próprio site.
var reservedExact = map[string]bool{
	"admin": true, "administrador": true, "root": true, "suporte": true, "support": true,
	"clube": true, "club": true, "hub": true, "tower": true, "watchtower": true, "guardiao": true,
	"relay": true, "signer": true, "wallet": true, "carteira": true, "faucet": true,
	"services": true, "service": true, "market": true, "mercado": true, "pay": true,
	"satdress": true, "staking": true, "tesouraria": true, "caixa": true, "financeiro": true,
	"pool": true, "btcpool": true, "bot": true, "arauto": true, "comunidade": true,
	"community": true, "contato": true, "contact": true, "oficial": true, "official": true,
	"doacao": true, "doacoes": true, "donate": true, "satsback": true, "biblioteca": true,
}

var demoHosts = map[string]bool{"demo.lnbits.com": true, "legend.lnbits.com": true}

// reservedFromFile lê RESERVED_NAMES_FILE (um nome por linha, # comenta) a cada consulta, para a
// lista de membros mudar sem reiniciar o serviço.
func reservedFromFile(name string) bool {
	if s.ReservedNamesFile == "" {
		return false
	}
	f, err := os.Open(s.ReservedNamesFile)
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.ToLower(strings.TrimSpace(sc.Text()))
		if line != "" && !strings.HasPrefix(line, "#") && line == name {
			return true
		}
	}
	return false
}

func isReserved(name string) bool {
	if reservedExact[name] {
		return true
	}
	for _, part := range reservedFragments {
		if strings.Contains(name, part) {
			return true
		}
	}
	return reservedFromFile(name)
}

// checkNewName vale só para um nome que ainda não existe.
func checkNewName(name string) error {
	if !validName.MatchString(name) {
		return errBadName
	}
	if isReserved(name) {
		return errReservedName
	}
	return nil
}

func checkDemoHost(params *Params) error {
	if demoHosts[strings.ToLower(hostName(params.Host))] {
		return errDemoHost
	}
	return nil
}

// sameHostRedirect só segue redirecionamento para o mesmo host (http -> https, por exemplo). Um
// encurtador como o tinyurl levaria a fatura a 127.0.0.1 depois da conferência do host.
func sameHostRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 3 {
		return errors.New("too many redirects from the node host")
	}
	if !strings.EqualFold(req.URL.Hostname(), via[0].URL.Hostname()) {
		return errors.New("node host redirected to another host")
	}
	return nil
}
