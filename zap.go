package main

// Zaps do Nostr (NIP-57) no satdress, feitos para o pay.br-ln.com em 09/10/2026.
//
// 1. A resposta da Lightning address anuncia allowsNostr e a pubkey do servidor (nostrPubkey).
// 2. Quem zapeia manda o pedido de zap (kind 9734) no parâmetro nostr do callback: ele é validado
//    e vira a descrição da fatura (o description_hash é o sha256 dele), criada no node do dono.
// 3. O satdress só repassa faturas e não as acompanha; para o zap, ele consulta o node do dono com
//    a credencial que o dono já cadastrou (LND: macaroon de fatura, que pode consultar faturas;
//    LNbits: chave de fatura) até a fatura ser paga ou o prazo acabar.
// 4. Paga, o servidor assina o recibo (kind 9735) e o publica nos relays que o pedido indicou.
//
// O servidor nunca toca nos sats. Sem NOSTR_PRIVATE_KEY, nada disso é anunciado e o satdress
// funciona como antes. Os zaps pendentes ficam só em memória: um restart no meio de um zap perde
// o recibo daquele zap (o pagamento chega normalmente ao dono).

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/fiatjaf/makeinvoice"
)

const (
	zapRequestKind = 9734
	zapReceiptKind = 9735
	maxZapRequest  = 16 * 1024
	maxZapRelays   = 10
	maxPendingZaps = 300
	zapWatchFor    = 65 * time.Minute
)

var (
	nostrKey     *btcec.PrivateKey
	nostrPubkey  string
	pendingZaps  int
	pendingMutex sync.Mutex

	// Trocáveis nos testes.
	zapCheckPaid = checkPaid
	zapPublish   = publishEvent
	zapSleep     = time.Sleep
)

func setupZaps() {
	if s.NostrPrivateKey == "" {
		log.Info().Msg("zaps desligados: sem NOSTR_PRIVATE_KEY")
		return
	}
	sk, err := parseNostrKey(s.NostrPrivateKey)
	if err != nil {
		log.Error().Err(err).Msg("zaps desligados")
		return
	}
	nostrKey, nostrPubkey = sk, xOnly(sk)
	log.Info().Str("nostrPubkey", nostrPubkey).Msg("zaps ligados")
}

// zapsFor diz se este dono pode receber zaps: precisa de um backend que dê para consultar.
func zapsFor(params *Params) bool {
	return nostrKey != nil && (params.Kind == "lnd" || params.Kind == "lnbits")
}

// parseZapRequest valida o pedido de zap como o NIP-57 (apêndice D) manda.
func parseZapRequest(raw string, msat int) (*NostrEvent, error) {
	if len(raw) > maxZapRequest {
		return nil, errors.New("zap request too large")
	}
	var ev NostrEvent
	if err := json.Unmarshal([]byte(raw), &ev); err != nil {
		return nil, errors.New("zap request is not valid json")
	}
	if ev.Kind != zapRequestKind {
		return nil, errors.New("zap request must be kind 9734")
	}
	if !ev.CheckSignature() {
		return nil, errors.New("zap request has an invalid signature")
	}
	if ev.countTags("p") != 1 {
		return nil, errors.New("zap request must have exactly one p tag")
	}
	if p := ev.firstTag("p"); len(p) < 2 || !isHex32(p[1]) {
		return nil, errors.New("zap request has an invalid p tag")
	}
	if ev.countTags("e") > 1 {
		return nil, errors.New("zap request must have at most one e tag")
	}
	if ev.countTags("P") > 1 {
		return nil, errors.New("zap request must have at most one P tag")
	}
	if len(zapRelays(&ev)) == 0 {
		return nil, errors.New("zap request must list relays")
	}
	if a := ev.firstTag("amount"); a != nil {
		if len(a) < 2 || a[1] != strconv.Itoa(msat) {
			return nil, errors.New("zap request amount differs from the invoice amount")
		}
	}
	return &ev, nil
}

func isHex32(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 32
}

// zapRelays são os relays do pedido (só ws/wss, sem repetir, no máximo maxZapRelays) e os de ZAP_RELAYS.
func zapRelays(ev *NostrEvent) []string {
	seen := map[string]bool{}
	var out []string
	add := func(r string) {
		r = strings.TrimSpace(r)
		u, err := url.Parse(r)
		if err != nil || (u.Scheme != "wss" && u.Scheme != "ws") || u.Host == "" || seen[r] || len(out) >= maxZapRelays {
			return
		}
		seen[r] = true
		out = append(out, r)
	}
	if t := ev.firstTag("relays"); t != nil {
		for _, r := range t[1:] {
			add(r)
		}
	}
	for _, r := range getDomains(s.ZapRelays) {
		add(r)
	}
	return out
}

// paymentHash tira o hash do pagamento (campo p) de uma fatura bolt11.
func paymentHash(bolt11 string) (string, error) {
	_, data, err := bech32.DecodeNoLimit(strings.ToLower(bolt11))
	if err != nil {
		return "", err
	}
	// 7 palavras de data; a assinatura ocupa as últimas 104.
	if len(data) < 7+104 {
		return "", errors.New("invoice too short")
	}
	fields := data[7 : len(data)-104]
	for i := 0; i+3 <= len(fields); {
		kind := fields[i]
		size := int(fields[i+1])*32 + int(fields[i+2])
		if i+3+size > len(fields) {
			break
		}
		if kind == 1 && size == 52 { // 'p'
			b, err := bech32.ConvertBits(fields[i+3:i+3+size], 5, 8, false)
			if err != nil {
				return "", err
			}
			return hex.EncodeToString(b), nil
		}
		i += 3 + size
	}
	return "", errors.New("invoice without payment hash")
}

// httpFor é um cliente próprio (o da makeinvoice troca de transporte a cada fatura), com TLS sem
// conferência (o REST do LND usa certificado próprio) e o Tor para endereço .onion.
func httpFor(host string) *http.Client {
	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	if strings.Contains(host, ".onion") {
		proxy := s.TorProxyURL
		if proxy == "" {
			proxy = makeinvoice.TorProxyURL
		}
		if u, err := url.Parse(proxy); err == nil {
			transport.Proxy = http.ProxyURL(u)
		}
	}
	return &http.Client{Timeout: 30 * time.Second, Transport: transport}
}

// checkPaid consulta o node do dono: (pago, preimage em hex, quando).
func checkPaid(params *Params, hash string) (bool, string, int64, error) {
	var req *http.Request
	var err error
	switch params.Kind {
	case "lnd":
		req, err = http.NewRequest("GET", strings.TrimRight(params.Host, "/")+"/v1/invoice/"+hash, nil)
		if err != nil {
			return false, "", 0, err
		}
		mac := params.Key
		if b, err := base64.StdEncoding.DecodeString(mac); err == nil {
			mac = hex.EncodeToString(b)
		}
		req.Header.Set("Grpc-Metadata-macaroon", mac)
	case "lnbits":
		req, err = http.NewRequest("GET", strings.TrimRight(params.Host, "/")+"/api/v1/payments/"+hash, nil)
		if err != nil {
			return false, "", 0, err
		}
		req.Header.Set("X-Api-Key", params.Key)
	default:
		return false, "", 0, errors.New("backend without zap support")
	}
	resp, err := httpFor(params.Host).Do(req)
	if err != nil {
		return false, "", 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return false, "", 0, fmt.Errorf("backend answered %d", resp.StatusCode)
	}
	if params.Kind == "lnd" {
		var inv struct {
			State      string `json:"state"`
			Settled    bool   `json:"settled"`
			Preimage   string `json:"r_preimage"`
			SettleDate string `json:"settle_date"`
		}
		if err := json.Unmarshal(body, &inv); err != nil {
			return false, "", 0, err
		}
		if inv.State != "SETTLED" && !inv.Settled {
			return false, "", 0, nil
		}
		pre := ""
		if b, err := base64.StdEncoding.DecodeString(inv.Preimage); err == nil && len(b) == 32 {
			pre = hex.EncodeToString(b)
		}
		at, _ := strconv.ParseInt(inv.SettleDate, 10, 64)
		return true, pre, at, nil
	}
	var pay struct {
		Paid     bool   `json:"paid"`
		Preimage string `json:"preimage"`
	}
	if err := json.Unmarshal(body, &pay); err != nil {
		return false, "", 0, err
	}
	if !pay.Paid {
		return false, "", 0, nil
	}
	pre := pay.Preimage
	if !isHex32(pre) || strings.Trim(pre, "0") == "" {
		pre = ""
	}
	return true, pre, 0, nil
}

// zapReceipt monta e assina o recibo do NIP-57.
func zapReceipt(zapReq *NostrEvent, rawZapReq, bolt11, preimage string, paidAt int64) (*NostrEvent, error) {
	tags := [][]string{{"p", zapReq.firstTag("p")[1]}}
	for _, name := range []string{"e", "a"} {
		if t := zapReq.firstTag(name); len(t) >= 2 {
			tags = append(tags, []string{name, t[1]})
		}
	}
	tags = append(tags, []string{"P", zapReq.PubKey}, []string{"bolt11", bolt11}, []string{"description", rawZapReq})
	if preimage != "" {
		tags = append(tags, []string{"preimage", preimage})
	}
	if paidAt == 0 {
		paidAt = time.Now().Unix()
	}
	ev := &NostrEvent{CreatedAt: paidAt, Kind: zapReceiptKind, Tags: tags, Content: ""}
	if err := ev.Sign(nostrKey); err != nil {
		return nil, err
	}
	return ev, nil
}

// watchZap acompanha a fatura do zap e publica o recibo quando ela for paga. Devolve false (sem
// acompanhar) se já houver zaps demais pendentes: o pagamento segue normal, só não vira recibo.
func watchZap(params *Params, zapReq *NostrEvent, rawZapReq, bolt11 string) bool {
	hash, err := paymentHash(bolt11)
	if err != nil {
		log.Error().Err(err).Msg("zap: fatura sem hash")
		return false
	}
	pendingMutex.Lock()
	if pendingZaps >= maxPendingZaps {
		pendingMutex.Unlock()
		log.Warn().Msg("zap: muitos pendentes, sem recibo para este")
		return false
	}
	pendingZaps++
	pendingMutex.Unlock()
	go func() {
		defer func() {
			pendingMutex.Lock()
			pendingZaps--
			pendingMutex.Unlock()
		}()
		start := time.Now()
		for attempt := 0; time.Since(start) < zapWatchFor; attempt++ {
			// A cada 3 s no primeiro minuto (o zap costuma ser pago na hora), depois a cada 20 s.
			if attempt < 20 {
				zapSleep(3 * time.Second)
			} else {
				zapSleep(20 * time.Second)
			}
			paid, preimage, at, err := zapCheckPaid(params, hash)
			if err != nil {
				log.Debug().Err(err).Str("name", params.Name).Msg("zap: consulta falhou")
				continue
			}
			if !paid {
				continue
			}
			receipt, err := zapReceipt(zapReq, rawZapReq, bolt11, preimage, at)
			if err != nil {
				log.Error().Err(err).Msg("zap: recibo não assinado")
				return
			}
			ok := 0
			for _, relay := range zapRelays(zapReq) {
				if err := zapPublish(relay, receipt, 10*time.Second); err != nil {
					log.Debug().Err(err).Str("relay", relay).Msg("zap: relay não aceitou")
					continue
				}
				ok++
			}
			log.Info().Str("name", params.Name).Int("relays", ok).Msg("zap: recibo publicado")
			return
		}
		log.Debug().Str("name", params.Name).Msg("zap: fatura não paga no prazo")
	}()
	return true
}
