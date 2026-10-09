package main

// Uso por endereço e a lista para o console do admin do Services (pedido do Jaime em 09/10/2026).
//
// Por endereço e por dia (horário de Brasília) contamos as faturas geradas para quem paga (a fatura
// de teste do cadastro não conta) e os zaps pagos, cujo recibo foi publicado. Só contagens: nem
// valor, nem quem pagou. Ficam no mesmo pebble, em chaves "stats:<endereço>:<dia>".
//
// GET /admin/addresses devolve os endereços cadastrados, sem credencial nem endereço do node, com
// as datas e o uso. Só responde com ADMIN_TOKEN, a quem conecta da própria máquina e sem passar pelo
// nginx (que manda X-Forwarded-For): o Services pergunta direto em 127.0.0.1.

import (
	"crypto/subtle"
	"encoding/json"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cockroachdb/pebble"
)

const statsPrefix = "stats:"

var (
	statsMutex sync.Mutex
	brasilia   = time.FixedZone("BRT", -3*60*60)
	statsNow   = time.Now
)

type dayStats struct {
	Invoices int `json:"invoices"`
	Zaps     int `json:"zaps"`
}

// recordUse soma um uso ("invoice" ou "zap") ao dia de hoje do endereço. Falha não atrapalha o pagamento.
func recordUse(name, domain, what string) {
	if db == nil {
		return
	}
	statsMutex.Lock()
	defer statsMutex.Unlock()
	key := []byte(statsPrefix + getID(name, domain) + ":" + statsNow().In(brasilia).Format("2006-01-02"))
	var day dayStats
	if val, closer, err := db.Get(key); err == nil {
		json.Unmarshal(val, &day)
		closer.Close()
	}
	switch what {
	case "invoice":
		day.Invoices++
	case "zap":
		day.Zaps++
	default:
		return
	}
	data, _ := json.Marshal(day)
	if err := db.Set(key, data, pebble.NoSync); err != nil {
		log.Debug().Err(err).Msg("stats: could not record use")
	}
}

type addressInfo struct {
	Address       string `json:"address"`
	Kind          string `json:"kind"`
	Tor           bool   `json:"tor"`
	Zaps          bool   `json:"zaps"`
	CreatedAt     int64  `json:"created_at,omitempty"`
	UpdatedAt     int64  `json:"updated_at,omitempty"`
	Invoices30d   int    `json:"invoices_30d"`
	Zaps30d       int    `json:"zaps_30d"`
	InvoicesTotal int    `json:"invoices_total"`
	ZapsTotal     int    `json:"zaps_total"`
	LastUsed      string `json:"last_used,omitempty"`
}

// listAddresses lê os cadastros e o uso. Nenhum campo de credencial sai daqui.
func listAddresses() []addressInfo {
	since := statsNow().In(brasilia).AddDate(0, 0, -30).Format("2006-01-02")
	byID := map[string]*addressInfo{}
	var order []string
	it := db.NewIter(nil)
	defer it.Close()
	for it.First(); it.Valid(); it.Next() {
		key := string(it.Key())
		if strings.HasPrefix(key, statsPrefix) {
			continue
		}
		var p Params
		if json.Unmarshal(it.Value(), &p) != nil {
			continue
		}
		address := key
		if !strings.Contains(address, "@") && p.Domain != "" {
			address = key + "@" + p.Domain
		}
		info := &addressInfo{Address: address, Kind: p.Kind, Tor: strings.Contains(p.Host, ".onion"),
			Zaps: zapsFor(&p), CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt}
		byID[key] = info
		order = append(order, key)
	}
	for it.SeekGE([]byte(statsPrefix)); it.Valid() && strings.HasPrefix(string(it.Key()), statsPrefix); it.Next() {
		rest := strings.TrimPrefix(string(it.Key()), statsPrefix)
		cut := strings.LastIndex(rest, ":")
		if cut < 0 {
			continue
		}
		info, day := byID[rest[:cut]], rest[cut+1:]
		if info == nil {
			continue
		}
		var d dayStats
		if json.Unmarshal(it.Value(), &d) != nil {
			continue
		}
		info.InvoicesTotal += d.Invoices
		info.ZapsTotal += d.Zaps
		if day >= since {
			info.Invoices30d += d.Invoices
			info.Zaps30d += d.Zaps
		}
		if day > info.LastUsed {
			info.LastUsed = day
		}
	}
	out := make([]addressInfo, 0, len(order))
	for _, id := range order {
		out = append(out, *byID[id])
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].CreatedAt > out[j].CreatedAt })
	return out
}

func handleAdminAddresses(w http.ResponseWriter, r *http.Request) {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	ip := net.ParseIP(host)
	given := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if s.AdminToken == "" || ip == nil || !ip.IsLoopback() || r.Header.Get("X-Forwarded-For") != "" ||
		r.Header.Get("X-Real-IP") != "" || subtle.ConstantTimeCompare([]byte(given), []byte(s.AdminToken)) != 1 {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]interface{}{"generated_at": statsNow().Unix(), "addresses": listAddresses()})
}
