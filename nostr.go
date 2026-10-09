package main

// O mínimo de Nostr que os zaps (NIP-57) pedem: evento, id, assinatura e publicação num relay.
// Feito aqui com o que o projeto já usa (btcec/v2 e gorilla/websocket) em vez de trazer uma
// biblioteca Nostr inteira, que arrastaria dezenas de módulos para um servidor de pagamentos.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/gorilla/websocket"
)

type NostrEvent struct {
	ID        string     `json:"id"`
	PubKey    string     `json:"pubkey"`
	CreatedAt int64      `json:"created_at"`
	Kind      int        `json:"kind"`
	Tags      [][]string `json:"tags"`
	Content   string     `json:"content"`
	Sig       string     `json:"sig"`
}

// serialize é o [0, pubkey, created_at, kind, tags, content] do NIP-01, cujo sha256 é o id.
func (e *NostrEvent) serialize() []byte {
	tags := e.Tags
	if tags == nil {
		tags = [][]string{}
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.Encode([]interface{}{0, e.PubKey, e.CreatedAt, e.Kind, tags, e.Content})
	out := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
	// encoding/json escapa U+2028 e U+2029; o NIP-01 manda deixá-los como estão.
	out = bytes.ReplaceAll(out, []byte(`\u2028`), []byte("\u2028"))
	out = bytes.ReplaceAll(out, []byte(`\u2029`), []byte("\u2029"))
	return out
}

func (e *NostrEvent) computeID() string {
	sum := sha256.Sum256(e.serialize())
	return hex.EncodeToString(sum[:])
}

// CheckSignature confere que o id é o do conteúdo e que a assinatura é da pubkey.
func (e *NostrEvent) CheckSignature() bool {
	if e.ID != e.computeID() {
		return false
	}
	pk, err := hex.DecodeString(e.PubKey)
	if err != nil || len(pk) != 32 {
		return false
	}
	pub, err := schnorr.ParsePubKey(pk)
	if err != nil {
		return false
	}
	sigb, err := hex.DecodeString(e.Sig)
	if err != nil {
		return false
	}
	sig, err := schnorr.ParseSignature(sigb)
	if err != nil {
		return false
	}
	id, _ := hex.DecodeString(e.ID)
	return sig.Verify(id, pub)
}

func (e *NostrEvent) Sign(sk *btcec.PrivateKey) error {
	e.PubKey = xOnly(sk)
	e.ID = e.computeID()
	id, _ := hex.DecodeString(e.ID)
	sig, err := schnorr.Sign(sk, id)
	if err != nil {
		return err
	}
	e.Sig = hex.EncodeToString(sig.Serialize())
	return nil
}

func (e *NostrEvent) firstTag(name string) []string {
	for _, t := range e.Tags {
		if len(t) >= 1 && t[0] == name {
			return t
		}
	}
	return nil
}

func (e *NostrEvent) countTags(name string) int {
	n := 0
	for _, t := range e.Tags {
		if len(t) >= 1 && t[0] == name {
			n++
		}
	}
	return n
}

func xOnly(sk *btcec.PrivateKey) string {
	return hex.EncodeToString(schnorr.SerializePubKey(sk.PubKey()))
}

func parseNostrKey(hexKey string) (*btcec.PrivateKey, error) {
	b, err := hex.DecodeString(strings.TrimSpace(hexKey))
	if err != nil || len(b) != 32 {
		return nil, errors.New("NOSTR_PRIVATE_KEY precisa ter 64 caracteres hex")
	}
	sk, _ := btcec.PrivKeyFromBytes(b)
	return sk, nil
}

// publishEvent manda o evento a um relay e espera o OK dele (ou o prazo).
func publishEvent(relayURL string, ev *NostrEvent, timeout time.Duration) error {
	dialer := websocket.Dialer{HandshakeTimeout: timeout}
	conn, _, err := dialer.Dial(relayURL, nil)
	if err != nil {
		return err
	}
	defer conn.Close()
	deadline := time.Now().Add(timeout)
	conn.SetWriteDeadline(deadline)
	if err := conn.WriteJSON([]interface{}{"EVENT", ev}); err != nil {
		return err
	}
	conn.SetReadDeadline(deadline)
	for {
		var msg []json.RawMessage
		if err := conn.ReadJSON(&msg); err != nil {
			return err
		}
		if len(msg) < 3 {
			continue
		}
		var label, id string
		json.Unmarshal(msg[0], &label)
		json.Unmarshal(msg[1], &id)
		if label != "OK" || id != ev.ID {
			continue
		}
		var ok bool
		json.Unmarshal(msg[2], &ok)
		if ok {
			return nil
		}
		reason := ""
		if len(msg) > 3 {
			json.Unmarshal(msg[3], &reason)
		}
		return fmt.Errorf("relay recusou: %s", reason)
	}
}
