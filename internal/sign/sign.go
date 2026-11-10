// Package sign implements the HMAC request signing shared by owp-panel (client)
// and owp-agent (server).
//
// Canonical string:  METHOD \n PATH?QUERY \n TIMESTAMP \n NONCE \n hex(sha256(body))
// Headers:           X-OWP-Key, X-OWP-Ts, X-OWP-Nonce, X-OWP-Sig (hex HMAC-SHA256)
package sign

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"
)

const MaxSkew = 60 * time.Second

func canonical(method, uri, ts, nonce string, body []byte) []byte {
	h := sha256.Sum256(body)
	var b bytes.Buffer
	b.WriteString(method + "\n" + uri + "\n" + ts + "\n" + nonce + "\n")
	b.WriteString(hex.EncodeToString(h[:]))
	return b.Bytes()
}

func mac(secret, msg []byte) string {
	m := hmac.New(sha256.New, secret)
	m.Write(msg)
	return hex.EncodeToString(m.Sum(nil))
}

func RandomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Sign adds signature headers to req. body must be the exact request body.
func Sign(req *http.Request, keyID string, secret []byte, body []byte) {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := RandomHex(12)
	req.Header.Set("X-OWP-Key", keyID)
	req.Header.Set("X-OWP-Ts", ts)
	req.Header.Set("X-OWP-Nonce", nonce)
	req.Header.Set("X-OWP-Sig", mac(secret, canonical(req.Method, req.URL.RequestURI(), ts, nonce, body)))
}

// Verifier checks signatures and rejects replays inside the skew window.
type Verifier struct {
	Keys map[string][]byte // keyID -> secret

	mu     sync.Mutex
	nonces map[string]time.Time
}

func NewVerifier(keys map[string][]byte) *Verifier {
	return &Verifier{Keys: keys, nonces: map[string]time.Time{}}
}

var (
	ErrUnsigned  = errors.New("missing signature")
	ErrBadKey    = errors.New("unknown key")
	ErrSkew      = errors.New("timestamp outside window")
	ErrReplay    = errors.New("nonce reused")
	ErrSignature = errors.New("bad signature")
)

// Verify reads and returns the body (so handlers can re-read it) after checking the signature.
func (v *Verifier) Verify(r *http.Request) ([]byte, error) {
	keyID, ts, nonce, sig := r.Header.Get("X-OWP-Key"), r.Header.Get("X-OWP-Ts"), r.Header.Get("X-OWP-Nonce"), r.Header.Get("X-OWP-Sig")
	if keyID == "" || ts == "" || nonce == "" || sig == "" {
		return nil, ErrUnsigned
	}
	secret, ok := v.Keys[keyID]
	if !ok {
		return nil, ErrBadKey
	}
	t, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return nil, ErrSkew
	}
	if d := time.Since(time.Unix(t, 0)); d > MaxSkew || d < -MaxSkew {
		return nil, ErrSkew
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<20)) // config backups with OpenClash data reach ~20 MB
	if err != nil {
		return nil, err
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	want := mac(secret, canonical(r.Method, r.URL.RequestURI(), ts, nonce, body))
	if !hmac.Equal([]byte(want), []byte(sig)) {
		return nil, ErrSignature
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	now := time.Now()
	for n, exp := range v.nonces {
		if now.After(exp) {
			delete(v.nonces, n)
		}
	}
	if _, dup := v.nonces[keyID+nonce]; dup {
		return nil, ErrReplay
	}
	v.nonces[keyID+nonce] = now.Add(2 * MaxSkew)
	return body, nil
}

// ---- token-bound signing between paired panels (Wharf ⇄ Berth) ----
//
// Same canonical string as above. The caller sends "Authorization: Bearer <token>" and
// <P>-Ts, <P>-Nonce, <P>-Sig, where <P> is the sender's header prefix ("X-Berth" when Berth
// calls Wharf, "X-Wharf" the other way) and the HMAC key is DeriveKey(token).

// DeriveKey turns a pairing token into its request-signing key.
func DeriveKey(token string) []byte {
	m := hmac.New(sha256.New, []byte(token))
	m.Write([]byte("wharf-berth-sign-v1"))
	return m.Sum(nil)
}

// SignPrefixed adds <prefix>-Ts, -Nonce and -Sig headers to req.
func SignPrefixed(req *http.Request, prefix string, key, body []byte) {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := RandomHex(12)
	req.Header.Set(prefix+"-Ts", ts)
	req.Header.Set(prefix+"-Nonce", nonce)
	req.Header.Set(prefix+"-Sig", mac(key, canonical(req.Method, req.URL.RequestURI(), ts, nonce, body)))
}

// CheckPrefixed verifies the time window and signature of a request whose body has
// already been read; it returns the nonce so the caller can reject replays durably.
func CheckPrefixed(r *http.Request, prefix string, key, body []byte) (string, error) {
	ts, nonce, sig := r.Header.Get(prefix+"-Ts"), r.Header.Get(prefix+"-Nonce"), r.Header.Get(prefix+"-Sig")
	if ts == "" || nonce == "" || sig == "" || len(nonce) > 64 {
		return "", ErrUnsigned
	}
	t, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return "", ErrSkew
	}
	if d := time.Since(time.Unix(t, 0)); d > MaxSkew || d < -MaxSkew {
		return "", ErrSkew
	}
	want := mac(key, canonical(r.Method, r.URL.RequestURI(), ts, nonce, body))
	if !hmac.Equal([]byte(want), []byte(sig)) {
		return "", ErrSignature
	}
	return nonce, nil
}
