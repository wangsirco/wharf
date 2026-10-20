package panel

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	"github.com/wangsirco/wharf/internal/release"
	"github.com/wangsirco/wharf/internal/version"
)

// A fake GitHub serving a signed release whose only change is the web UI.
func TestOnlineWebUpdate(t *testing.T) {
	dir := t.TempDir()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	updateKey = base64.StdEncoding.EncodeToString(pub)
	defer func() { updateKey = version.UpdateKey }()

	// the new UI bundle
	src := filepath.Join(dir, "newweb")
	_ = os.MkdirAll(filepath.Join(src, "assets"), 0o755)
	_ = os.WriteFile(filepath.Join(src, "index.html"), []byte("<html>new ui</html>"), 0o644)
	_ = os.WriteFile(filepath.Join(src, "assets", "app.js"), []byte("console.log(2)"), 0o644)
	var bundle bytes.Buffer
	if err := release.PackWeb(src, &bundle); err != nil {
		t.Fatal(err)
	}
	webHash, _ := release.WebHash(os.DirFS(src))
	sum := sha256.Sum256(bundle.Bytes())

	var m release.Manifest
	m.Version = "99.0.0"
	m.Core.Hash = version.CoreHash // program unchanged
	m.Core.Packages = map[string]release.Asset{}
	m.Web.Hash = webHash
	m.Web.Asset = release.Asset{Name: "wharf-web-99.0.0.tar.gz", SHA256: hex.EncodeToString(sum[:]), Size: int64(bundle.Len())}
	mb, _ := json.Marshal(m)
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, mb))
	tamper := false

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/me/wharf/releases/latest":
			fmt.Fprintf(w, `{"tag_name":"v99.0.0","html_url":"x","body":"notes","assets":[
				{"name":%q,"browser_download_url":"%s/dl/%s"},{"name":%q,"browser_download_url":"%s/dl/%s"}]}`,
				release.ManifestName, srv.URL, release.ManifestName, release.SigName, srv.URL, release.SigName)
		case "/dl/" + release.ManifestName:
			if tamper {
				w.Write(bytes.Replace(mb, []byte("99.0.0"), []byte("99.0.1"), 1))
				return
			}
			w.Write(mb)
		case "/dl/" + release.SigName:
			w.Write([]byte(sig))
		case "/dl/wharf-web-99.0.0.tar.gz":
			w.Write(bundle.Bytes())
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	githubAPI = srv.URL
	defer func() { githubAPI = "https://api.github.com" }()

	db, err := OpenDB(filepath.Join(dir, "panel.db"))
	if err != nil {
		t.Fatal(err)
	}
	builtin := fstest.MapFS{"index.html": {Data: []byte("<html>old ui</html>")}}
	a := NewApp(Config{DataDir: dir, Agent: AgentConfig{URL: "http://127.0.0.1:1"}}, db, builtin)
	_ = a.setSetting("update.repo", "me/wharf")

	info := a.checkUpdate()
	if !info.Signed || info.manifest == nil {
		t.Fatalf("manifest not accepted: %+v", info.Error)
	}
	byID := map[string]compStatus{}
	for _, c := range info.Components {
		byID[c.ID] = c
	}
	if byID["core"].Update || !byID["web"].Update || !info.Newer {
		t.Fatalf("expected a web-only update: %+v", info.Components)
	}
	if err := a.installWeb(info.base, info.manifest); err != nil {
		t.Fatal(err)
	}
	if b, _ := fs.ReadFile(a.webState().fs, "index.html"); string(b) != "<html>new ui</html>" || a.webState().version != "99.0.0" {
		t.Fatalf("new UI not served: %q", b)
	}
	// a restart keeps serving the downloaded UI
	a2 := NewApp(Config{DataDir: dir, Agent: AgentConfig{URL: "http://127.0.0.1:1"}}, db, builtin)
	a2.loadWebOverride()
	if !a2.webState().override {
		t.Fatal("override not reloaded after restart")
	}
	a2.dropWebOverride()
	if b, _ := fs.ReadFile(a2.webState().fs, "index.html"); string(b) != "<html>old ui</html>" {
		t.Fatal("rollback did not restore the built-in UI")
	}

	tamper = true
	if info := a.checkUpdate(); info.manifest != nil || info.Error == "" {
		t.Fatal("tampered manifest accepted")
	}
}
