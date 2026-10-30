package panel

import (
	"crypto/md5"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
)

func TestOnePanelSites(t *testing.T) {
	const key = "k3y"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sum := md5.Sum([]byte("1panel" + key + r.Header.Get("1Panel-Timestamp")))
		if r.Header.Get("1Panel-Token") != hex.EncodeToString(sum[:]) {
			w.Write([]byte(`{"code":401,"message":"API 接口禁止访问","data":null}`))
			return
		}
		switch r.URL.Path {
		case "/api/v1/websites/search":
			w.Write([]byte(`{"code":200,"data":{"total":1,"items":[{"id":3,"primaryDomain":"Blog.Example.com","alias":"blog","protocol":"HTTPS","status":"Running"}]}}`))
		case "/api/v1/websites/domains/3":
			w.Write([]byte(`{"code":200,"data":[{"domain":"blog.example.com","port":80},{"domain":"*.cdn.example.com","port":80}]}`))
		default:
			w.WriteHeader(404)
			w.Write([]byte("<html>"))
		}
	}))
	defer srv.Close()

	if _, _, err := fetchOnePanelSites(srv.URL, "wrong"); err == nil {
		t.Fatal("wrong key accepted")
	}
	sites, ver, err := fetchOnePanelSites(srv.URL, key)
	if err != nil || ver != "v1" || len(sites) != 1 {
		t.Fatalf("sites=%v ver=%s err=%v", sites, ver, err)
	}
	if !slices.Equal(sites[0].Domains, []string{"blog.example.com", "*.cdn.example.com"}) {
		t.Fatalf("domains %v", sites[0].Domains)
	}
	onePanel.sites = sites
	defer func() { onePanel.sites = nil }()
	for d, want := range map[string]bool{"blog.example.com": true, "a.cdn.example.com": true, "a.b.cdn.example.com": false, "xtls.example.com": false} {
		if got := onePanelOwner(d) != nil; got != want {
			t.Errorf("%s: %v", d, got)
		}
	}
}
