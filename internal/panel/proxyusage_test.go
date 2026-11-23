package panel

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestUsageBucket(t *testing.T) {
	now := int64(1_800_000_000)
	if b := usageBucket(now-3*3600, now, now, now-86400); b != 300 {
		t.Errorf("3h recent: %d", b)
	}
	if b := usageBucket(now-3*3600, now, now, 0); b != 3600 {
		t.Errorf("3h without fine data: %d", b)
	}
	if b := usageBucket(now-2*86400, now, now, now-86400); b != 3600 {
		t.Errorf("2d: %d", b)
	}
	if b := usageBucket(now-30*86400, now, now, now-86400); b != 86400 {
		t.Errorf("30d: %d", b)
	}
}

func TestProxyUsage(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "u.db"))
	if err != nil {
		t.Fatal(err)
	}
	a := &App{db: db}
	now := time.Now().Unix()
	created := now - 10*86400
	mustExec := func(q string, args ...any) {
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatal(err)
		}
	}
	mustExec(`INSERT INTO proxy_nodes(id, owner_id, name, protocol, transport, security, entry, port, created, updated) VALUES(1, 1, 'n1', 'vless', 'tcp', 'reality', 'port', 4430, ?, ?)`, created, created)
	mustExec(`INSERT INTO proxy_nodes(id, owner_id, name, protocol, transport, security, entry, port, created, updated) VALUES(2, 2, 'n2', 'vless', 'tcp', 'reality', 'port', 4431, ?, ?)`, created, created)
	for _, u := range []struct {
		id, owner int64
		name      string
	}{{1, 1, "alice"}, {2, 1, "bob"}, {3, 2, "carol"}} {
		mustExec(`INSERT INTO proxy_users(id, owner_id, name, secret, sub_token, created) VALUES(?, ?, ?, 's', ?, ?)`, u.id, u.owner, u.name, u.name, created)
	}
	h := now / 3600 * 3600
	mustExec(`INSERT INTO proxy_traffic VALUES(?, 1, 1, 100, 1000)`, h-5*86400)
	mustExec(`INSERT INTO proxy_traffic VALUES(?, 2, 1, 10, 20)`, h-3600)
	mustExec(`INSERT INTO proxy_traffic VALUES(?, 9, 1, 1, 2)`, h-3600) // deleted user
	mustExec(`INSERT INTO proxy_traffic VALUES(?, 3, 1, 5, 5)`, h-3600) // someone else's user on node 1
	mustExec(`INSERT INTO proxy_traffic VALUES(?, 3, 2, 7, 7)`, h-7200) // someone else's node

	get := func(u *User, q string) usageResp {
		r := httptest.NewRequest("GET", "/api/proxy/usage?"+q, nil)
		r = r.WithContext(context.WithValue(r.Context(), userKey, u))
		w := httptest.NewRecorder()
		a.handleProxyUsage(w, r)
		var out usageResp
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", q, w.Code, w.Body)
		}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return out
	}
	admin := &User{ID: 1, Role: "admin"}
	// node 1 since creation: all its traffic, by user, the other admin's user summed, the deleted one named
	r := get(admin, "node=1")
	if r.From != created || r.Total.Up != 116 || r.Total.Down != 1027 || r.Bucket != 86400 || r.ByKind != "user" {
		t.Fatalf("node lifetime: %+v", r)
	}
	names := map[string]int64{}
	for _, p := range r.By {
		names[p.Name] = p.Up + p.Down
	}
	if names["alice"] != 1100 || names["bob"] != 30 || names["已删除的用户 #9"] != 3 || names["其他管理员的用户"] != 10 {
		t.Fatalf("parts: %+v", names)
	}
	// the last 2 days: hours, only the recent rows
	r = get(admin, "node=1&from="+itoa64(now-2*86400))
	if r.Bucket != 3600 || r.Total.Up+r.Total.Down != 43 || r.Peak == nil {
		t.Fatalf("node 2d: %+v", r.Total)
	}
	// an admin can't see another admin's node
	rq := httptest.NewRequest("GET", "/api/proxy/usage?node=2", nil)
	rq = rq.WithContext(context.WithValue(rq.Context(), userKey, admin))
	w := httptest.NewRecorder()
	a.handleProxyUsage(w, rq)
	if w.Code != 404 {
		t.Fatalf("foreign node: %d", w.Code)
	}
	// everything for the super admin
	r = get(&User{ID: 9, Role: RoleSuper}, "from="+itoa64(now-86400))
	if r.Total.Up+r.Total.Down != 57 || r.ByKind != "node" {
		t.Fatalf("all 24h: %+v", r.Total)
	}
	// a user: per node
	r = get(admin, "user=1")
	if r.Total.Up != 100 || len(r.By) != 1 || r.By[0].Name != "n1" {
		t.Fatalf("user: %+v", r)
	}
}
