package panel

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
)

func TestUndoOwnChange(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "u.db"))
	if err != nil {
		t.Fatal(err)
	}
	a := &App{db: db}
	me := &User{ID: 7, Username: "me", Role: "admin"}
	other := &User{ID: 8, Username: "other", Role: "admin"}
	_ = a.setSetting("ui.name", "New")
	a.audit(actor{user: me}, "setting.update", "setting", "ui.name", "修改设置 ui.name", "Old", "New", true)

	req := func(u *User, method, path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, nil)
		r = r.WithContext(context.WithValue(r.Context(), userKey, u))
		w := httptest.NewRecorder()
		if method == "GET" {
			a.handleUndoable(w, r)
		} else {
			r.SetPathValue("id", path[len("/api/audit/"):len(path)-len("/undo")])
			a.handleUndo(w, r)
		}
		return w
	}
	var got struct {
		ID      int64  `json:"id"`
		Summary string `json:"summary"`
	}
	_ = json.Unmarshal(req(me, "GET", "/api/audit/undo?since=0").Body.Bytes(), &got)
	if got.ID == 0 {
		t.Fatal("no undoable entry")
	}
	var none map[string]any
	_ = json.Unmarshal(req(other, "GET", "/api/audit/undo?since=0").Body.Bytes(), &none)
	if len(none) != 0 {
		t.Fatalf("other user sees my change: %v", none)
	}
	path := "/api/audit/" + strconv.FormatInt(got.ID, 10) + "/undo"
	if w := req(other, "POST", path); w.Code != 403 {
		t.Fatalf("other user undid: %d", w.Code)
	}
	if w := req(me, "POST", path); w.Code != 200 {
		t.Fatalf("undo: %d %s", w.Code, w.Body)
	}
	if v := a.setting("ui.name"); v != "Old" {
		t.Fatalf("setting after undo: %q", v)
	}
	if w := req(me, "POST", path); w.Code != 400 {
		t.Fatalf("second undo: %d", w.Code)
	}
	// the restore itself is not offered for undo
	_ = json.Unmarshal(req(me, "GET", "/api/audit/undo?since=0").Body.Bytes(), &none)
	if len(none) != 0 {
		t.Fatalf("restore offered as undoable: %v", none)
	}
}
