package panel

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

const tgTestToken = "123456789:AAHfakefakefakefakefakefakefake_123"

func TestTelegramChannel(t *testing.T) {
	updates := `[{"update_id":1,"message":{"message_id":2,"from":{"id":555,"is_bot":false,"first_name":"测试"},
		"chat":{"id":555,"first_name":"测试","username":"someone","type":"private"},"date":1,"text":"111"}}]`
	tg := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/bot"+tgTestToken+"/") {
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`{"ok":false,"description":"Unauthorized"}`))
			return
		}
		switch {
		case strings.HasSuffix(r.URL.Path, "/getMe"):
			_, _ = w.Write([]byte(`{"ok":true,"result":{"username":"wharf_test_bot"}}`))
		case strings.HasSuffix(r.URL.Path, "/getUpdates"):
			_, _ = w.Write([]byte(`{"ok":true,"result":` + updates + `}`))
		}
	}))
	defer tg.Close()
	tgAPI = tg.URL
	defer func() { tgAPI = "https://api.telegram.org" }()

	db, err := OpenDB(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	a := &App{db: db}
	add := func(body map[string]string) (int, string) {
		b, _ := json.Marshal(body)
		req := httptest.NewRequest("POST", "/api/alerts/channels", bytes.NewReader(b))
		req = req.WithContext(context.WithValue(req.Context(), userKey, &User{ID: 1, Username: "admin", Role: RoleSuper}))
		rec := httptest.NewRecorder()
		a.handleAlertChannelAdd(rec, req)
		return rec.Code, rec.Body.String()
	}
	url := func() (u string) {
		_ = db.QueryRow(`SELECT url FROM alert_channels ORDER BY id DESC LIMIT 1`).Scan(&u)
		return
	}

	// chat_id as the page sends it (snake case) — was dropped before 0.18.2
	if code, body := add(map[string]string{"type": "telegram", "token": tgTestToken, "chat_id": "123456789"}); code != 200 {
		t.Fatalf("explicit chat id: %d %s", code, body)
	}
	if url() != "telegram://"+tgTestToken+"/123456789" {
		t.Fatalf("url %s", url())
	}
	// no chat id, token pasted as the whole getUpdates address with spaces
	if code, body := add(map[string]string{"type": "telegram", "token": "  " + tg.URL + "/bot" + tgTestToken + "/getUpdates \n"}); code != 200 {
		t.Fatalf("auto chat id: %d %s", code, body)
	}
	if url() != "telegram://"+tgTestToken+"/555" {
		t.Fatalf("auto url %s", url())
	}
	// wrong token: says so
	if code, body := add(map[string]string{"type": "telegram", "token": "123456789:AAEwrongwrongwrongwrongwrongwrong_x", "chat_id": "1"}); code != 400 || !strings.Contains(body, "Bot Token 无效") {
		t.Fatalf("bad token: %d %s", code, body)
	}
	// nobody wrote to the bot yet
	updates = `[]`
	if code, body := add(map[string]string{"type": "telegram", "token": tgTestToken}); code != 400 || !strings.Contains(body, "@wharf_test_bot") {
		t.Fatalf("no chats: %d %s", code, body)
	}
}
