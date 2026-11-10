package sign

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPrefixedRoundTrip(t *testing.T) {
	key := DeriveKey("wharf_bth_x")
	body := []byte(`{"a":1}`)
	r := httptest.NewRequest("POST", "/api/ext/berth/v1/bans?x=1", strings.NewReader(string(body)))
	SignPrefixed(r, "X-Berth", key, body)
	if _, err := CheckPrefixed(r, "X-Berth", key, body); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckPrefixed(r, "X-Berth", DeriveKey("other"), body); err != ErrSignature {
		t.Fatalf("other key: %v", err)
	}
	if _, err := CheckPrefixed(r, "X-Berth", key, []byte(`{"a":2}`)); err != ErrSignature {
		t.Fatalf("other body: %v", err)
	}
	if _, err := CheckPrefixed(r, "X-Wharf", key, body); err != ErrUnsigned {
		t.Fatalf("other prefix: %v", err)
	}
}
