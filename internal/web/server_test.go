package web

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fakessh/internal/store"
)

func TestDashboardFilteringEscapingAndSecurityHeaders(t *testing.T) {
	ctx := context.Background()
	dataStore, err := store.Open(ctx, filepath.Join(t.TempDir(), "web.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer dataStore.Close()
	attempts := []store.Attempt{{Username: []byte(`<script>alert(1)</script>`), Password: []byte(`p&<"word`), Method: "password", RemoteIP: "2001:db8::1", RemotePort: 123, ClientVersion: []byte("SSH-2.0-test<script>"), At: time.Now()}, {Username: []byte("binary"), Password: []byte{'x', 0, 0xff}, Method: "keyboard-interactive", RemoteIP: "192.0.2.1", RemotePort: 456, ClientVersion: []byte("client"), At: time.Now()}}
	for _, a := range attempts {
		if err := dataStore.Record(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	server, err := New(":0", dataStore, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/attempts?ip=2001%3Adb8&method=password&page_size=1", nil)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	body := response.Body.String()
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, body)
	}
	if !strings.Contains(body, "1 unique credential pair") || strings.Contains(body, "binary") {
		t.Fatalf("filter did not apply: %s", body)
	}
	if strings.Contains(body, `<script>alert(1)</script>`) {
		t.Fatal("dynamic script content was not HTML escaped")
	}
	if !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Fatal("escaped username missing")
	}
	for _, header := range []string{"Content-Security-Policy", "X-Content-Type-Options", "X-Robots-Tag"} {
		if response.Header().Get(header) == "" {
			t.Errorf("missing %s", header)
		}
	}
	binaryRequest := httptest.NewRequest(http.MethodGet, "/attempts?username=binary", nil)
	binaryResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(binaryResponse, binaryRequest)
	if !strings.Contains(binaryResponse.Body.String(), `x\x00\xff`) {
		t.Fatalf("binary password not escaped: %s", binaryResponse.Body.String())
	}
}

func TestHealthChecksDatabase(t *testing.T) {
	dataStore, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "health.db"))
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(":0", dataStore, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	body, _ := io.ReadAll(response.Result().Body)
	if response.Code != 200 || string(body) != "ok\n" {
		t.Fatalf("healthy response: %d %q", response.Code, body)
	}
	dataStore.Close()
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("closed database status=%d", response.Code)
	}
}

func TestPaginationURLPreservesAndEscapesFilters(t *testing.T) {
	filter := store.AttemptFilter{Username: "root & admin", Password: "p?#", IP: "2001:db8::1", Method: "password", Client: "OpenSSH", PageSize: 25}
	got := attemptURL(filter, 2)
	request := httptest.NewRequest(http.MethodGet, got, nil)
	query := request.URL.Query()
	if query.Get("username") != filter.Username || query.Get("password") != filter.Password || query.Get("ip") != filter.IP || query.Get("page") != "2" || query.Get("page_size") != "25" {
		t.Fatalf("pagination URL lost filters: %s", got)
	}
}
