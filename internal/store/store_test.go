package store

import (
	"bytes"
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(context.Background(), filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestRecordDeduplicatesAndAggregatesSources(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	base := time.Date(2026, 7, 27, 10, 0, 0, 0, time.UTC)
	attempt := Attempt{Username: []byte("root"), Password: []byte("hunter2"), Method: "password", RemoteIP: "192.0.2.10", RemotePort: 50123, ClientVersion: []byte("SSH-2.0-test"), At: base}
	if err := s.Record(ctx, attempt); err != nil {
		t.Fatal(err)
	}
	attempt.At = base.Add(time.Hour)
	attempt.RemotePort = 50124
	if err := s.Record(ctx, attempt); err != nil {
		t.Fatal(err)
	}
	attempt.RemoteIP = "2001:db8::5"
	attempt.Method = "keyboard-interactive"
	if err := s.Record(ctx, attempt); err != nil {
		t.Fatal(err)
	}
	page, err := s.Credentials(ctx, AttemptFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 1 || len(page.Items) != 1 || page.Items[0].Attempts != 3 || page.Items[0].Sources != 2 {
		t.Fatalf("unexpected credential aggregation: %+v", page)
	}
	if !page.Items[0].FirstSeen.Equal(base) || !page.Items[0].LastSeen.Equal(base.Add(time.Hour)) {
		t.Fatalf("unexpected times: %+v", page.Items[0])
	}
	sources, total, err := s.Sources(ctx, page.Items[0].ID, 1, 50)
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || len(sources) != 2 {
		t.Fatalf("unexpected sources: total=%d values=%+v", total, sources)
	}
	stats, err := s.Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stats.TotalAttempts != 3 || stats.UniqueCredentials != 1 || stats.UniqueIPs != 2 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
}

func TestConcurrentUpsertIsAccurate(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	const count = 64
	a := Attempt{Username: []byte("admin"), Password: []byte("admin"), Method: "password", RemoteIP: "198.51.100.8", RemotePort: 22, ClientVersion: []byte("scanner"), At: time.Now()}
	var wg sync.WaitGroup
	errs := make(chan error, count)
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- s.Record(ctx, a) }()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	page, err := s.Credentials(ctx, AttemptFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 1 || page.Items[0].Attempts != count {
		t.Fatalf("want %d attempts, got %+v", count, page)
	}
	sources, _, err := s.Sources(ctx, page.Items[0].ID, 1, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(sources) != 1 || sources[0].Attempts != count {
		t.Fatalf("unexpected source count: %+v", sources)
	}
}

func TestTruncationUsesFullInputForDeduplication(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	prefix := bytes.Repeat([]byte("x"), MaxPasswordBytes)
	for _, suffix := range []byte{'a', 'b'} {
		password := append(append([]byte{}, prefix...), suffix)
		if err := s.Record(ctx, Attempt{Username: bytes.Repeat([]byte("u"), MaxUsernameBytes+1), Password: password, Method: "password", RemoteIP: "203.0.113.2", ClientVersion: bytes.Repeat([]byte("c"), MaxClientBytes+1), At: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	page, err := s.Credentials(ctx, AttemptFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 2 {
		t.Fatalf("different full passwords must remain unique, got %d", page.Total)
	}
	if !page.Items[0].UsernameTruncated || !page.Items[0].PasswordTruncated {
		t.Fatalf("missing truncation markers: %+v", page.Items[0])
	}
}

func TestDisplayBytes(t *testing.T) {
	if got := DisplayBytes([]byte("<script>")); got != "<script>" {
		t.Fatalf("printable text changed: %q", got)
	}
	if got := DisplayBytes([]byte{'a', 0, 0xff}); got != `a\x00\xff` {
		t.Fatalf("binary rendering = %q", got)
	}
}

func TestPersistenceAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "persistent.db")
	ctx := context.Background()
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	a := Attempt{Username: []byte("root"), Password: []byte("toor"), Method: "password", RemoteIP: "127.0.0.1", ClientVersion: []byte("client"), At: time.Now()}
	if err := s.Record(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	page, err := s.Credentials(ctx, AttemptFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 1 || page.Items[0].Attempts != 1 {
		t.Fatalf("data did not persist: %+v", page)
	}
}

func TestSubsecondFirstAndLastSeenOrdering(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	base := time.Date(2026, 7, 27, 10, 0, 0, 0, time.UTC)
	a := Attempt{Username: []byte("time"), Password: []byte("test"), Method: "password", RemoteIP: "192.0.2.20", ClientVersion: []byte("client")}
	a.At = base.Add(900 * time.Millisecond)
	if err := s.Record(ctx, a); err != nil {
		t.Fatal(err)
	}
	a.At = base
	if err := s.Record(ctx, a); err != nil {
		t.Fatal(err)
	}
	page, err := s.Credentials(ctx, AttemptFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if !page.Items[0].FirstSeen.Equal(base) || !page.Items[0].LastSeen.Equal(base.Add(900*time.Millisecond)) {
		t.Fatalf("subsecond ordering is wrong: %+v", page.Items[0])
	}
}
