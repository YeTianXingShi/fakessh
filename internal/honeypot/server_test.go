package honeypot

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"fakessh/internal/store"
	"golang.org/x/crypto/ssh"
)

func TestPasswordAndKeyboardInteractiveAlwaysFailAndRecord(t *testing.T) {
	ctx := context.Background()
	dataStore, err := store.Open(ctx, filepath.Join(t.TempDir(), "ssh.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer dataStore.Close()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := New("", dataStore, signer, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		server.Shutdown(shutdownCtx)
		<-done
	}()
	base := &ssh.ClientConfig{User: "root", HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 2 * time.Second, ClientVersion: "SSH-2.0-FakeSSH_Test"}
	passwordConfig := *base
	passwordConfig.Auth = []ssh.AuthMethod{ssh.Password("correct-or-not")}
	if client, err := ssh.Dial("tcp", listener.Addr().String(), &passwordConfig); err == nil {
		client.Close()
		t.Fatal("password authentication unexpectedly succeeded")
	}
	keyboardConfig := *base
	keyboardConfig.Auth = []ssh.AuthMethod{ssh.KeyboardInteractive(func(_, _ string, questions []string, echo []bool) ([]string, error) {
		return []string{"interactive-secret"}, nil
	})}
	if client, err := ssh.Dial("tcp", listener.Addr().String(), &keyboardConfig); err == nil {
		client.Close()
		t.Fatal("keyboard-interactive authentication unexpectedly succeeded")
	}
	page, err := dataStore.Credentials(ctx, store.AttemptFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 2 {
		t.Fatalf("want two captured credentials, got %+v", page)
	}
	passwordPage, err := dataStore.Credentials(ctx, store.AttemptFilter{Password: "interactive-secret"})
	if err != nil {
		t.Fatal(err)
	}
	if passwordPage.Total != 1 {
		t.Fatalf("keyboard-interactive password was not recorded: %+v", passwordPage)
	}
}

func TestHostKeyPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys", "host_key")
	first, err := LoadOrCreateHostKey(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreateHostKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(first.PublicKey().Marshal()) != string(second.PublicKey().Marshal()) {
		t.Fatal("host key changed after reload")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("host key mode = %o", info.Mode().Perm())
	}
}
