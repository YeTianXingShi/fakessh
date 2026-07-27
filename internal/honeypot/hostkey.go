package honeypot

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

func LoadOrCreateHostKey(path string) (ssh.Signer, error) {
	contents, err := os.ReadFile(path)
	if err == nil {
		return ssh.ParsePrivateKey(contents)
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read host key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("create host key directory: %w", err)
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate host key: %w", err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("marshal host key: %w", err)
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, data, 0600); err != nil {
		return nil, fmt.Errorf("write host key: %w", err)
	}
	if err := os.Rename(temporary, path); err != nil {
		os.Remove(temporary)
		return nil, fmt.Errorf("install host key: %w", err)
	}
	return ssh.NewSignerFromKey(privateKey)
}
