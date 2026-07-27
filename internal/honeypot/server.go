package honeypot

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"fakessh/internal/store"
	"golang.org/x/crypto/ssh"
)

var errAuthenticationFailed = errors.New("authentication failed")

type Server struct {
	addr        string
	store       *store.Store
	config      *ssh.ServerConfig
	logger      *slog.Logger
	mu          sync.Mutex
	listener    net.Listener
	connections map[net.Conn]struct{}
	wg          sync.WaitGroup
}

func New(addr string, dataStore *store.Store, signer ssh.Signer, logger *slog.Logger) *Server {
	s := &Server{addr: addr, store: dataStore, logger: logger, connections: make(map[net.Conn]struct{})}
	s.config = &ssh.ServerConfig{
		ServerVersion:               "SSH-2.0-OpenSSH_9.6",
		MaxAuthTries:                6,
		PasswordCallback:            s.password,
		KeyboardInteractiveCallback: s.keyboardInteractive,
	}
	s.config.AddHostKey(signer)
	return s
}

func (s *Server) ListenAndServe() error {
	listener, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	return s.Serve(listener)
}

func (s *Server) Serve(listener net.Listener) error {
	s.mu.Lock()
	s.listener = listener
	s.mu.Unlock()
	s.logger.Info("SSH honeypot listening", "address", listener.Addr())
	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		s.track(conn, true)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.track(conn, false)
			defer conn.Close()
			if _, _, _, err := ssh.NewServerConn(conn, s.config); err != nil {
				s.logger.Debug("SSH connection ended", "remote", conn.RemoteAddr(), "error", err)
			}
		}()
	}
}

func (s *Server) password(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	s.record(meta, password, "password")
	return nil, errAuthenticationFailed
}

func (s *Server) keyboardInteractive(meta ssh.ConnMetadata, challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
	answers, err := challenge("", "", []string{"Password: "}, []bool{false})
	if err == nil {
		password := []byte{}
		if len(answers) > 0 {
			password = []byte(answers[0])
		}
		s.record(meta, password, "keyboard-interactive")
	}
	return nil, errAuthenticationFailed
}

func (s *Server) record(meta ssh.ConnMetadata, password []byte, method string) {
	ip, port := remote(meta.RemoteAddr())
	attempt := store.Attempt{Username: []byte(meta.User()), Password: append([]byte(nil), password...), Method: method, RemoteIP: ip, RemotePort: port, ClientVersion: append([]byte(nil), meta.ClientVersion()...), At: time.Now().UTC()}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.store.Record(ctx, attempt); err != nil {
		s.logger.Error("failed to record authentication", "remote_ip", ip, "method", method, "error", err)
	}
}

func remote(addr net.Addr) (string, int) {
	if tcp, ok := addr.(*net.TCPAddr); ok {
		return tcp.IP.String(), tcp.Port
	}
	host, portText, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String(), 0
	}
	var port int
	fmt.Sscanf(portText, "%d", &port)
	return host, port
}

func (s *Server) track(conn net.Conn, add bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if add {
		s.connections[conn] = struct{}{}
	} else {
		delete(s.connections, conn)
	}
}

func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	if s.listener != nil {
		_ = s.listener.Close()
	}
	for conn := range s.connections {
		_ = conn.Close()
	}
	s.mu.Unlock()
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
