package config

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	SSHListenAddr  string
	WebListenAddr  string
	DataDir        string
	DBPath         string
	SSHHostKeyPath string
	LogLevel       slog.Level
}

func Load() Config {
	dataDir := getenv("DATA_DIR", "/data")
	return Config{
		SSHListenAddr:  getenv("SSH_LISTEN_ADDR", ":2222"),
		WebListenAddr:  getenv("WEB_LISTEN_ADDR", ":8080"),
		DataDir:        dataDir,
		DBPath:         getenv("DB_PATH", filepath.Join(dataDir, "fakessh.db")),
		SSHHostKeyPath: getenv("SSH_HOST_KEY_PATH", filepath.Join(dataDir, "ssh_host_ed25519_key")),
		LogLevel:       logLevel(getenv("LOG_LEVEL", "info")),
	}
}

func getenv(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func logLevel(value string) slog.Level {
	switch strings.ToLower(value) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
