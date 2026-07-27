package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"fakessh/internal/config"
	"fakessh/internal/honeypot"
	"fakessh/internal/store"
	webserver "fakessh/internal/web"
)

func main() {
	cfg := config.Load()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))
	slog.SetDefault(logger)
	if err := os.MkdirAll(cfg.DataDir, 0700); err != nil {
		logger.Error("create data directory", "error", err)
		os.Exit(1)
	}
	if err := os.MkdirAll(filepath.Dir(cfg.DBPath), 0700); err != nil {
		logger.Error("create database directory", "error", err)
		os.Exit(1)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	dataStore, err := store.Open(ctx, cfg.DBPath)
	if err != nil {
		logger.Error("open database", "error", err)
		os.Exit(1)
	}
	signer, err := honeypot.LoadOrCreateHostKey(cfg.SSHHostKeyPath)
	if err != nil {
		dataStore.Close()
		logger.Error("load host key", "error", err)
		os.Exit(1)
	}
	sshServer := honeypot.New(cfg.SSHListenAddr, dataStore, signer, logger)
	webServer, err := webserver.New(cfg.WebListenAddr, dataStore, logger)
	if err != nil {
		dataStore.Close()
		logger.Error("initialize web server", "error", err)
		os.Exit(1)
	}
	errorsChannel := make(chan error, 2)
	go func() { errorsChannel <- sshServer.ListenAndServe() }()
	go func() { errorsChannel <- webServer.ListenAndServe() }()
	select {
	case <-ctx.Done():
		logger.Info("shutdown requested")
	case err := <-errorsChannel:
		if err != nil {
			logger.Error("server stopped", "error", err)
		}
		cancel()
	}
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()
	if err := webServer.Shutdown(shutdownCtx); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("web shutdown", "error", err)
	}
	if err := sshServer.Shutdown(shutdownCtx); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("SSH shutdown", "error", err)
	}
	if err := dataStore.Close(); err != nil {
		logger.Error("close database", "error", err)
	}
}
