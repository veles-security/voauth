// Package logger provides module-wide structured logging configuration.
package logger

import (
	"context"
	"log/slog"
	"sync"
)

// Logger is the module-wide structured logging contract. *slog.Logger
// implements Logger directly.
type Logger interface {
	Log(ctx context.Context, level slog.Level, msg string, args ...any)
}

var (
	loggerMutex sync.RWMutex
	logger      Logger = slog.Default()
)

// SetLogger replaces the logger used throughout the module. A nil logger
// restores slog.Default.
func SetLogger(replacement Logger) {
	if replacement == nil {
		replacement = slog.Default()
	}

	loggerMutex.Lock()
	logger = replacement
	loggerMutex.Unlock()
}

// GetLogger returns the logger currently used throughout the module.
func GetLogger() Logger {
	loggerMutex.RLock()
	defer loggerMutex.RUnlock()
	return logger
}
