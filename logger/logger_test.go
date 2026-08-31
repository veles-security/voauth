package logger

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

type recordingLogger struct {
	message string
}

func (l *recordingLogger) Log(_ context.Context, _ slog.Level, message string, _ ...any) {
	l.message = message
}

func TestSetLogger(t *testing.T) {
	original := GetLogger()
	t.Cleanup(func() { SetLogger(original) })

	tests := []struct {
		name   string
		logger Logger
		assert func(*testing.T)
	}{
		{
			name:   "custom logger",
			logger: &recordingLogger{},
			assert: func(t *testing.T) {
				configured := GetLogger().(*recordingLogger)
				configured.Log(context.Background(), slog.LevelInfo, "configured")
				if configured.message != "configured" {
					t.Fatalf("custom logger message = %q, want %q", configured.message, "configured")
				}
			},
		},
		{
			name: "configured slog logger",
			assert: func(t *testing.T) {
				var output bytes.Buffer
				SetLogger(slog.New(slog.NewTextHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug})))
				GetLogger().Log(context.Background(), slog.LevelDebug, "configured slog")
				if !strings.Contains(output.String(), "configured slog") {
					t.Fatalf("slog output = %q, want configured message", output.String())
				}
			},
		},
		{
			name:   "nil restores default",
			logger: nil,
			assert: func(t *testing.T) {
				if actual := GetLogger(); actual != slog.Default() {
					t.Fatalf("logger = %T, want slog.Default", actual)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			SetLogger(test.logger)
			test.assert(t)
		})
	}
}

func TestGetLogger(t *testing.T) {
	original := GetLogger()
	t.Cleanup(func() { SetLogger(original) })
	configured := &recordingLogger{}
	SetLogger(configured)

	if actual := GetLogger(); actual != configured {
		t.Fatalf("GetLogger() = %T, want configured logger", actual)
	}
}
