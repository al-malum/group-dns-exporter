package pdns

import (
	"log/slog"
	"os"
)

func initLogger(logPath, logLevel string) {
	var level slog.Level
	var src bool
	switch logLevel {
	case "DEBUG":
		level = slog.LevelDebug
		src = true
	case "INFO":
		level = slog.LevelInfo
		src = false
	case "WARN":
		level = slog.LevelWarn
		src = false
	case "ERROR":
		level = slog.LevelError
		src = false
	}
	var logFile, _ = os.OpenFile(logPath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	var logger = slog.New(slog.NewJSONHandler(
		logFile,
		&slog.HandlerOptions{
			AddSource: src,
			Level:     level,
		}))
	slog.SetDefault(logger)
}
