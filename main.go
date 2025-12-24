//go:generate go tool templ generate .
//go:generate go tool templ fmt .
//go:generate go tool stringer -type Role,Page -linecomment -output stringers.go
package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"time"
)

type Flags struct {
	DevModeRole string

	DisableSSE bool
	LogLevel   int
	Addr       string

	// OAuth client ID.
	ClientID string
	// OAuth Client secret. Provided by provider.
	ClientSecret string
	// Redirect URL used by OAuth.
	RedirectURL string
}

const (
	envSecret = "OASECRET"
	envID     = "OAID"
)

func run() error {
	var flags Flags
	flag.StringVar(&flags.DevModeRole, "dev", "", "Developer mode role from available: ['external', 'user', 'mod', 'admin', 'owner'].")
	flag.BoolVar(&flags.DisableSSE, "disable-sse", false, "Disable SSE events (toasts).")
	flag.StringVar(&flags.Addr, "http", ":8080", "Address on which to host HTTP server.")
	flag.StringVar(&flags.ClientSecret, "oauth-secret", "", "OAuth client secret. DO NOT SET FLAG. Set via Environment "+envSecret)
	flag.StringVar(&flags.ClientID, "oauth-cid", os.Getenv(envID), "OAuth client ID.")
	flag.IntVar(&flags.LogLevel, "log", int(slog.LevelDebug), fmt.Sprintf("Logging level. DEBUG=%d INFO=%d WARN=%d ERROR=%d", slog.LevelDebug, slog.LevelInfo, slog.LevelWarn, slog.LevelError))
	flag.StringVar(&flags.RedirectURL, "oauth-redirect", "http://localhost:8080/auth/callback", "Redirect URL for OAuth at /auth/callback endpoint. For local development is http://localhost:8080/auth/callback")
	flag.Parse()
	if flags.ClientSecret != "" {
		return errors.New("client secret flag set only for documentation purposes. Set environment: " + envSecret)
	}
	flags.ClientSecret = os.Getenv(envSecret)
	if flags.DevModeRole == "" && flags.ClientSecret == "" {
		return errors.New("set OAuth client secret environment " + envSecret)
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.Level(flags.LogLevel),
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == "time" {
				a.Value = slog.StringValue(a.Value.Time().Format("2006/01/02-15:04:05"))
			}
			return a
		},
	})))

	var sv Server
	err := sv.Init(flags)
	if err != nil {
		return fmt.Errorf("initializing server: %w", err)
	}
	err = sv.Run()
	if err != nil {
		log.Println("server exited with error:", err)
	}
	return errors.New("unexpected end to program")
}

func main() {
	start := time.Now()
	err := run()
	elapsed := time.Since(start)
	if err != nil {
		log.Fatalln(elapsed, "failed:", err)
	}
	fmt.Println(elapsed, "finished")
}
