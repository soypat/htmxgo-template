package main

import (
	"crypto/md5"
	"crypto/rand"
	"errors"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/soypat/uuid"
)

// handleSSE establishes a Server-Sent Events connection for real-time toast notifications.
//
// Subscription model: Clients subscribe by their authenticated email address. This means:
//   - All browser tabs for the same user receive the same toasts (useful for user-targeted
//     notifications like "your export is ready" or "job completed")
//   - Backend code can send toasts to specific users via sv.toasts.Send(email, toast)
//
// Alternative designs considered:
//   - Per-session subscription: Would require session IDs, toasts only appear in originating tab
//   - Per-connection subscription: Each SSE connection gets unique ID, most granular control
//
// The email-based approach was chosen because toast notifications in this app are user-level
// events (not request-specific), and showing them across all tabs improves UX.
func (sv *Server) handleSSE() RoleHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, rc RequestContext) {
		connID := sv.toasts.NewID().String()[:8]
		email := rc.User.Email
		mustClose := email == "" || rc.User.Role.Canon() < RoleExternal

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming not supported", http.StatusInternalServerError)
			return
		}
		defer flusher.Flush()
		if mustClose {
			w.Write([]byte(": connected\n\nevent:close\ndata: unauthorized\n\n"))
			return
			// Immediate heartbeat on connect - critical for fast stale connection detection
		} else if _, err := w.Write([]byte(": connected\n\n")); err != nil {
			slog.Debug("sse initial write failed", slog.String("conn", connID), slog.String("err", err.Error()))
			return
		}
		flusher.Flush()

		ch := sv.toasts.Subscribe(email)
		defer sv.toasts.Unsubscribe(email, ch)

		slog.Debug("sse connected", slog.String("conn", connID), slog.String("email", email))
		defer slog.Debug("sse disconnected", slog.String("conn", connID), slog.String("email", email))

		// Heartbeat detects dead connections by forcing periodic writes.
		//
		// Why this is necessary:
		// - SSE connections do NOT persist between page loads - browser closes them on navigation
		// - However, Go's HTTP server only detects client disconnect when a WRITE fails
		// - TCP writes go to kernel buffer and "succeed" even if client is gone
		// - Failure is only detected after TCP retransmit timeout (30+ seconds on Linux)
		// - These "zombie" handlers consume the browser's 6-connection limit, blocking page loads
		//
		// Solution: Send heartbeats frequently. If client is gone, write eventually fails.
		// We send one immediately on connect to detect stale connections ASAP.
		heartbeat := time.NewTicker(15 * time.Second)
		defer heartbeat.Stop()

		flusher.Flush()

		for {
			select {
			case toast := <-ch:
				var lvlstr = "SUCCESS"
				if toast.Level != toastLevelSuccess {
					lvlstr = toast.Level.String()
				}
				_, err := fmt.Fprintf(w, "event: toast\ndata: <div class=\"toast toast-%s\" id=\"toast-%s\">%s</div>\n\n",
					html.EscapeString(lvlstr),
					html.EscapeString(toast.ID),
					html.EscapeString(toast.Message))
				if err != nil {
					slog.Debug("sse write failed", slog.String("conn", connID), slog.String("err", err.Error()))
					return
				}
				flusher.Flush()

			case <-heartbeat.C:
				_, err := fmt.Fprintf(w, ": heartbeat\n\n")
				if err != nil {
					slog.Debug("sse heartbeat failed", slog.String("conn", connID), slog.String("err", err.Error()))
					return
				}
				flusher.Flush()

			case <-r.Context().Done():
				slog.Debug("sse context done", slog.String("conn", connID), slog.String("err", r.Context().Err().Error()))
				return
			}
		}
	}
}

// handleSendUserToast sends a toast notification to a specific user via SSE.
func (sv *Server) handleSendUserToast() RoleHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, rc RequestContext) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		adminEmail := rc.User.Email

		email := r.FormValue("email")
		message := r.FormValue("message")
		toastType := r.FormValue("type")

		if email == "" || message == "" {
			http.Error(w, "email and message required", http.StatusBadRequest)
			return
		}

		// Validate toast type
		var lvl slog.Level = slog.LevelInfo
		switch toastType {
		case "warn":
			lvl = slog.LevelWarn
		case "error":
			lvl = slog.LevelError
		case "debug":
			lvl = slog.LevelDebug
		case "success":
			lvl = toastLevelSuccess
		}

		err := sv.toasts.Send(email, Toast{
			Level:   lvl,
			Message: message,
		})
		if err == nil {
			sv.toasts.Send(adminEmail, Toast{
				Level:   toastLevelSuccess,
				Message: "Toast delivered succesfully to " + email,
			})
		} else {
			sv.toasts.Send(adminEmail, Toast{
				Level:   slog.LevelError,
				Message: err.Error(),
			})
		}
	}
}

const toastLevelSuccess = slog.LevelInfo - 1

// Toast represents a notification message sent via SSE.
type Toast struct {
	ID      string
	Level   slog.Level // "info", "success", "error", "warning"
	Message string
}

// ToastBroker manages SSE subscriptions for toast notifications.
type ToastBroker struct {
	mu      sync.RWMutex
	clients map[string]map[chan Toast]struct{} // email -> set of channels
	uuidGen uuid.Generator
}

func (tb *ToastBroker) Init() error {
	return tb.uuidGen.Init(uuid.GeneratorConfig{
		RandSource: rand.Reader,
		Version:    4,
		Hash:       md5.New(),
	})
}

func (tb *ToastBroker) NewID() uuid.UUID {
	id, err := tb.uuidGen.NewRandom()
	if err != nil {
		slog.Error("CRITICAL:ToastNewID", slog.String("err", err.Error()))
		id, err = tb.uuidGen.NewRandom()
		if err != nil {
			panic("double newrandom fail") // Should not happen with system random source.
		}
	}
	return id
}

func (tb *ToastBroker) Subscribe(email string) chan Toast {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	if tb.clients == nil {
		tb.clients = make(map[string]map[chan Toast]struct{})
	}
	if tb.clients[email] == nil {
		tb.clients[email] = make(map[chan Toast]struct{})
	}
	ch := make(chan Toast, 10)
	tb.clients[email][ch] = struct{}{}
	return ch
}

func (tb *ToastBroker) Unsubscribe(email string, ch chan Toast) {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	if tb.clients[email] != nil {
		delete(tb.clients[email], ch)
		close(ch)
	}
}

func (tb *ToastBroker) Send(email string, toast Toast) (err error) {
	tb.mu.RLock()
	defer tb.mu.RUnlock()
	if toast.ID == "" {
		toast.ID = tb.NewID().String()[:8]
	}
	for ch := range tb.clients[email] {
		select {
		case ch <- toast:
		default:
			err = errors.New("one or more toasts not sent due to full channel")
		}
	}
	return err
}

// Broadcast sends a toast to all connected clients.
func (tb *ToastBroker) Broadcast(toast Toast) (err error) {
	tb.mu.RLock()
	defer tb.mu.RUnlock()
	if toast.ID == "" {
		toast.ID = tb.NewID().String()[:8]
	}
	for _, clients := range tb.clients {
		for ch := range clients {
			select {
			case ch <- toast:
			default:
				err = errors.New("one or more toasts not sent due to full channel")
			}
		}
	}
	return err
}
