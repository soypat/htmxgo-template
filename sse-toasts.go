package main

import (
	"context"
	"errors"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
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
func (sv *Server) handleSSE() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		email := sv.auth.GetEmail(r)
		if email == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming not supported", http.StatusInternalServerError)
			return
		}

		ch := sv.toasts.Subscribe(email)
		defer sv.toasts.Unsubscribe(email, ch)
		ctx, cancel := context.WithTimeout(r.Context(), 24*time.Hour)
		defer cancel()
		for {
			select {
			case toast := <-ch:
				var lvlstr = "SUCCESS"
				if toast.Level != toastLevelSuccess {
					lvlstr = toast.Level.String()
				}
				fmt.Fprintf(w, "event: toast\ndata: <div class=\"toast toast-%s\" id=\"toast-%s\">%s</div>\n\n",
					html.EscapeString(lvlstr),
					html.EscapeString(toast.ID),
					html.EscapeString(toast.Message))
				flusher.Flush()
			case <-ctx.Done():
				slog.Warn("sse too long duration", slog.String("email", email), slog.String("err", ctx.Err().Error()))
				return
			}
		}
	}
}

// handleSendUserToast sends a toast notification to a specific user via SSE.
func (sv *Server) handleSendUserToast() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		adminEmail := sv.auth.GetEmail(r)

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
		toast.ID = uuid.New().String()[:8]
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
		toast.ID = uuid.New().String()[:8]
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
