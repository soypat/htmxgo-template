package main

import (
	"context"
	"errors"
	"fmt"
	"html"
	"log"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/a-h/templ"
	"github.com/google/uuid"
)

type RenderContext struct {
	User User
	Page Page
}

type Page uint8

const (
	pageUndefined = iota
	pageLanding
	pageUsers
)

type Server struct {
	// Inspired by Mat Ryer's post on writing HTTP services:
	// https://pace.dev/blog/2018/05/09/how-I-write-http-services-after-eight-years.html
	router *http.ServeMux
	addr   string
	// table stores data
	db     Store
	auth   Authenticator
	toasts ToastBroker
}

func (sv *Server) Run() error {
	return http.ListenAndServe(sv.addr, sv.router)
}

func (sv *Server) Init(flags Flags) (err error) {
	slog.Debug("Server.Init")
	if sv.router != nil {
		return errors.New("Server already initialized")
	}
	err = sv.db.Open("db.bbolt")
	if err != nil {
		return err
	}
	sv.addr = flags.Addr
	if !flags.DevMode {
		var auth Auth
		err = auth.Config(flags)
		sv.auth = &auth
	} else {
		const devEmail = "dev@example.com"
		sv.db.UserCreate(User{Email: devEmail, ID: uuid.Max, Provider: "nowhere"})
		sv.auth = &DevAuth{Email: devEmail}
	}
	if err != nil {
		return err
	}

	sv.router = http.NewServeMux()
	sv.HandleFunc("/", sv.handleLanding())
	sv.HandleFunc("/users", sv.RequireAuth(sv.handleUsers()))
	sv.HandleFunc("/users/send-toast", sv.RequireAuth(sv.handleSendUserToast()))
	if flags.DisableSSE {
		sv.HandleFunc("/sse", func(w http.ResponseWriter, r *http.Request) { http.Error(w, "sse disabled", 401) })
	} else {
		sv.HandleFunc("/sse", sv.handleSSE())
	}

	return nil
}

// MIDDLEWARE.

// RequireAuth is middleware that redirects to login if not authenticated.
func (sv *Server) RequireAuth(next http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if sv.auth.GetEmail(r) == "" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	}
}

func (sv *Server) HandleFunc(parentPattern string, handler func(http.ResponseWriter, *http.Request)) {
	sv.router.HandleFunc(parentPattern, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("No-Log") != "true" && slog.Default().Enabled(context.Background(), slog.LevelDebug) {
			slog.Debug("Server:handle", slog.String("url", r.URL.String()), slog.String("handler", parentPattern), slog.String("addr", r.RemoteAddr))
		}
		handler(w, r)
	})
}

func (sv *Server) RenderContext(w http.ResponseWriter, r *http.Request) (rc RenderContext) {
	email := sv.auth.GetEmail(r)
	err := sv.db.UserByEmail(&rc.User, email)
	if err != nil {
		rc.User = User{}
		return rc
	}
	switch r.RequestURI {
	case "/":
		rc.Page = pageLanding
	case "/users":
		rc.Page = pageUsers
	}
	return rc
}

func (sv *Server) handleLanding() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sv.servePage(w, r, landingPage(sv.RenderContext(w, r)))
	}
}

func (sv *Server) handleUsers() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var users []User
		err := sv.db.Users(func(dst *User) error {
			users = append(users, *dst)
			return nil
		})
		if err != nil {
			sv.error(w, err.Error(), 500)
			return
		}
		sv.servePage(w, r, usersPage(users))
	}
}

// servePage uses the `page` function and serves an entire page to the http response writer with `component` as the core page content.
func (sv *Server) servePage(w http.ResponseWriter, r *http.Request, component templ.Component) {
	rc := sv.RenderContext(w, r)
	sv.serveComponent(w, r, page(component, rc))
}

// serveComponent is the lowest level way of serving a component using Templ. Can serve whole pages to individual HTML elements for partial page updates.
func (sv *Server) serveComponent(w http.ResponseWriter, r *http.Request, c templ.Component) {
	handler := templ.Handler(c)
	handler.ServeHTTP(w, r)
	slog.Debug("serveComponent:done", slog.String("req", r.URL.String()))
}

func (sv *Server) error(w http.ResponseWriter, errstr string, code int) {
	slog.Error(errstr, slog.String("status", http.StatusText(code)))
	log.Println("server error ", code, errstr)
	if code == http.StatusBadRequest || code == http.StatusInternalServerError || code == http.StatusUnprocessableEntity {
		// https://stackoverflow.com/questions/69364278/handle-errors-with-htmx
		w.Header().Add("HX-Retarget", "#errors")
		w.Header().Add("HX-Reswap", "innerHTML")
	}
	w.WriteHeader(code)
	w.Write([]byte(`<article class="pico-color-pink-400">`))
	w.Write([]byte(http.StatusText(code)))
	w.Write([]byte(": "))
	w.Write([]byte(html.EscapeString(errstr)))
	w.Write([]byte(`</article>`))
}

func fmtSeconds(s float64) (fmted string) {
	const (
		daysPerYear    = 365.24
		secondsPerDay  = 60 * 60 * 24 // [s/day]
		secondsPerYear = secondsPerDay * daysPerYear
	)
	switch {
	case s < 1:
		fmted = time.Duration(s * float64(time.Second)).String()
	case s < 3600:
		fmted = time.Duration(s * float64(time.Second)).Round(time.Second).String()
	case s < 3600*24:
		fmted = time.Duration(s * float64(time.Second)).Round(time.Minute).String()
	case s < secondsPerYear:
		fmted = fmt.Sprintf("%.1f days", s/(3600*24))
	default:
		fmted = fmt.Sprintf("%.1f years", s/secondsPerYear)
	}
	// Trim 0 seconds/minutes for [time.Duration] formatted data.
	if strings.HasSuffix(fmted, "m0s") {
		fmted = fmted[:len(fmted)-2]
	}
	if strings.HasSuffix(fmted, "h0m") {
		fmted = fmted[:len(fmted)-2]
	}
	return fmted
}
