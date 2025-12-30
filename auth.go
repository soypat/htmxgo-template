package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	sessionCookie = "gsan_session"
	stateCookie   = "gsan_oauth_state"
)

type Role int

const (
	roleUndefined Role = iota // undefined
	RoleExternal              // external
	RoleUser                  // user
	RoleModerator             // mod
	RoleAdmin                 // admin

	// RoleOwner is the maximum role. Keep new roles under this unless adding something like "god-emperor"
	// On changing this max value make sure to change enum marshalling call.
	RoleOwner // owner
	roleEnd   // not-a-real-role
)

func (enum Role) MarshalJSON() ([]byte, error) { return []byte(strconv.Quote(enum.String())), nil }

func (enum *Role) UnmarshalJSON(b []byte) error {
	return enumUnmarshalJSON(enum, b, roleEnd)
}

func (enum *Role) UnmarshalText(b []byte) error {
	s := string(b)
	for v := Role(0); v < roleEnd; v++ {
		if v.String() == s && v.IsValid() {
			*enum = v
			return nil
		}
	}
	return errors.New("invalid role: " + s)
}

func (role Role) IsValid() bool { return role > roleUndefined && role < roleEnd }

// Canon sanitizes role and ensures if invalid is set to zero and fails all clearance checks.
func (role Role) Canon() Role {
	if role.IsValid() {
		return role
	}
	return 0
}

// Level returns a slog.Level for badge coloring. Higher role = higher level.
func (role Role) Level() (lvl slog.Level) {
	switch role {
	case RoleOwner, RoleAdmin:
		lvl = slog.LevelError
	case RoleModerator:
		lvl = slog.LevelWarn
	case RoleUser:
		lvl = slog.LevelInfo
	case RoleExternal:
		lvl = LevelSuccess
	default:
		lvl = slog.LevelDebug
	}
	return lvl
}

type RoleHandlerFunc func(w http.ResponseWriter, r *http.Request, rc RequestContext)

type Authenticator interface {
	GetSession(r *http.Request) (AuthSession, bool)
	HandleLogin(w http.ResponseWriter, r *http.Request)
	HandleCallback(w http.ResponseWriter, r *http.Request) (AuthSession, bool)
	HandleLogout(w http.ResponseWriter, r *http.Request)
}

type Auth struct {
	oauth    *oauth2.Config
	sessions map[string]*AuthSession // token -> session
}

var _ Authenticator = (*Auth)(nil) // compile time guarantee of interface implementation.

type AuthSession struct {
	Email        string
	CSRFToken    string
	Provider     string
	Picture      string
	VerifiedMail bool
	ExpiresAt    time.Time
}

func (auth *Auth) Config(cfg Flags, redirectURL string) error {
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return errors.New("empty client secret/id for OAuth")
	}
	_, err := url.Parse(redirectURL)
	if err != nil {
		return err
	}
	*auth = Auth{
		oauth: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  redirectURL,
			Scopes:       []string{"email"},
			Endpoint:     google.Endpoint,
		},
		sessions: make(map[string]*AuthSession),
	}
	return nil
}

// GetEmail returns the email from the session, or empty if not logged in.
func (a *Auth) GetSession(r *http.Request) (AuthSession, bool) {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil || cookie.Value == "" {
		return AuthSession{}, false
	}

	sess, ok := a.sessions[cookie.Value]
	if !ok || time.Now().After(sess.ExpiresAt) {
		return AuthSession{}, false
	}
	return *sess, true
}

// HandleLogin redirects to Google OAuth.
func (a *Auth) HandleLogin(w http.ResponseWriter, r *http.Request) {
	state := rand32String()
	http.SetCookie(w, &http.Cookie{
		Name:     stateCookie,
		Value:    state,
		Path:     "/",
		MaxAge:   300,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	slog.Info("oauth-login", slog.String("state", state))
	url := a.oauth.AuthCodeURL(state)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// HandleCallback handles the OAuth callback.
func (a *Auth) HandleCallback(w http.ResponseWriter, r *http.Request) (AuthSession, bool) {
	// Verify state
	stateCookie, err := r.Cookie(stateCookie)
	if err != nil || stateCookie.Value != r.URL.Query().Get("state") {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return AuthSession{}, false
	}

	// Exchange code for token
	code := r.URL.Query().Get("code")
	token, err := a.oauth.Exchange(context.Background(), code)
	if err != nil {
		http.Error(w, "failed to exchange token", http.StatusInternalServerError)
		return AuthSession{}, false
	}

	// Get user info
	client := a.oauth.Client(context.Background(), token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		http.Error(w, "failed to get user info", http.StatusInternalServerError)
		return AuthSession{}, false
	}
	defer resp.Body.Close()

	var userInfo struct {
		Email         string `json:"email"`
		VerifiedEmail bool   `json:"verified_email"`
		Picture       string `json:"picture"`
	}
	data, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(data, &userInfo); err != nil {
		http.Error(w, "failed to decode user info", http.StatusInternalServerError)
		return AuthSession{}, false
	}

	// Create session
	sessionToken := rand32String()
	sess := &AuthSession{
		Email:        userInfo.Email,
		Provider:     "google",
		CSRFToken:    rand32String(),
		Picture:      userInfo.Picture,
		VerifiedMail: userInfo.VerifiedEmail,
		ExpiresAt:    time.Now().Add(24 * time.Hour),
	}
	a.sessions[sessionToken] = sess
	slog.Info("oauth-login-callback", slog.String("email", userInfo.Email), slog.String("provider", sess.Provider), slog.String("state", stateCookie.Value), slog.String("token", sessionToken))

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    sessionToken,
		Path:     "/",
		MaxAge:   86400,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(w, r, "/", http.StatusSeeOther)
	return *sess, true
}

// HandleLogout clears the session.
func (a *Auth) HandleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(sessionCookie)
	sess, ok := a.GetSession(r)
	if !ok {
		slog.Warn("not-logged-in-for-logout")
		return
	}
	if err == nil {
		delete(a.sessions, cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:   sessionCookie,
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	slog.Info("oauth-logout", slog.String("email", sess.Email), slog.String("token", cookie.Value))
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func rand32String() string {
	var b [32]byte
	rand.Read(b[:])
	return base64.URLEncoding.EncodeToString(b[:])
}

// DevAuth is a simple auth for development that auto-logs in with a fixed email.
type DevAuth struct {
	Email     string
	csrfOnce  sync.Once
	csrfToken string
	expires   time.Time
}

var _ Authenticator = (*DevAuth)(nil) // compile time guarantee of interface implementation.

func (d *DevAuth) GetSession(r *http.Request) (AuthSession, bool) {
	d.csrfOnce.Do(func() {
		d.csrfToken = rand32String()
		d.expires = time.Now().Add(time.Hour * 200)
	})
	return AuthSession{
		Email:     d.Email,
		CSRFToken: d.csrfToken,
		Provider:  "nowhere",
		ExpiresAt: d.expires,
	}, true
}

func (d *DevAuth) HandleLogin(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (d *DevAuth) HandleCallback(w http.ResponseWriter, r *http.Request) (AuthSession, bool) {
	http.Redirect(w, r, "/", http.StatusSeeOther)
	return d.GetSession(r)
}

func (d *DevAuth) HandleLogout(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func enumUnmarshalJSON[T interface {
	~int | ~uint | ~uint8 | ~int64 | ~uint64 // common enum types.
	String() string
	IsValid() bool
}](ptr *T, b []byte, maxEnumLim T) error {
	strq := string(b)
	bs, err := strconv.Unquote(strq)
	if err != nil {
		return err
	}
	if len(bs) == 0 {
		return errors.New("cannot unmarshal empty enum string")
	}
	var v T
	for v = 0; v < maxEnumLim; v++ {
		str := v.String()
		if str == bs {
			if !v.IsValid() {
				return errors.New("invalid enum value: " + strq)
			}
			*ptr = v
			return nil
		}
	}
	return errors.New("cannot unmarshal JSON to enum: " + strq)
}
