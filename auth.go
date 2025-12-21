package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	sessionCookie = "gsan_session"
	stateCookie   = "gsan_oauth_state"
)

type Role int

func (enum Role) MarshalJSON() ([]byte, error) { return []byte(strconv.Quote(enum.String())), nil }

func (enum *Role) UnmarshalJSON(b []byte) error {
	return enumUnmarshalJSON(enum, b, roleEnd)
}

func (role Role) IsValid() bool { return role > roleUndefined && role < roleEnd }

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

type RoleHandlerFunc func(w http.ResponseWriter, r *http.Request, rc RequestContext)

type Authenticator interface {
	GetEmail(r *http.Request) string
	HandleLogin(w http.ResponseWriter, r *http.Request)
	HandleCallback(w http.ResponseWriter, r *http.Request)
	HandleLogout(w http.ResponseWriter, r *http.Request)
}

type Auth struct {
	oauth    *oauth2.Config
	sessions map[string]*AuthSession // token -> session
}

type AuthSession struct {
	Email     string
	ExpiresAt time.Time
}

func (auth *Auth) Config(cfg Flags) error {
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return errors.New("empty client secret/id for OAuth")
	}
	_, err := url.Parse(cfg.RedirectURL)
	if err != nil {
		return err
	}
	*auth = Auth{
		oauth: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Scopes:       []string{"email"},
			Endpoint:     google.Endpoint,
		},
		sessions: make(map[string]*AuthSession),
	}
	return nil
}

// GetEmail returns the email from the session, or empty if not logged in.
func (a *Auth) GetEmail(r *http.Request) string {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		return ""
	}

	sess, ok := a.sessions[cookie.Value]
	if !ok || time.Now().After(sess.ExpiresAt) {
		return ""
	}
	return sess.Email
}

// HandleLogin redirects to Google OAuth.
func (a *Auth) HandleLogin(w http.ResponseWriter, r *http.Request) {
	sessionToken := rand32String()

	http.SetCookie(w, &http.Cookie{
		Name:     stateCookie,
		Value:    sessionToken,
		Path:     "/",
		MaxAge:   300,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	url := a.oauth.AuthCodeURL(sessionToken)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// HandleCallback handles the OAuth callback.
func (a *Auth) HandleCallback(w http.ResponseWriter, r *http.Request) {
	// Verify state
	stateCookie, err := r.Cookie(stateCookie)
	if err != nil || stateCookie.Value != r.URL.Query().Get("state") {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}

	// Exchange code for token
	code := r.URL.Query().Get("code")
	token, err := a.oauth.Exchange(context.Background(), code)
	if err != nil {
		http.Error(w, "failed to exchange token", http.StatusInternalServerError)
		return
	}

	// Get user info
	client := a.oauth.Client(context.Background(), token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		http.Error(w, "failed to get user info", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	var userInfo struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		http.Error(w, "failed to decode user info", http.StatusInternalServerError)
		return
	}

	// Create session
	sessionToken := rand32String()
	a.sessions[sessionToken] = &AuthSession{
		Email:     userInfo.Email,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    sessionToken,
		Path:     "/",
		MaxAge:   86400,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// HandleLogout clears the session.
func (a *Auth) HandleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(sessionCookie)
	if err == nil {
		delete(a.sessions, cookie.Value)
	}

	http.SetCookie(w, &http.Cookie{
		Name:   sessionCookie,
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func rand32String() string {
	var b [32]byte
	rand.Read(b[:])
	return base64.URLEncoding.EncodeToString(b[:])
}

// DevAuth is a simple auth for development that auto-logs in with a fixed email.
type DevAuth struct {
	Email string
}

func (d *DevAuth) GetEmail(r *http.Request) string {
	return d.Email
}

func (d *DevAuth) HandleLogin(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (d *DevAuth) HandleCallback(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (d *DevAuth) HandleLogout(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func enumUnmarshalJSON[T interface {
	~int | ~uint | ~uint8 | ~int64 | ~uint64 // common enum types.
	String() string
}](ptr *T, b []byte, maxEnumLim T) error {
	strq := string(b)
	bs, err := strconv.Unquote(strq)
	if err != nil {
		return err
	}
	if len(bs) == 0 {
		return errors.New("cannot unmarshal empty enum string")
	}
	var v T = 1
	for v = 1; v < maxEnumLim; v++ {
		str := v.String()
		if str == bs {
			*ptr = v
			return nil
		}
	}
	return errors.New("cannot unmarshal JSON to enum: " + strq)
}
