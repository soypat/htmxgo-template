package main

import (
	"context"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/a-h/templ"
	"github.com/google/uuid"
)

// Stores generic information about the request that is commonly used in
// frontend rendering or within API endpoint logic.
type RequestContext struct {
	User            User
	Page            Page
	ActiveWorkspace *Workspace
	WorkspaceRole   Role
	CSRFToken       string
	Now             time.Time
}

// Page state. Used to highlight current page.
type Page uint8

const (
	pageUndefined  Page = iota // undefined
	pageLanding                // landing
	pageUsers                  // users
	pageWorkspaces             // workspaces
	pageDocuments              // documents
	pageMembers                // members
)

const activeWorkspaceCookie = "active_workspace"

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
	page := sv.addr
	if page[0] == ':' {
		page = "localhost" + page
	}
	page = "http://" + page
	slog.Info("listen-serve", slog.String("addr", page))
	return http.ListenAndServe(sv.addr, sv.router)
}

func (sv *Server) Init(flags Flags) (err error) {
	slog.Debug("Server.Init")
	if sv.router != nil {
		return errors.New("Server already initialized")
	} else if len(flags.Addr) == 0 {
		return errors.New("empty address")
	}

	err = sv.db.Open("db.bbolt")
	if err != nil {
		return err
	}
	sv.addr = flags.Addr
	var devrole Role
	if flags.DevModeRole != "" {
		err = devrole.UnmarshalJSON([]byte("\"" + flags.DevModeRole + "\""))
		if err != nil {
			return err
		}
	}
	if devrole.IsValid() {
		const devEmail = "dev@example.com"
		usr := User{Email: devEmail, ID: uuid.Max, Provider: "nowhere", Role: devrole}
		err = sv.db.UserCreate(usr)
		if err != nil {
			// If user exists then get user and renew role.
			err = sv.db.UserByEmail(&usr, devEmail)
			if err != nil {
				return err
			}
			usr.Role = devrole
			err = sv.db.UserUpdate(usr)
			if err != nil {
				return err
			}
		}
		sv.auth = &DevAuth{Email: devEmail}
		slog.Warn("developer-mode")
	} else {
		var auth Auth
		err = auth.Config(flags)
		sv.auth = &auth
		slog.Warn("PRODUCTION-MODE")
	}
	if err != nil {
		return err
	}

	sv.router = http.NewServeMux()
	sv.HandleFuncNoAuth("/", sv.handleLanding())
	sv.HandleFuncNoAuth("/login", sv.auth.HandleLogin)
	sv.HandleFuncNoAuth("/auth/callback", sv.auth.HandleCallback)
	sv.HandleFuncNoAuth("/logout", sv.auth.HandleLogout)
	sv.HandleFuncNoWorkspace(RoleAdmin, "GET /users", sv.handleUsers())
	sv.HandleFuncNoWorkspace(RoleAdmin, "POST /users/send-toast", sv.handleSendUserToast())

	// Workspace management (no active workspace required).
	sv.HandleFuncNoWorkspace(RoleUser, "GET /workspaces", sv.handleWorkspaces())
	sv.HandleFuncNoWorkspace(RoleUser, "POST /workspaces", sv.handleCreateWorkspace())
	sv.HandleFuncNoWorkspace(RoleUser, "POST /workspaces/{id}/activate", sv.handleActivateWorkspace())
	sv.HandleFuncNoWorkspace(RoleAdmin, "DELETE /workspaces/{id}", sv.handleDeleteWorkspace())

	// Document routes (active workspace required).
	sv.HandleFunc(RoleUser, "GET /documents", sv.handleDocuments())
	sv.HandleFunc(RoleUser, "POST /documents", sv.handleCreateDocument())
	sv.HandleFunc(RoleUser, "GET /documents/{id}", sv.handleDocumentView())
	sv.HandleFunc(RoleUser, "POST /documents/{id}/name", sv.handleUpdateDocumentName())

	// Member management routes (active workspace required).
	sv.HandleFunc(RoleExternal, "GET /members", sv.handleMembers())
	sv.HandleFunc(RoleModerator, "POST /members", sv.handleAddMember())
	sv.HandleFunc(RoleAdmin, "DELETE /members/{id}", sv.handleRemoveMember())
	sv.HandleFunc(RoleAdmin, "POST /members/{id}/role", sv.handleChangeMemberRole())
	sv.HandleFunc(RoleOwner, "POST /workspaces/transfer-owner", sv.handleTransferOwnership())

	if flags.DisableSSE {
		sv.HandleFuncNoWorkspace(RoleUser, "/sse", func(w http.ResponseWriter, r *http.Request, _ RequestContext) { http.Error(w, "sse disabled", 401) })
	} else {
		sv.HandleFuncNoWorkspace(RoleUser, "/sse", sv.handleSSE())
	}

	return nil
}

// MIDDLEWARE.

// HandleFunc registers a handler that requires authentication, role clearance, AND an active workspace.
// Use this for routes that operate within the context of a workspace (e.g., /documents).
func (sv *Server) HandleFunc(requiredClearance Role, parentPattern string, handler RoleHandlerFunc) {
	sv.router.HandleFunc(parentPattern, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("No-Log") != "true" && slog.Default().Enabled(context.Background(), slog.LevelDebug) {
			slog.Debug("Server:handle", slog.String("url", r.URL.String()), slog.String("handler", parentPattern), slog.String("addr", r.RemoteAddr))
		}
		if sv.auth.GetEmail(r) == "" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		rc := sv.RenderContext(w, r)
		if !rc.User.HasClearance(requiredClearance) {
			http.NotFound(w, r)
			return
		}
		if rc.ActiveWorkspace == nil {
			http.Redirect(w, r, "/workspaces", http.StatusSeeOther)
			return
		}
		// Validate CSRF for mutating requests.
		if r.Method == http.MethodPost || r.Method == http.MethodDelete || r.Method == http.MethodPut || r.Method == http.MethodPatch {
			if !sv.validateCSRF(r, rc) {
				sv.error(w, "invalid CSRF token", http.StatusForbidden)
				return
			}
		}
		handler(w, r, rc)
	})
}

// HandleFuncNoWorkspace registers a handler that requires authentication and role clearance,
// but does NOT require an active workspace. Use this for workspace management routes.
func (sv *Server) HandleFuncNoWorkspace(requiredClearance Role, parentPattern string, handler RoleHandlerFunc) {
	sv.router.HandleFunc(parentPattern, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("No-Log") != "true" && slog.Default().Enabled(context.Background(), slog.LevelDebug) {
			slog.Debug("Server:handle", slog.String("url", r.URL.String()), slog.String("handler", parentPattern), slog.String("addr", r.RemoteAddr))
		}
		if sv.auth.GetEmail(r) == "" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		rc := sv.RenderContext(w, r)
		if !rc.User.HasClearance(requiredClearance) {
			http.NotFound(w, r)
			return
		}
		// Validate CSRF for mutating requests.
		if r.Method == http.MethodPost || r.Method == http.MethodDelete || r.Method == http.MethodPut || r.Method == http.MethodPatch {
			if !sv.validateCSRF(r, rc) {
				sv.error(w, "invalid CSRF token", http.StatusForbidden)
				return
			}
		}
		handler(w, r, rc)
	})
}

func (sv *Server) HandleFuncNoAuth(parentPattern string, handler func(http.ResponseWriter, *http.Request)) {
	sv.router.HandleFunc(parentPattern, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("No-Log") != "true" && slog.Default().Enabled(context.Background(), slog.LevelDebug) {
			slog.Debug("Server:handle", slog.String("url", r.URL.String()), slog.String("handler", parentPattern), slog.String("addr", r.RemoteAddr))
		}
		handler(w, r)
	})
}

func (sv *Server) RenderContext(w http.ResponseWriter, r *http.Request) (rc RequestContext) {
	err := sv.db.UserByEmail(&rc.User, sv.auth.GetEmail(r))
	if err != nil {
		rc.User = User{}
	}
	// Load active workspace from cookie if set.
	if wsID := sv.getActiveWorkspaceID(r); wsID != uuid.Nil {
		var ws Workspace
		if err := sv.db.WorkspaceByUUID(&ws, wsID); err == nil {
			// Verify user is still a member of this workspace.
			rc.WorkspaceRole = rc.User.WorkspaceRole(&ws)
			if rc.WorkspaceRole.IsValid() {
				rc.ActiveWorkspace = &ws
			} else {
				slog.Warn("user-danger", slog.String("mail", rc.User.Email), slog.String("id", rc.User.ID.String()), slog.String("workspaceID", ws.ID.String()))
				return rc //
			}
		}
	}
	switch r.RequestURI {
	case "/":
		rc.Page = pageLanding
	case "/users":
		rc.Page = pageUsers
	case "/workspaces":
		rc.Page = pageWorkspaces
	case "/documents":
		rc.Page = pageDocuments
	case "/members":
		rc.Page = pageMembers
	}
	rc.CSRFToken = sv.auth.GetCSRFToken(r)
	rc.Now = time.Now()
	return rc
}

// getActiveWorkspaceID returns the workspace UUID from the cookie, or uuid.Nil if not set.
func (sv *Server) getActiveWorkspaceID(r *http.Request) uuid.UUID {
	cookie, err := r.Cookie(activeWorkspaceCookie)
	if err != nil {
		return uuid.Nil
	}
	wsID, err := uuid.Parse(cookie.Value)
	if err != nil {
		return uuid.Nil
	}
	return wsID
}

// setActiveWorkspace sets a cookie to store the active workspace ID.
func (sv *Server) setActiveWorkspace(w http.ResponseWriter, wsID uuid.UUID) {
	http.SetCookie(w, &http.Cookie{
		Name:     activeWorkspaceCookie,
		Value:    wsID.String(),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// clearActiveWorkspace removes the active workspace cookie.
func (sv *Server) clearActiveWorkspace(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     activeWorkspaceCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
}

func (sv *Server) handleLanding() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sv.servePage(w, r, landingPage(sv.RenderContext(w, r)), sv.RenderContext(w, r))
	}
}

func (sv *Server) handleUsers() RoleHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, rc RequestContext) {
		var users []User
		err := sv.db.Users(func(dst *User) error {
			users = append(users, *dst)
			return nil
		})
		if err != nil {
			sv.error(w, err.Error(), 500)
			return
		}
		sv.servePage(w, r, usersPage(rc, users), rc)
	}
}

func (sv *Server) handleWorkspaces() RoleHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, rc RequestContext) {
		var workspaces []Workspace
		for _, wsID := range rc.User.Workspaces {
			var ws Workspace
			if err := sv.db.WorkspaceByUUID(&ws, wsID); err == nil {
				workspaces = append(workspaces, ws)
			}
		}
		sv.servePage(w, r, workspacesPage(rc, workspaces), rc)
	}
}

func (sv *Server) handleCreateWorkspace() RoleHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, rc RequestContext) {
		ws := Workspace{
			ID:      uuid.New(),
			OwnerID: rc.User.ID,
			Name:    r.FormValue("name"),
			Members: []Member{{
				UserID:        rc.User.ID,
				Email:         rc.User.Email,
				AddedBy:       rc.User.ID,
				JoinedAt:      time.Now(),
				WorkspaceRole: RoleAdmin,
			}},
		}
		if err := sv.db.WorkspaceCreate(ws); err != nil {
			sv.error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// Add workspace to user's list.
		rc.User.Workspaces = append(rc.User.Workspaces, ws.ID)
		if err := sv.db.UserUpdate(rc.User); err != nil {
			sv.error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// Activate the new workspace.
		sv.setActiveWorkspace(w, ws.ID)
		w.Header().Set("HX-Redirect", "/documents")
	}
}

func (sv *Server) handleActivateWorkspace() RoleHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, rc RequestContext) {
		wsIDStr := r.PathValue("id")
		wsID, err := uuid.Parse(wsIDStr)
		if err != nil {
			sv.error(w, "invalid workspace ID", http.StatusBadRequest)
			return
		}
		// Verify workspace exists and user is a member.
		var ws Workspace
		if err := sv.db.WorkspaceByUUID(&ws, wsID); err != nil {
			sv.error(w, "workspace not found", http.StatusNotFound)
			return
		}
		isMember := false
		for _, m := range ws.Members {
			if m.UserID == rc.User.ID {
				isMember = true
				break
			}
		}
		if !isMember {
			sv.error(w, "access denied", http.StatusForbidden)
			return
		}
		sv.setActiveWorkspace(w, wsID)
		w.Header().Set("HX-Redirect", "/documents")
	}
}

func (sv *Server) handleDeleteWorkspace() RoleHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, rc RequestContext) {
		wsIDStr := r.PathValue("id")
		wsID, err := uuid.Parse(wsIDStr)
		if err != nil {
			sv.error(w, "invalid workspace ID", http.StatusBadRequest)
			return
		}
		if err := sv.db.WorkspaceDelete(wsID); err != nil {
			sv.error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// Clear active workspace if it was the deleted one.
		if rc.ActiveWorkspace != nil && rc.ActiveWorkspace.ID == wsID {
			sv.clearActiveWorkspace(w)
		}
		w.WriteHeader(http.StatusOK)
	}
}

// Document handlers (require active workspace via HandleFunc middleware).

func (sv *Server) handleDocuments() RoleHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, rc RequestContext) {
		var docs []DocumentView
		for _, docID := range rc.ActiveWorkspace.Documents {
			var doc DocumentView
			if err := sv.db.DocumentViewByUUID(&doc, docID); err == nil {
				docs = append(docs, doc)
			}
		}
		sv.servePage(w, r, documentsPage(rc, docs), rc)
	}
}

func (sv *Server) handleCreateDocument() RoleHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, rc RequestContext) {
		if err := r.ParseMultipartForm(10 << 20); err != nil { // 10MB max
			sv.error(w, "file too large", http.StatusBadRequest)
			return
		}
		title := r.FormValue("title")
		file, _, err := r.FormFile("file")
		if err != nil {
			sv.error(w, "file required", http.StatusBadRequest)
			return
		}
		defer file.Close()

		content, err := io.ReadAll(file)
		if err != nil {
			sv.error(w, "failed to read file", http.StatusInternalServerError)
			return
		}

		doc := Document{
			ID:        uuid.New(),
			CreatorID: rc.User.ID,
			Title:     title,
			Content:   content,
		}
		if err := sv.db.DocumentCreate(doc); err != nil {
			sv.error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := sv.db.WorkspaceAddDocument(rc.ActiveWorkspace.ID, doc.ID); err != nil {
			sv.error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

func (sv *Server) handleDocumentView() RoleHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, rc RequestContext) {
		docIDStr := r.PathValue("id")
		docID, err := uuid.Parse(docIDStr)
		if err != nil {
			sv.error(w, "invalid document ID", http.StatusBadRequest)
			return
		}
		// Verify document belongs to active workspace.
		found := false
		for _, d := range rc.ActiveWorkspace.Documents {
			if d == docID {
				found = true
				break
			}
		}
		if !found {
			sv.error(w, "document not found in workspace", http.StatusNotFound)
			return
		}
		var doc Document
		if err := sv.db.DocumentByUUID(&doc, docID); err != nil {
			sv.error(w, "document not found", http.StatusNotFound)
			return
		}
		sv.servePage(w, r, documentPage(rc, doc), rc)
	}
}

func (sv *Server) handleUpdateDocumentName() RoleHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, rc RequestContext) {
		docIDStr := r.PathValue("id")
		docID, err := uuid.Parse(docIDStr)
		if err != nil {
			sv.error(w, "invalid document ID", http.StatusBadRequest)
			return
		}
		// Verify document belongs to active workspace.
		found := false
		for _, d := range rc.ActiveWorkspace.Documents {
			if d == docID {
				found = true
				break
			}
		}
		if !found {
			sv.error(w, "document not found in workspace", http.StatusNotFound)
			return
		}
		var doc Document
		if err := sv.db.DocumentByUUID(&doc, docID); err != nil {
			sv.error(w, "document not found", http.StatusNotFound)
			return
		}
		newName := r.FormValue("name")
		if newName == "" {
			sv.error(w, "name required", http.StatusBadRequest)
			return
		}
		doc.Title = newName
		if err := sv.db.DocumentUpdate(doc); err != nil {
			sv.error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

// Member handlers (require active workspace via HandleFunc middleware).

func (sv *Server) handleMembers() RoleHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, rc RequestContext) {
		sv.servePage(w, r, membersPage(rc), rc)
	}
}

// handleAddMember adds an existing user to Workspace.Members and adds the workspace to User.Workspaces.
func (sv *Server) handleAddMember() RoleHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, rc RequestContext) {
		email := r.FormValue("email")
		if email == "" {
			sv.errorShow(rc, "email is required", nil)
			return
		}
		var role Role
		if err := role.UnmarshalText([]byte(r.FormValue("role"))); err != nil || role > rc.WorkspaceRole {
			sv.errorShow(rc, "invalid role", err)
			return
		}
		if slices.ContainsFunc(rc.ActiveWorkspace.Members, func(m Member) bool { return m.Email == email }) {
			sv.errorShow(rc, "already a member", nil)
			return
		}

		// User must already exist.
		var user User
		if err := sv.db.UserByEmail(&user, email); err != nil {
			sv.errorShow(rc, "user not found", err)
			return
		}

		// Atomically add member to workspace and workspace to user.
		member := Member{
			UserID: user.ID, Email: email, AddedBy: rc.User.ID, JoinedAt: time.Now(), WorkspaceRole: role,
		}
		if err := sv.db.WorkspaceAddMember(rc.ActiveWorkspace.ID, member); err != nil {
			sv.errorShow(rc, "failed to add member", err)
			return
		}

		sv.toasts.Send(rc.User.Email, Toast{Level: toastLevelSuccess, Message: "added " + email})
		w.Header().Set("HX-Redirect", "/members")
	}
}

// handleRemoveMember removes a user from Workspace.Members and removes the workspace from User.Workspaces.
func (sv *Server) handleRemoveMember() RoleHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, rc RequestContext) {
		memberID, err := uuid.Parse(r.PathValue("id"))
		if err != nil || memberID == rc.ActiveWorkspace.OwnerID || memberID == rc.User.ID {
			sv.errorShow(rc, "cannot remove this member", err)
			return
		}

		// Find email before removing.
		idx := slices.IndexFunc(rc.ActiveWorkspace.Members, func(m Member) bool { return m.UserID == memberID })
		if idx == -1 {
			sv.errorShow(rc, "member not found", nil)
			return
		}
		email := rc.ActiveWorkspace.Members[idx].Email

		// Atomically remove member from workspace and workspace from user.
		if err := sv.db.WorkspaceRemoveMember(rc.ActiveWorkspace.ID, memberID); err != nil {
			sv.errorShow(rc, "failed to remove member", err)
			return
		}

		sv.toasts.Send(rc.User.Email, Toast{Level: toastLevelSuccess, Message: "removed " + email})
		w.Header().Set("HX-Redirect", "/members")
	}
}

// handleChangeMemberRole updates a member's WorkspaceRole in Workspace.Members.
func (sv *Server) handleChangeMemberRole() RoleHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, rc RequestContext) {
		memberID, err := uuid.Parse(r.PathValue("id"))
		if err != nil || memberID == rc.ActiveWorkspace.OwnerID {
			sv.errorShow(rc, "cannot change this role", err)
			return
		}
		var newRole Role
		if err := newRole.UnmarshalText([]byte(r.FormValue("role"))); err != nil || newRole > rc.WorkspaceRole {
			sv.errorShow(rc, "invalid role", err)
			return
		}

		// Update WorkspaceRole in Workspace.Members.
		idx := slices.IndexFunc(rc.ActiveWorkspace.Members, func(m Member) bool { return m.UserID == memberID })
		if idx == -1 {
			sv.errorShow(rc, "member not found", nil)
			return
		}
		email := rc.ActiveWorkspace.Members[idx].Email
		rc.ActiveWorkspace.Members[idx].WorkspaceRole = newRole
		if err := sv.db.WorkspaceUpdate(*rc.ActiveWorkspace); err != nil {
			sv.errorShow(rc, "failed to update workspace", err)
			return
		}

		sv.toasts.Send(rc.User.Email, Toast{Level: toastLevelSuccess, Message: email + " is now " + newRole.String()})
		w.Header().Set("HX-Redirect", "/members")
	}
}

// handleTransferOwnership changes Workspace.OwnerID and adjusts roles.
func (sv *Server) handleTransferOwnership() RoleHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, rc RequestContext) {
		newOwnerID, err := uuid.Parse(r.URL.Query().Get("to"))
		if err != nil || newOwnerID == rc.User.ID {
			sv.errorShow(rc, "invalid transfer target", err)
			return
		}

		// Find new owner and promote to Admin if needed. Demote old owner to Admin.
		newOwnerIdx := slices.IndexFunc(rc.ActiveWorkspace.Members, func(m Member) bool { return m.UserID == newOwnerID })
		if newOwnerIdx == -1 {
			sv.errorShow(rc, "user is not a member", nil)
			return
		}
		newOwnerEmail := rc.ActiveWorkspace.Members[newOwnerIdx].Email
		if rc.ActiveWorkspace.Members[newOwnerIdx].WorkspaceRole < RoleAdmin {
			rc.ActiveWorkspace.Members[newOwnerIdx].WorkspaceRole = RoleAdmin
		}

		// Demote old owner to Admin.
		oldOwnerIdx := slices.IndexFunc(rc.ActiveWorkspace.Members, func(m Member) bool { return m.UserID == rc.ActiveWorkspace.OwnerID })
		if oldOwnerIdx != -1 {
			rc.ActiveWorkspace.Members[oldOwnerIdx].WorkspaceRole = RoleAdmin
		}

		rc.ActiveWorkspace.OwnerID = newOwnerID
		if err := sv.db.WorkspaceUpdate(*rc.ActiveWorkspace); err != nil {
			sv.errorShow(rc, "failed to update workspace", err)
			return
		}

		sv.toasts.Send(rc.User.Email, Toast{Level: toastLevelSuccess, Message: "transferred ownership to " + newOwnerEmail})
		w.Header().Set("HX-Redirect", "/members")
	}
}

// servePage uses the `page` function and serves an entire page to the http response writer with `component` as the core page content.
func (sv *Server) servePage(w http.ResponseWriter, r *http.Request, component templ.Component, rc RequestContext) {
	sv.serveComponent(w, r, page(component, rc))
}

// serveComponent is the lowest level way of serving a component using Templ. Can serve whole pages to individual HTML elements for partial page updates.
func (sv *Server) serveComponent(w http.ResponseWriter, r *http.Request, c templ.Component) {
	handler := templ.Handler(c)
	handler.ServeHTTP(w, r)
	slog.Debug("serveComponent:done", slog.String("req", r.URL.String()))
}

func (sv *Server) errorShow(rc RequestContext, contextForUser string, err error) {
	if err != nil {
		slog.Error("errorShow", slog.String("ctx", contextForUser), slog.String("err", err.Error()), slog.String("email", rc.User.Email), slog.String("page", rc.Page.String()))
	} else {
		slog.Warn("errorShow", slog.String("ctx", contextForUser), slog.String("email", rc.User.Email), slog.String("page", rc.Page.String()))
	}
	sv.toasts.Send(rc.User.Email, Toast{Level: slog.LevelError, Message: contextForUser})
}

// validateCSRF checks the CSRF token from the request against the session token.
// Returns true if valid, false otherwise.
func (sv *Server) validateCSRF(r *http.Request, rc RequestContext) bool {
	token := r.FormValue("csrf_token")
	if token == "" {
		token = r.Header.Get("X-CSRF-Token")
	}
	return token != "" && token == rc.CSRFToken
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
