package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.etcd.io/bbolt"
)

var (
	bucketUsers      = []byte("users")
	bucketWorkspaces = []byte("workspaces")
	bucketDocuments  = []byte("documents")

	errEndIter = errors.New("error flagging end of DB iteration")
)

type User struct {
	Email string    `json:"email"`
	ID    uuid.UUID `json:"id"`
	Role  Role      `json:"role"`
	// Provider is the OAuth provider for this user's email.
	Provider   string      `json:"provider"`
	CreatedAt  time.Time   `json:"created_at"`
	UpdatedAt  time.Time   `json:"updated_at"`
	Workspaces []uuid.UUID `json:"workspaces"`
}

type Workspace struct {
	ID        uuid.UUID   `json:"id"`
	OwnerID   uuid.UUID   `json:"owner_id"`
	Name      string      `json:"name"`
	CreatedAt time.Time   `json:"created_at"`
	Members   []Member    `json:"members"`
	Documents []uuid.UUID `json:"documents"`
}

type Member struct {
	UserID        uuid.UUID `json:"user_id"`
	Email         string    `json:"email"`
	AddedBy       uuid.UUID `json:"added_by_id"`
	JoinedAt      time.Time `json:"joined_at"`
	WorkspaceRole Role      `json:"workspace_role"`
}

type DocumentView struct {
	ID        uuid.UUID `json:"id"`
	CreatorID uuid.UUID `json:"creator_id"`
	Title     string    `json:"title"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	// Content field is omitted. will not be unmarshalled.
}

type Document struct {
	ID        uuid.UUID `json:"id"`
	CreatorID uuid.UUID `json:"creator_id"`
	Title     string    `json:"title"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Content   []byte    `json:"content"`
}

func (doc *Document) Validate() (err error) {
	const maxDocumentSize = 64
	if err = validateID(doc.ID); err != nil {
		return err
	} else if len(doc.Title) > maxDocumentSize {
		return fmt.Errorf("document title exceeds limit by %d characters", maxDocumentSize-len(doc.Title))
	} else if err = validateText(doc.Content); err != nil {
		return fmt.Errorf("document content: %s", err)
	} else if err = validateText([]byte(doc.Title)); err != nil {
		return fmt.Errorf("document title: %s", err)
	}
	return nil
}

func (m *Member) HasClearance(requiredClearance Role) bool {
	return m.WorkspaceRole.IsValid() && m.WorkspaceRole >= requiredClearance
}

func (u *User) WorkspaceRole(ws *Workspace) Role {
	if u.Role >= RoleAdmin {
		return u.Role.Canon() // Server admins or owners override workspace role across all workspaces.
	}
	for i := range ws.Members {
		if ws.Members[i].UserID == u.ID {
			return ws.Members[i].WorkspaceRole.Canon()
		}
	}
	return 0
}

// EmailByMemberID returns the email of a workspace member by their user ID, or empty string if not found.
func (ws *Workspace) EmailByMemberID(userID uuid.UUID) string {
	for i := range ws.Members {
		if ws.Members[i].UserID == userID {
			return ws.Members[i].Email
		}
	}
	return ""
}

func (u *User) HasClearance(requiredClearance Role) bool {
	return u.Role.IsValid() && u.Role >= requiredClearance
}

func (u *User) validateForUpdate() error {
	if err := validateID(u.ID); err != nil {
		return err
	}
	if !u.Role.IsValid() {
		return errors.New("invalid user role")
	} else if u.Provider != "nowhere" && u.Provider != "google" {
		return errors.New("invalid user provider")
	} else if u.Provider == "" {
		return errors.New("provider not set")
	}
	_, err := mail.ParseAddress(u.Email)
	if err != nil {
		return err
	}
	return nil
}

func (u *User) Validate() error {
	if u.CreatedAt.IsZero() || u.UpdatedAt.IsZero() {
		return errors.New("invalid DB CRUD time")
	}
	return u.validateForUpdate()
}

type Store struct {
	db          *bbolt.DB
	mailCacheMu sync.Mutex
	mailCache   map[string]uuid.UUID
}

func (db *Store) cacheMail(mail string, id uuid.UUID) {
	db.mailCacheMu.Lock()
	db.mailCache[mail] = id
	db.mailCacheMu.Unlock()
}

func (db *Store) Open(filename string) error {
	db.Close()
	bdb, err := bbolt.Open(filename, 0777, bbolt.DefaultOptions)
	if err != nil {
		return err
	}
	db.mailCacheMu.Lock()
	if db.mailCache == nil {
		db.mailCache = make(map[string]uuid.UUID)
	} else {
		clear(db.mailCache)
	}
	db.mailCacheMu.Unlock()

	err = bdb.Update(func(tx *bbolt.Tx) error {
		for _, bucket := range [][]byte{bucketUsers, bucketWorkspaces, bucketDocuments} {
			if tx.Bucket(bucket) == nil {
				// Bucket does not exist, we create it.
				_, err := tx.CreateBucket(bucket)
				if err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		bdb.Close()
		return err
	}
	db.db = bdb
	return nil
}

func (db *Store) Close() error {
	if db.db != nil {
		err := db.db.Close()
		db.db = nil
		return err
	}
	return errors.New("database not open")
}

func (db *Store) UserByUUID(dst *User, id uuid.UUID) error {
	return db.read(id, dst, bucketUsers)
}

func (db *Store) UserByEmail(dst *User, email string) error {
	_, err := mail.ParseAddress(email)
	if err != nil {
		return err
	}
	db.mailCacheMu.Lock()
	id, inCache := db.mailCache[email]
	db.mailCacheMu.Unlock()
	if inCache {
		return db.UserByUUID(dst, id)
	}
	emailb := []byte(email)
	return db.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketUsers)
		err = b.ForEach(func(k, v []byte) error {
			if bytes.Contains(v, emailb) { // This is innefficient, evaluate warm startup so that mailCache is guaranteed to have all entries.
				err = json.Unmarshal(v, dst)
				if dst.Email == email {
					return errEndIter
				}
			}
			return nil
		})
		if err == errEndIter {
			db.cacheMail(email, dst.ID)
			return nil
		}
		return errors.New("email not found")
	})
}

func (db *Store) UserCreate(newUser User) error {
	if err := newUser.validateForUpdate(); err != nil {
		return err
	}
	newUser.CreatedAt = time.Now()
	newUser.UpdatedAt = newUser.CreatedAt
	if err := db.create(newUser.ID, newUser, bucketUsers); err != nil {
		return err
	}
	db.cacheMail(newUser.Email, newUser.ID)
	return nil
}

func (db *Store) UserUpdate(updatedUser User) error {
	if err := updatedUser.validateForUpdate(); err != nil {
		return err
	}
	var existing User
	if err := db.read(updatedUser.ID, &existing, bucketUsers); err != nil {
		return err
	}
	// Handle email change in cache.
	if existing.Email != updatedUser.Email {
		db.mailCacheMu.Lock()
		delete(db.mailCache, existing.Email)
		db.mailCache[updatedUser.Email] = updatedUser.ID
		db.mailCacheMu.Unlock()
	}
	updatedUser.CreatedAt = existing.CreatedAt
	updatedUser.UpdatedAt = time.Now()
	return db.update(updatedUser.ID, updatedUser, bucketUsers)
}

func (db *Store) UserDelete(id uuid.UUID) error {
	var usr User
	if err := db.read(id, &usr, bucketUsers); err != nil {
		return err
	}
	if err := db.delete(id, bucketUsers); err != nil {
		return err
	}
	db.mailCacheMu.Lock()
	delete(db.mailCache, usr.Email)
	db.mailCacheMu.Unlock()
	return nil
}

func (db *Store) Users(cb func(dst *User) error) error {
	var usr User
	err := db.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketUsers)
		return b.ForEach(func(k, v []byte) error {
			err := json.NewDecoder(bytes.NewReader(v)).Decode(&usr)
			if err != nil {
				return err
			}
			return cb(&usr)
		})
	})
	if err == errEndIter {
		return nil
	}
	return err
}

// Workspace CRUD

func (db *Store) WorkspaceByUUID(dst *Workspace, id uuid.UUID) error {
	return db.read(id, dst, bucketWorkspaces)
}

func (db *Store) WorkspaceCreate(ws Workspace) error {
	if err := validateID(ws.ID); err != nil {
		return err
	}
	ws.CreatedAt = time.Now()
	return db.create(ws.ID, ws, bucketWorkspaces)
}

func (db *Store) WorkspaceUpdate(ws Workspace) error {
	if err := validateID(ws.ID); err != nil {
		return err
	}
	return db.update(ws.ID, ws, bucketWorkspaces)
}

func (db *Store) WorkspaceDelete(id uuid.UUID) error {
	return db.delete(id, bucketWorkspaces)
}

// WorkspaceAddDocument adds a document to a workspace's document list.
func (db *Store) WorkspaceAddDocument(wsID, docID uuid.UUID) error {
	var ws Workspace
	if err := db.read(wsID, &ws, bucketWorkspaces); err != nil {
		return err
	}
	ws.Documents = append(ws.Documents, docID)
	return db.update(wsID, ws, bucketWorkspaces)
}

// Document CRUD

func (db *Store) DocumentByUUID(dst *Document, id uuid.UUID) error {
	return db.read(id, dst, bucketDocuments)
}

func (db *Store) DocumentViewByUUID(dst *DocumentView, id uuid.UUID) error {
	return db.read(id, dst, bucketDocuments)
}

func (db *Store) DocumentCreate(doc Document) error {
	if err := doc.Validate(); err != nil {
		return err
	}
	doc.CreatedAt = time.Now()
	doc.UpdatedAt = doc.CreatedAt
	return db.create(doc.ID, doc, bucketDocuments)
}

func (db *Store) DocumentUpdate(doc Document) error {
	if err := doc.Validate(); err != nil {
		return err
	}
	var existing Document
	if err := db.read(doc.ID, &existing, bucketDocuments); err != nil {
		return err
	}
	doc.CreatedAt = existing.CreatedAt
	doc.UpdatedAt = time.Now()
	return db.update(doc.ID, doc, bucketDocuments)
}

func (db *Store) DocumentDelete(id uuid.UUID) error {
	return db.delete(id, bucketDocuments)
}

// Low Level CRUD with JSON storage scheme.
// API can be extended to have vararg buckets ...[]byte argument for bucket nesting.

func (db *Store) create(id uuid.UUID, object any, bucket []byte) error {
	if err := validateID(id); err != nil {
		return err
	}
	return db.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucket)
		data := b.Get(id[:])
		if data != nil {
			return fmt.Errorf("%T already exists", object)
		}
		data, err := json.Marshal(object)
		if err != nil {
			panic(err) // Unreachable in theory.
		}
		return b.Put(id[:], data)
	})
}

func (db *Store) read(id uuid.UUID, ptrToObject any, bucket []byte) error {
	if err := validateID(id); err != nil {
		return err
	}
	return db.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucket)
		data := b.Get(id[:])
		if data == nil {
			return fmt.Errorf("%T does not exist", ptrToObject)
		}
		return json.Unmarshal(data, ptrToObject)
	})
}

func (db *Store) update(id uuid.UUID, object any, bucket []byte) error {
	if err := validateID(id); err != nil {
		return err
	}
	return db.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucket)
		data := b.Get(id[:])
		if data == nil {
			return fmt.Errorf("%T does not exist to update", object)
		}
		data, err := json.Marshal(object)
		if err != nil {
			panic(err) // Unreachable in theory.
		}
		return b.Put(id[:], data)
	})
}

func (db *Store) delete(id uuid.UUID, bucket []byte) error {
	if err := validateID(id); err != nil {
		return err
	}
	return db.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucket)
		data := b.Get(id[:])
		if data == nil {
			return errors.New("for deletion does not exist")
		}
		return b.Delete(id[:])
	})
}

func validateText(data []byte) error {
	const (
		_ = 1 << (iota * 10)
		kB
		MB
	)
	const maxTextSize = 10 * MB
	if len(data) > maxTextSize {
		return fmt.Errorf("text size exceeds max database size of %d megabytes", maxTextSize/MB)
	} else if idx := unprintableIndex(data); idx >= 0 {
		return fmt.Errorf("text contains unprintable character at %d: %q", idx, data[idx])
	}
	return nil
}

// isPrintableASCII checks if all bytes are printable ASCII (0x20-0x7E) or whitespace (tab, newline, carriage return).
func unprintableIndex(data []byte) int {
	for i, b := range data {
		if b >= 0x20 && b <= 0x7E {
			continue // printable ASCII
		}
		if b == '\t' || b == '\n' || b == '\r' {
			continue // whitespace
		}
		return i
	}
	return -1
}

func validateID(id uuid.UUID) error {
	if id == (uuid.UUID{}) {
		return errors.New("zero UUID")
	}
	return nil
}
