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
	bucketUsers = []byte("users")

	errEndIter = errors.New("error flagging end of DB iteration")
)

type User struct {
	Email string    `json:"email"`
	ID    uuid.UUID `json:"uuid"`
	Role  Role      `json:"role"`
	// Provider is the OAuth provider for this user's email.
	Provider   string      `json:"provider"`
	CreatedAt  time.Time   `json:"created_at"`
	UpdatedAt  time.Time   `json:"updated_at"`
	Workspaces []uuid.UUID `json:"workspaces"`
}

type Workspace struct {
	ID        uuid.UUID   `json:"uuid"`
	Members   []Member    `json:"members"`
	Documents []uuid.UUID `json:"documents"`
}

type Member struct {
	UserID        uuid.UUID `json:"user_uuid"`
	WorkspaceRole Role      `json:"workspace_role"`
}

type DocumentView struct {
	ID    uuid.UUID `json:"uuid"`
	Title string    `json:"title"`
	// Content field is omitted. will not be unmarshalled.
}

type Document struct {
	ID      uuid.UUID `json:"uuid"`
	Title   string    `json:"title"`
	Content []byte    `json:"content"`
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
	return m.WorkspaceRole >= requiredClearance
}

func (u *User) HasClearance(requiredClearance Role) bool {
	return u.Role >= requiredClearance
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
		for _, bucket := range [][]byte{bucketUsers} {
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
	if len(data) > 5*MB {
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
