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
	Provider  string    `json:"provider"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (u *User) HasClearance(requiredClearance Role) bool {
	return u.Role >= requiredClearance
}
func (u *User) validateForUpdate() error {
	if !u.Role.IsValid() {
		return errors.New("invalid user role")
	} else if u.Provider != "nowhere" && u.Provider != "google" {
		return errors.New("invalid user provider")
	}
	var z uuid.UUID
	if u.ID == z {
		return errors.New("UUID not set")
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
	if id == (uuid.UUID{}) {
		return errors.New("zero UUID")
	}
	return db.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketUsers)
		data := b.Get(id[:])
		if data == nil {
			return errors.New("user not found")
		}
		return json.NewDecoder(bytes.NewReader(data)).Decode(dst)
	})
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
	err := newUser.validateForUpdate()
	if err != nil {
		return err
	}
	return db.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketUsers)
		data := b.Get(newUser.ID[:])
		if data != nil {
			return errors.New("user already exists")
		}
		newUser.CreatedAt = time.Now()
		newUser.UpdatedAt = newUser.CreatedAt
		data, err := json.Marshal(newUser)
		if err != nil {
			panic(err) // Unreachable in theory.
		}
		db.cacheMail(newUser.Email, newUser.ID)
		return b.Put(newUser.ID[:], data)
	})
}

func (db *Store) UserUpdate(updatedUser User) error {
	err := updatedUser.validateForUpdate()
	if err != nil {
		return err
	}
	return db.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketUsers)
		data := b.Get(updatedUser.ID[:])
		if data == nil {
			return errors.New("could not find user to update")
		}
		var existing User
		json.Unmarshal(data, &existing)
		if existing.Email != updatedUser.Email {
			// Email change cache update.
			db.mailCacheMu.Lock()
			delete(db.mailCache, existing.Email)
			db.mailCache[updatedUser.Email] = updatedUser.ID
			db.mailCacheMu.Unlock()
		}
		updatedUser.CreatedAt = existing.CreatedAt
		updatedUser.UpdatedAt = time.Now()
		data, err := json.Marshal(updatedUser)
		if err != nil {
			panic(err) // Unreachable in theory.
		}
		fmt.Println("update old user", existing, "with new", updatedUser)
		return b.Put(updatedUser.ID[:], data)
	})
}

func (db *Store) UserDelete(id uuid.UUID) error {
	return db.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketUsers)
		data := b.Get(id[:])
		if data == nil {
			return errors.New("could not find user to delete")
		}
		var usr User
		err := json.Unmarshal(data, &usr)
		if err != nil {
			return err
		}
		db.mailCacheMu.Lock()
		delete(db.mailCache, usr.Email)
		db.mailCacheMu.Unlock()
		return b.Delete(id[:])
	})
}

func (db *Store) Users(cb func(dst *User) error) error {
	var usr User
	return db.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketUsers)
		return b.ForEach(func(k, v []byte) error {
			err := json.NewDecoder(bytes.NewReader(v)).Decode(&usr)
			if err != nil {
				return err
			}
			return cb(&usr)
		})
	})
}
