package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/mail"
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
	// Provider is the OAuth provider for this user's email.
	Provider  string    `json:"provider"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (u *User) Validate() error {
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

type Store struct {
	db *bbolt.DB
}

func (db *Store) Open(filename string) error {
	db.Close()
	bdb, err := bbolt.Open(filename, 0777, bbolt.DefaultOptions)
	if err != nil {
		return err
	}
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
	emailb := []byte(email)
	return db.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketUsers)
		err = b.ForEach(func(k, v []byte) error {
			// Quite inefficient for several users, prefer searching users by UUID until adding a cache.
			if bytes.Contains(v, emailb) {
				err = json.NewDecoder(bytes.NewReader(v)).Decode(dst)
				if dst.Email == email {
					return errEndIter
				}
			}
			return nil
		})
		if err == errEndIter {
			return nil
		}
		return errors.New("email not found")
	})
}

func (db *Store) UserCreate(newUser User) error {
	err := newUser.Validate()
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
		return b.Put(newUser.ID[:], data)
	})
}

func (db *Store) UserUpdate(updatedUser User) error {
	err := updatedUser.Validate()
	if err != nil {
		return err
	}
	return db.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketUsers)
		data := b.Get(updatedUser.ID[:])
		if data == nil {
			return errors.New("could not find user to update")
		}
		updatedUser.UpdatedAt = time.Now()
		data, err := json.Marshal(updatedUser)
		if err != nil {
			panic(err) // Unreachable in theory.
		}
		return b.Put(updatedUser.ID[:], data)
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
