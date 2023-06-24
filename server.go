package main

import (
	"embed"
	"io/fs"
	"log"
	"net/http"
	"strings"
	"text/template"
)

//go:embed assets
var assets embed.FS

type Server struct {
	// Inspired by Mat Ryer's post on writing HTTP services:
	// https://pace.dev/blog/2018/05/09/how-I-write-http-services-after-eight-years.html
	router *http.ServeMux
	// table stores data
	table []record
}

func NewServer() *Server {
	return &Server{
		router: http.NewServeMux(),
		table: []record{
			{DocumentName: "HX-1", Author: "John Doe", Description: "A document"},
		},
	}
}

func (s *Server) routes() {
	s.router.HandleFunc("/", s.handleLanding())
	s.router.HandleFunc("/assets/", s.handlePublicAsset())
	s.router.HandleFunc("/table/", s.handleTable())
	s.router.HandleFunc("/table/action/", s.handleTableAction())
}

func (s *Server) handleLanding() http.HandlerFunc {
	index, errSetup := assets.ReadFile("assets/index.html")
	if errSetup != nil {
		panic(errSetup)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		w.Write(index)
	}
}

func (s *Server) handlePublicAsset() http.HandlerFunc {
	publicAssets, errSetup := fs.Sub(assets, "assets/public")
	if errSetup != nil {
		panic(errSetup)
	}
	httpFS := http.FileServer(http.FS(publicAssets))

	return func(w http.ResponseWriter, r *http.Request) {
		r.URL.Path = strings.TrimPrefix(r.URL.Path, "/assets")
		httpFS.ServeHTTP(w, r)
	}
}

func (s *Server) handleTable() http.HandlerFunc {
	tmpl, errSetup := template.ParseFS(assets, "assets/table_tmpl.html")
	if errSetup != nil {
		panic(errSetup)
	}
	return func(w http.ResponseWriter, r *http.Request) {
		err := tmpl.Execute(w, s.table)
		if err != nil {
			panic(err)
		}
	}
}

func (s *Server) handleTableAction() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		method := r.Method
		name := r.URL.Path[len("/table/action/"):]
		idx := -1

		// If method is PUT, we are creating, not editing existing record.
		if method != http.MethodPost {
			for i, record := range s.table {
				if record.DocumentName == name {
					idx = i
					break
				}
			}
			if idx == -1 {
				http.Error(w, "invalid document name", http.StatusBadRequest)
			}
		}

		switch {
		case method == http.MethodDelete:
			s.table = append(s.table[:idx], s.table[idx+1:]...)
		case method == http.MethodPost:
			// Parse form data.
			err := r.ParseForm()
			if err != nil {
				http.Error(w, "invalid form data", http.StatusBadRequest)
				return
			}
			// Get form data.
			name := r.FormValue("document_name")
			author := r.FormValue("author")
			description := r.FormValue("description")
			if name == "" || author == "" || description == "" {
				// This is not suitable for production. We should validate data
				// before creating a record. i.e. Making sure characters are utf-8,
				// and that the length of the strings are within a certain range,
				// and that the data is not malicious (URL injection a.k.a XSS, etc.)
				http.Error(w, "invalid form data", http.StatusBadRequest)
				return
			}
			// Create new record.
			s.table = append(s.table, record{DocumentName: name, Author: author, Description: description})
		default:
			http.Error(w, "invalid method "+method, http.StatusMethodNotAllowed)
			return
		}
		log.Println("action", method, "on", name, "successful")
	}
}

type record struct {
	DocumentName string `json:"document_name"`
	Author       string `json:"author"`
	Description  string `json:"description"`
}
