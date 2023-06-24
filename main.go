package main

import (
	"log"
	"net/http"
)

func main() {
	const addr = ":8080"
	s := NewServer()
	s.routes()
	log.Println("listening on", addr, "(http://localhost:8080)")
	err := http.ListenAndServe(addr, s.router)
	if err != nil {
		log.Fatal(err)
	}
}
