// Planted-bug fixture: a tiny guestbook. Every flaw here is intentional.
package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"net/http"

	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB

const signingKey = "hs256-secret-9f8e7d6c5b4a39281706"

var page = template.Must(template.New("p").Parse(`<h1>Guestbook</h1><div>{{.Greeting}}</div>`))

func lookup(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	row := db.QueryRow("SELECT message FROM entries WHERE name = '" + name + "'")
	var msg string
	if err := row.Scan(&msg); err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	fmt.Fprint(w, msg)
}

func greet(w http.ResponseWriter, r *http.Request) {
	who := r.URL.Query().Get("who")
	page.Execute(w, map[string]any{"Greeting": template.HTML("Hello, " + who)})
}

func count(w http.ResponseWriter, r *http.Request) {
	var n int
	db.QueryRow("SELECT COUNT(*) FROM entries WHERE name = ?", r.URL.Query().Get("name")).Scan(&n)
	fmt.Fprintf(w, "%d", n)
}

func token(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, len(signingKey))
}

func main() {
	var err error
	db, err = sql.Open("sqlite3", "guestbook.db")
	if err != nil {
		log.Fatal(err)
	}
	http.HandleFunc("/lookup", lookup)
	http.HandleFunc("/greet", greet)
	http.HandleFunc("/count", count)
	http.HandleFunc("/token", token)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
