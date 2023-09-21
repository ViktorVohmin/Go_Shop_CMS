package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"crypto/tls"
	 
	"golang.org/x/crypto/bcrypt"
	_ "github.com/lib/pq"
)

const (
	host     = "localhost"
	port     = 5432
	user     = "postgres"
	password = "1"
	dbname   = "postgres"
)

var db *sql.DB

func main() {
	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname)

	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	
	// Загрузка PEM-файла
    certFile := "cert.pem"

    cert, err := tls.LoadX509KeyPair(certFile, certFile)
    if err != nil {
        log.Fatal(err)
    }

    // Создание TLS-конфигурации
    tlsConfig := &tls.Config{
        Certificates: []tls.Certificate{cert},
    }

    // Настройка HTTP-сервера с использованием TLS
    server := &http.Server{
        Addr:      fmt.Sprintf(":%d", port),
        TLSConfig: tlsConfig,
    }
	http.HandleFunc("/", loginPage)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/signup", signupPage)
	http.HandleFunc("/register", registerHandler)

	port := 8888
	fmt.Printf("Сервер запущен на порту %d\n", port)

	err = http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
	if err != nil {
		log.Fatal(err)
	}
}

func loginPage(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("login.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, nil)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	hashedPassword := getPasswordByUsername(username)
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		fmt.Fprintln(w, "Ошибка авторизации. Пожалуйста, проверьте имя пользователя и пароль.")
		return
	}

	fmt.Fprintln(w, "Авторизация успешна!")
}

func getPasswordByUsername(username string) string {
	var password string
	row := db.QueryRow("SELECT password FROM users WHERE username = $1", username)
	err := row.Scan(&password)
	if err != nil {
		log.Println(err)
		return ""
	}
	return password
}

func signupPage(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("signup.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, nil)
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	// Проверьте, существует ли уже пользователь с таким именем
	if userExists(username) {
		fmt.Fprintln(w, "Пользователь с таким именем уже существует.")
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	_, err = db.Exec("INSERT INTO users (username, password) VALUES ($1, $2)", username, string(hashedPassword))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Fprintln(w, "Регистрация успешна!")
}

func userExists(username string) bool {
	var count int
	row := db.QueryRow("SELECT COUNT(*) FROM users WHERE username = $1", username)
	err := row.Scan(&count)
	if err != nil {
		log.Println(err)
		return false
	}
	return count > 0
}
