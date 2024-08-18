package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

// User represents a user in the system
type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"password,omitempty"`
}

// Question represents a single question in the quiz
type Question struct {
	ID            int    `json:"id"`
	Text          string `json:"text"`
	Options       string `json:"options"`
	CorrectAnswer int    `json:"correctAnswer"`
}

// UserScore represents a user's score for a quiz
type UserScore struct {
	ID     int       `json:"id"`
	UserID int       `json:"userId"`
	Score  int       `json:"score"`
	Date   time.Time `json:"date"`
}

var db *sql.DB
var jwtKey = []byte("your_secret_key") // Replace with a secure secret key

func main() {
	var err error
	db, err = sql.Open("sqlite3", "./quiz.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	createTables()

	router := mux.NewRouter()

	router.HandleFunc("/signup", signup).Methods("POST")
	router.HandleFunc("/login", login).Methods("POST")
	router.HandleFunc("/questions", authMiddleware(getQuestions)).Methods("GET")
	router.HandleFunc("/questions", authMiddleware(addQuestion)).Methods("POST")
	router.HandleFunc("/questions/{id}", authMiddleware(updateQuestion)).Methods("PUT")
	router.HandleFunc("/questions/{id}", authMiddleware(deleteQuestion)).Methods("DELETE")
	router.HandleFunc("/submit-score", authMiddleware(submitScore)).Methods("POST")
	router.HandleFunc("/user-scores", authMiddleware(getUserScores)).Methods("GET")
	router.HandleFunc("/deduct-points", authMiddleware(deductPoints)).Methods("POST")

	log.Fatal(http.ListenAndServe(":8080", router))
}

func createTables() {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			password TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS questions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			text TEXT NOT NULL,
			options TEXT NOT NULL,
			correctAnswer INTEGER NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS user_scores (
    	id INTEGER PRIMARY KEY AUTOINCREMENT,
    	user_id INTEGER NOT NULL UNIQUE,
    	score INTEGER NOT NULL,
    	date DATETIME DEFAULT CURRENT_TIMESTAMP,
    	FOREIGN KEY (user_id) REFERENCES users (id)
		);`,
	}

	for _, query := range queries {
		_, err := db.Exec(query)
		if err != nil {
			log.Fatal(err)
		}
	}
}

func signup(w http.ResponseWriter, r *http.Request) {
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	result, err := db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", user.Username, string(hashedPassword))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	id, _ := result.LastInsertId()
	user.ID = int(id)
	user.Password = "" // Don't send password back

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(user)
}

func login(w http.ResponseWriter, r *http.Request) {
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var dbUser User
	err = db.QueryRow("SELECT id, username, password FROM users WHERE username = ?", user.Username).Scan(&dbUser.ID, &dbUser.Username, &dbUser.Password)
	if err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(dbUser.Password), []byte(user.Password))
	if err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userId": dbUser.ID,
		"exp":    time.Now().Add(time.Hour * 24).Unix(),
	})

	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Missing authorization token", http.StatusUnauthorized)
			return
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			http.Error(w, "Invalid token claims", http.StatusUnauthorized)
			return
		}

		userId := int(claims["userId"].(float64))
		r.Header.Set("UserId", strconv.Itoa(userId))

		next.ServeHTTP(w, r)
	}
}

func submitScore(w http.ResponseWriter, r *http.Request) {
	var score UserScore
	err := json.NewDecoder(r.Body).Decode(&score)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	userIdStr := r.Header.Get("UserId")
	userId, _ := strconv.Atoi(userIdStr)

	var currentScore int
	err = db.QueryRow("SELECT score FROM user_scores WHERE user_id = ?", userId).Scan(&currentScore)
	if err != nil && err != sql.ErrNoRows {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	newScore := currentScore + score.Score

	if err == sql.ErrNoRows {
		_, err = db.Exec("INSERT INTO user_scores (user_id, score) VALUES (?, ?)", userId, newScore)
	} else {
		_, err = db.Exec("UPDATE user_scores SET score = ?, date = CURRENT_TIMESTAMP WHERE user_id = ?", newScore, userId)
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	score.ID = 0 // We don't need to return the ID
	score.UserID = userId
	score.Score = newScore

	json.NewEncoder(w).Encode(score)
}

func deductPoints(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Points int `json:"points"`
	}
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	userIdStr := r.Header.Get("UserId")
	userId, _ := strconv.Atoi(userIdStr)

	var currentPoints int
	err = db.QueryRow("SELECT score FROM user_scores WHERE user_id = ?", userId).Scan(&currentPoints)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if currentPoints < request.Points {
		http.Error(w, "Insufficient points", http.StatusBadRequest)
		return
	}

	newTotalPoints := currentPoints - request.Points
	_, err = db.Exec("UPDATE user_scores SET score = ? WHERE user_id = ?", newTotalPoints, userId)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]int{"newTotalPoints": newTotalPoints})
}

func getUserScores(w http.ResponseWriter, r *http.Request) {
	userIdStr := r.Header.Get("UserId")
	userId, _ := strconv.Atoi(userIdStr)

	var score UserScore
	err := db.QueryRow("SELECT id, score, date FROM user_scores WHERE user_id = ?", userId).Scan(&score.ID, &score.Score, &score.Date)
	if err == sql.ErrNoRows {
		// If no score found, return an empty score
		score = UserScore{UserID: userId, Score: 0, Date: time.Now()}
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	score.UserID = userId

	json.NewEncoder(w).Encode(score)
}

func getQuestions(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT id, text, options, correctAnswer FROM questions")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var questions []Question
	for rows.Next() {
		var q Question
		err := rows.Scan(&q.ID, &q.Text, &q.Options, &q.CorrectAnswer)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		questions = append(questions, q)
	}

	json.NewEncoder(w).Encode(questions)
}

func addQuestion(w http.ResponseWriter, r *http.Request) {
	var q Question
	err := json.NewDecoder(r.Body).Decode(&q)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	result, err := db.Exec("INSERT INTO questions (text, options, correctAnswer) VALUES (?, ?, ?)",
		q.Text, q.Options, q.CorrectAnswer)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	id, _ := result.LastInsertId()
	q.ID = int(id)

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(q)
}

func updateQuestion(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	id, err := strconv.Atoi(params["id"])
	if err != nil {
		http.Error(w, "Invalid question ID", http.StatusBadRequest)
		return
	}

	var q Question
	err = json.NewDecoder(r.Body).Decode(&q)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	_, err = db.Exec("UPDATE questions SET text = ?, options = ?, correctAnswer = ? WHERE id = ?",
		q.Text, q.Options, q.CorrectAnswer, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	q.ID = id
	json.NewEncoder(w).Encode(q)
}

func deleteQuestion(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	id, err := strconv.Atoi(params["id"])
	if err != nil {
		http.Error(w, "Invalid question ID", http.StatusBadRequest)
		return
	}

	_, err = db.Exec("DELETE FROM questions WHERE id = ?", id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
