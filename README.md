# Golang Security Best Practices Guide
This repository is a study-oriented project focused on secure coding and DevSecOps practices using the Go programming language. It is my personal structured notations designed to help students into secure software development practices with hands-on examples and real-world use cases.

Topics include input validation, authentication and authorization, cryptography, HTTP security, error handling, and more — all structured to promote clean, maintainable, and secure code. The content is continuously updated as part of my ongoing learning journey in offesive security. I will try to maintain it simple and clean.

Ideal for those who want to explore Go with a security-first mindset. So welcome!

## Table of Contents

1. [Project Structure](#project-structure)
2. [Input Validation and Sanitization](#input-validation-and-sanitization)
3. [Authentication and Authorization](#authentication-and-authorization)
4. [Database Security](#database-security)
5. [Cryptography and Hashing](#cryptography-and-hashing)
6. [HTTP Security](#http-security)
7. [Error Handling](#error-handling)
8. [Logging and Monitoring](#logging-and-monitoring)
9. [Configuration Management](#configuration-management)
10. [File Operations Security](#file-operations-security)

## Project Structure
### Recommended Directory Layout
```
myapp/
├── cmd/
│   └── server/
│       └── main.go
├── internal/
│   ├── auth/
│   ├── config/
│   ├── handlers/
│   ├── middleware/
│   ├── models/
│   └── utils/
├── pkg/
│   └── crypto/
├── configs/
├── migrations/
├── docs/
├── scripts/
└── go.mod
```

### Use Case 1: Basic Project Structure

```go
// cmd/server/main.go
package main

import (
    "context"
    "log"
    "net/http"
    "os"
    "os/signal"
    "syscall"
    "time"

    "myapp/internal/config"
    "myapp/internal/handlers"
    "myapp/internal/middleware"
)

func main() {
    cfg := config.Load()
    
    // Initialize router with middleware
    mux := http.NewServeMux()
    
    // Apply security middleware
    handler := middleware.SecurityHeaders(
        middleware.RateLimit(
            middleware.Logger(mux),
        ),
    )
    
    // Register routes
    handlers.RegisterRoutes(mux)
    
    server := &http.Server{
        Addr:         cfg.Port,
        Handler:      handler,
        ReadTimeout:  15 * time.Second,
        WriteTimeout: 15 * time.Second,
        IdleTimeout:  60 * time.Second,
    }
    
    // Graceful shutdown
    go func() {
        if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
            log.Fatalf("Server failed to start: %v", err)
        }
    }()
    
    quit := make(chan os.Signal, 1)
    signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
    <-quit
    
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    
    if err := server.Shutdown(ctx); err != nil {
        log.Fatalf("Server forced to shutdown: %v", err)
    }
}
```
## Input Validation and Sanitization

### Use Case 2: Request Validation

```go
// internal/models/user.go
package models

import (
    "errors"
    "net/mail"
    "regexp"
    "strings"
    "unicode/utf8"
)

type User struct {
    ID       int64  `json:"id"`
    Email    string `json:"email"`
    Username string `json:"username"`
    Password string `json:"-"` // Never expose in JSON
}

var (
    usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9_]{3,20}$`)
    
    ErrInvalidEmail    = errors.New("invalid email format")
    ErrInvalidUsername = errors.New("username must be 3-20 characters, alphanumeric and underscore only")
    ErrPasswordTooWeak = errors.New("password must be at least 8 characters")
)

func (u *User) Validate() error {
    // Email validation
    if _, err := mail.ParseAddress(u.Email); err != nil {
        return ErrInvalidEmail
    }
    
    // Username validation
    if !usernameRegex.MatchString(u.Username) {
        return ErrInvalidUsername
    }
    
    // Password validation
    if utf8.RuneCountInString(u.Password) < 8 {
        return ErrPasswordTooWeak
    }
    
    return nil
}

func (u *User) Sanitize() {
    u.Email = strings.TrimSpace(strings.ToLower(u.Email))
    u.Username = strings.TrimSpace(u.Username)
}
```
### Use Case 3: SQL Injection Prevention

```go
// internal/handlers/user.go
package handlers

import (
    "database/sql"
    "encoding/json"
    "net/http"
    "strconv"
    
    "myapp/internal/models"
    "github.com/gorilla/mux"
)

type UserHandler struct {
    db *sql.DB
}

func NewUserHandler(db *sql.DB) *UserHandler {
    return &UserHandler{db: db}
}

func (h *UserHandler) GetUser(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    userIDStr := vars["id"]
    
    // Validate input
    userID, err := strconv.ParseInt(userIDStr, 10, 64)
    if err != nil {
        http.Error(w, "Invalid user ID", http.StatusBadRequest)
        return
    }
    
    // Use parameterized queries to prevent SQL injection
    query := "SELECT id, email, username FROM users WHERE id = $1"
    var user models.User
    
    err = h.db.QueryRow(query, userID).Scan(&user.ID, &user.Email, &user.Username)
    if err != nil {
        if err == sql.ErrNoRows {
            http.Error(w, "User not found", http.StatusNotFound)
            return
        }
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(user)
}

func (h *UserHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
    var user models.User
    
    if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
        http.Error(w, "Invalid JSON", http.StatusBadRequest)
        return
    }
    
    // Sanitize and validate
    user.Sanitize()
    if err := user.Validate(); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    
    // Hash password before storing
    hashedPassword, err := hashPassword(user.Password)
    if err != nil {
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }
    
    // Use parameterized query
    query := `INSERT INTO users (email, username, password_hash) VALUES ($1, $2, $3) RETURNING id`
    err = h.db.QueryRow(query, user.Email, user.Username, hashedPassword).Scan(&user.ID)
    if err != nil {
        http.Error(w, "Failed to create user", http.StatusInternalServerError)
        return
    }
    
    user.Password = "" // Clear password from response
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusCreated)
    json.NewEncoder(w).Encode(user)
}
```

## Authentication and Authorization

### Use Case 4: JWT Authentication

```go
// internal/auth/jwt.go
package auth

import (
    "errors"
    "time"
    
    "github.com/golang-jwt/jwt/v5"
)

var (
    ErrInvalidToken = errors.New("invalid token")
    ErrTokenExpired = errors.New("token expired")
)

type Claims struct {
    UserID int64  `json:"user_id"`
    Role   string `json:"role"`
    jwt.RegisteredClaims
}

type JWTManager struct {
    secretKey     []byte
    tokenDuration time.Duration
}

func NewJWTManager(secretKey string, tokenDuration time.Duration) *JWTManager {
    return &JWTManager{
        secretKey:     []byte(secretKey),
        tokenDuration: tokenDuration,
    }
}

func (manager *JWTManager) Generate(userID int64, role string) (string, error) {
    claims := Claims{
        UserID: userID,
        Role:   role,
        RegisteredClaims: jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(time.Now().Add(manager.tokenDuration)),
            IssuedAt:  jwt.NewNumericDate(time.Now()),
            Issuer:    "myapp",
        },
    }
    
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString(manager.secretKey)
}

func (manager *JWTManager) Verify(tokenString string) (*Claims, error) {
    token, err := jwt.ParseWithClaims(
        tokenString,
        &Claims{},
        func(token *jwt.Token) (interface{}, error) {
            return manager.secretKey, nil
        },
    )
    
    if err != nil {
        return nil, ErrInvalidToken
    }
    
    claims, ok := token.Claims.(*Claims)
    if !ok || !token.Valid {
        return nil, ErrInvalidToken
    }
    
    return claims, nil
}
```

### Use Case 5: Authentication Middleware

```go
// internal/middleware/auth.go
package middleware

import (
    "context"
    "net/http"
    "strings"
    
    "myapp/internal/auth"
)

type contextKey string

const UserContextKey contextKey = "user"

func AuthMiddleware(jwtManager *auth.JWTManager) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            authHeader := r.Header.Get("Authorization")
            if authHeader == "" {
                http.Error(w, "Authorization header required", http.StatusUnauthorized)
                return
            }
            
            // Expected format: "Bearer <token>"
            parts := strings.Split(authHeader, " ")
            if len(parts) != 2 || parts[0] != "Bearer" {
                http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
                return
            }
            
            claims, err := jwtManager.Verify(parts[1])
            if err != nil {
                http.Error(w, "Invalid token", http.StatusUnauthorized)
                return
            }
            
            // Add user info to context
            ctx := context.WithValue(r.Context(), UserContextKey, claims)
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}

func RequireRole(role string) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            claims, ok := r.Context().Value(UserContextKey).(*auth.Claims)
            if !ok {
                http.Error(w, "Unauthorized", http.StatusUnauthorized)
                return
            }
            
            if claims.Role != role {
                http.Error(w, "Forbidden", http.StatusForbidden)
                return
            }
            
            next.ServeHTTP(w, r)
        })
    }
}
```

## Database Security

### Use Case 6: Database Connection with Security

```go
// internal/database/connection.go
package database

import (
    "database/sql"
    "fmt"
    "time"
    
    _ "github.com/lib/pq"
)

type Config struct {
    Host     string
    Port     int
    User     string
    Password string
    DBName   string
    SSLMode  string
}

func Connect(cfg Config) (*sql.DB, error) {
    // Build connection string with SSL
    dsn := fmt.Sprintf(
        "host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
        cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.DBName, cfg.SSLMode,
    )
    
    db, err := sql.Open("postgres", dsn)
    if err != nil {
        return nil, fmt.Errorf("failed to open database: %w", err)
    }
    
    // Configure connection pool
    db.SetMaxOpenConns(25)
    db.SetMaxIdleConns(5)
    db.SetConnMaxLifetime(5 * time.Minute)
    db.SetConnMaxIdleTime(1 * time.Minute)
    
    // Test connection
    if err := db.Ping(); err != nil {
        return nil, fmt.Errorf("failed to ping database: %w", err)
    }
    
    return db, nil
}
```

### Use Case 7: Secure Database Transactions

```go
// internal/repository/user.go
package repository

import (
    "database/sql"
    "fmt"
    
    "myapp/internal/models"
)

type UserRepository struct {
    db *sql.DB
}

func NewUserRepository(db *sql.DB) *UserRepository {
    return &UserRepository{db: db}
}

func (r *UserRepository) CreateUserWithProfile(user *models.User, profile *models.Profile) error {
    // Use transaction for data consistency
    tx, err := r.db.Begin()
    if err != nil {
        return fmt.Errorf("failed to begin transaction: %w", err)
    }
    
    defer func() {
        if err != nil {
            tx.Rollback()
        }
    }()
    
    // Insert user
    userQuery := `INSERT INTO users (email, username, password_hash) VALUES ($1, $2, $3) RETURNING id`
    err = tx.QueryRow(userQuery, user.Email, user.Username, user.Password).Scan(&user.ID)
    if err != nil {
        return fmt.Errorf("failed to create user: %w", err)
    }
    
    // Insert profile
    profileQuery := `INSERT INTO profiles (user_id, first_name, last_name) VALUES ($1, $2, $3)`
    _, err = tx.Exec(profileQuery, user.ID, profile.FirstName, profile.LastName)
    if err != nil {
        return fmt.Errorf("failed to create profile: %w", err)
    }
    
    if err = tx.Commit(); err != nil {
        return fmt.Errorf("failed to commit transaction: %w", err)
    }
    
    return nil
}

func (r *UserRepository) GetUserByEmail(email string) (*models.User, error) {
    query := `SELECT id, email, username, password_hash FROM users WHERE email = $1`
    
    var user models.User
    err := r.db.QueryRow(query, email).Scan(
        &user.ID, &user.Email, &user.Username, &user.Password,
    )
    
    if err != nil {
        if err == sql.ErrNoRows {
            return nil, nil
        }
        return nil, fmt.Errorf("failed to get user: %w", err)
    }
    
    return &user, nil
}
```



