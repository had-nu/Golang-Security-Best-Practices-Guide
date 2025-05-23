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
