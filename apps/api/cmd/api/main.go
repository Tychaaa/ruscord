package main

import (
	"database/sql"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func main() {
	loadDotEnv(".env")
	cfg := Config{
		APIPort:     getenv("API_PORT", "8080"),
		CORSOrigins: getenv("CORS_ORIGINS", "http://localhost:5173"),
		DatabaseURL: mustGetenv("DATABASE_URL"),
		JWTSecret:   mustGetenv("JWT_SECRET"),
	}

	db, err := sql.Open("pgx", cfg.DatabaseURL)
	if err != nil {
		log.Fatal(err)
	}
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)

	if err := db.Ping(); err != nil {
		log.Fatal("db ping:", err)
	}

	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery())
	r.Use(corsMiddleware(cfg.CORSOrigins))

	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true, "ts": time.Now().UTC().Format(time.RFC3339)})
	})

	auth := r.Group("/auth")
	{
		auth.POST("/register", func(c *gin.Context) { handleRegister(c, db) })
		auth.POST("/login", func(c *gin.Context) { handleLogin(c, db, cfg.JWTSecret) })
		auth.POST("/refresh", func(c *gin.Context) { handleRefresh(c, db, cfg.JWTSecret) })
		auth.POST("/logout", func(c *gin.Context) { handleLogout(c, db) })
	}

	r.GET("/me", func(c *gin.Context) {
		uid, err := requireAuth(c, cfg.JWTSecret)
		if err != nil {
			return
		}
		var email, username string
		err = db.QueryRow(`SELECT email, username FROM users WHERE id=$1`, uid).Scan(&email, &username)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"id": uid, "email": email, "username": username})
	})

	// Users
	r.GET("/users/search", func(c *gin.Context) { handleUserSearch(c, db, cfg.JWTSecret) })

	// DM
	r.POST("/dm", func(c *gin.Context) { handleDMCreate(c, db, cfg.JWTSecret) })
	r.GET("/dm", func(c *gin.Context) { handleDMList(c, db, cfg.JWTSecret) })

	// Rooms
	r.POST("/rooms", func(c *gin.Context) { handleRoomCreate(c, db, cfg.JWTSecret) })
	r.GET("/rooms", func(c *gin.Context) { handleRoomList(c, db, cfg.JWTSecret) })
	r.POST("/rooms/join", func(c *gin.Context) { handleRoomJoin(c, db, cfg.JWTSecret) })

	// Messages
	r.POST("/dm/:id/messages", func(c *gin.Context) { handleDMMessageCreate(c, db, cfg.JWTSecret) })
	r.GET("/dm/:id/messages", func(c *gin.Context) { handleDMMessageList(c, db, cfg.JWTSecret) })
	r.POST("/rooms/:id/messages", func(c *gin.Context) { handleRoomMessageCreate(c, db, cfg.JWTSecret) })
	r.GET("/rooms/:id/messages", func(c *gin.Context) { handleRoomMessageList(c, db, cfg.JWTSecret) })

	// WebSocket
	r.GET("/ws", func(c *gin.Context) { handleWS(c, db, cfg.JWTSecret) })

	log.Printf("API listening on :%s", cfg.APIPort)
	if err := r.Run(":" + cfg.APIPort); err != nil {
		log.Fatal(err)
	}
}
