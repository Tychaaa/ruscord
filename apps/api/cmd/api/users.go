package main

import (
	"database/sql"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

type userPublic struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
}

func handleUserSearch(c *gin.Context, db *sql.DB, jwtSecret string) {
	_, err := requireAuth(c, jwtSecret)
	if err != nil {
		return
	}

	q := strings.TrimSpace(c.Query("q"))
	if q == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "q is required"})
		return
	}
	pat := "%" + q + "%"

	rows, err := db.Query(
		`SELECT id, username, email
		 FROM users
		 WHERE username ILIKE $1 OR email ILIKE $1
		 ORDER BY username
		 LIMIT 20`, pat,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	defer rows.Close()

	out := make([]userPublic, 0, 20)
	for rows.Next() {
		var u userPublic
		if err := rows.Scan(&u.ID, &u.Username, &u.Email); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "db scan error"})
			return
		}
		out = append(out, u)
	}
	c.JSON(http.StatusOK, out)
}
