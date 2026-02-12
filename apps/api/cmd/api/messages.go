package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type messageCreateReq struct {
	Content string `json:"content"`
}

type messageItem struct {
	ID        int64     `json:"id"`
	Content   string    `json:"content"`
	CreatedAt time.Time `json:"created_at"`
	Author    struct {
		ID       int64  `json:"id"`
		Username string `json:"username"`
	} `json:"author"`
}

func parseIDParam(c *gin.Context, name string) (int64, bool) {
	v := c.Param(name)
	id, err := strconv.ParseInt(v, 10, 64)
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return 0, false
	}
	return id, true
}

func parseLimitBefore(c *gin.Context) (limit int, before int64) {
	limit = 50
	before = int64(^uint64(0) >> 1) // max int64

	if l := strings.TrimSpace(c.Query("limit")); l != "" {
		if n, err := strconv.Atoi(l); err == nil {
			if n < 1 {
				n = 1
			}
			if n > 100 {
				n = 100
			}
			limit = n
		}
	}
	if b := strings.TrimSpace(c.Query("before")); b != "" {
		if n, err := strconv.ParseInt(b, 10, 64); err == nil && n > 0 {
			before = n
		}
	}
	return
}

/* ---------------- DM messages ---------------- */

func handleDMMessageCreate(c *gin.Context, db *sql.DB, jwtSecret string) {
	uid, err := requireAuth(c, jwtSecret)
	if err != nil {
		return
	}
	threadID, ok := parseIDParam(c, "id")
	if !ok {
		return
	}
	if err := ensureDMParticipant(db, threadID, uid); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "dm not found"})
		return
	}

	var req messageCreateReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	content := strings.TrimSpace(req.Content)
	if content == "" || len(content) > 4000 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid content"})
		return
	}

	var msg messageItem
	err = db.QueryRow(
		`WITH ins AS (
			INSERT INTO messages(dm_thread_id, author_id, content)
			VALUES ($1,$2,$3)
			RETURNING id, content, created_at, author_id
		)
		SELECT ins.id, ins.content, ins.created_at, u.id, u.username
		FROM ins JOIN users u ON u.id = ins.author_id`,
		threadID, uid, content,
	).Scan(&msg.ID, &msg.Content, &msg.CreatedAt, &msg.Author.ID, &msg.Author.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}

	wsHub.Broadcast(fmt.Sprintf("dm:%d", threadID), wsOutMessageNew{
		Type:    "message:new",
		Target:  wsOutTarget{Kind: "dm", ID: threadID},
		Message: msg,
	})

	c.JSON(http.StatusCreated, msg)
}

func handleDMMessageList(c *gin.Context, db *sql.DB, jwtSecret string) {
	uid, err := requireAuth(c, jwtSecret)
	if err != nil {
		return
	}
	threadID, ok := parseIDParam(c, "id")
	if !ok {
		return
	}
	if err := ensureDMParticipant(db, threadID, uid); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "dm not found"})
		return
	}

	limit, before := parseLimitBefore(c)

	rows, err := db.Query(
		`SELECT x.id, x.content, x.created_at, u.id, u.username
		 FROM (
			SELECT id, content, created_at, author_id
			FROM messages
			WHERE dm_thread_id=$1 AND id < $2
			ORDER BY id DESC
			LIMIT $3
		 ) x
		 JOIN users u ON u.id = x.author_id
		 ORDER BY x.id ASC`,
		threadID, before, limit,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	defer rows.Close()

	out := make([]messageItem, 0, limit)
	for rows.Next() {
		var m messageItem
		if err := rows.Scan(&m.ID, &m.Content, &m.CreatedAt, &m.Author.ID, &m.Author.Username); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "db scan error"})
			return
		}
		out = append(out, m)
	}
	c.JSON(http.StatusOK, out)
}

/* --------------- Room messages --------------- */

func handleRoomMessageCreate(c *gin.Context, db *sql.DB, jwtSecret string) {
	uid, err := requireAuth(c, jwtSecret)
	if err != nil {
		return
	}
	roomID, ok := parseIDParam(c, "id")
	if !ok {
		return
	}
	if err := ensureRoomMember(db, roomID, uid); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "room not found"})
		return
	}

	var req messageCreateReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	content := strings.TrimSpace(req.Content)
	if content == "" || len(content) > 4000 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid content"})
		return
	}

	var msg messageItem
	err = db.QueryRow(
		`WITH ins AS (
			INSERT INTO messages(room_id, author_id, content)
			VALUES ($1,$2,$3)
			RETURNING id, content, created_at, author_id
		)
		SELECT ins.id, ins.content, ins.created_at, u.id, u.username
		FROM ins JOIN users u ON u.id = ins.author_id`,
		roomID, uid, content,
	).Scan(&msg.ID, &msg.Content, &msg.CreatedAt, &msg.Author.ID, &msg.Author.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}

	wsHub.Broadcast(fmt.Sprintf("room:%d", roomID), wsOutMessageNew{
		Type:    "message:new",
		Target:  wsOutTarget{Kind: "room", ID: roomID},
		Message: msg,
	})

	c.JSON(http.StatusCreated, msg)
}

func handleRoomMessageList(c *gin.Context, db *sql.DB, jwtSecret string) {
	uid, err := requireAuth(c, jwtSecret)
	if err != nil {
		return
	}
	roomID, ok := parseIDParam(c, "id")
	if !ok {
		return
	}
	if err := ensureRoomMember(db, roomID, uid); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "room not found"})
		return
	}

	limit, before := parseLimitBefore(c)

	rows, err := db.Query(
		`SELECT x.id, x.content, x.created_at, u.id, u.username
		 FROM (
			SELECT id, content, created_at, author_id
			FROM messages
			WHERE room_id=$1 AND id < $2
			ORDER BY id DESC
			LIMIT $3
		 ) x
		 JOIN users u ON u.id = x.author_id
		 ORDER BY x.id ASC`,
		roomID, before, limit,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	defer rows.Close()

	out := make([]messageItem, 0, limit)
	for rows.Next() {
		var m messageItem
		if err := rows.Scan(&m.ID, &m.Content, &m.CreatedAt, &m.Author.ID, &m.Author.Username); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "db scan error"})
			return
		}
		out = append(out, m)
	}
	c.JSON(http.StatusOK, out)
}
