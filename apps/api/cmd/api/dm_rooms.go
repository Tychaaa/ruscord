package main

import (
	"crypto/rand"
	"database/sql"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

/* ------------------------- DM ------------------------- */

type dmCreateReq struct {
	UserID int64 `json:"user_id"`
}

type dmListItem struct {
	ID        int64      `json:"id"`
	OtherUser userPublic `json:"other_user"`
}

func handleDMCreate(c *gin.Context, db *sql.DB, jwtSecret string) {
	uid, err := requireAuth(c, jwtSecret)
	if err != nil {
		return
	}

	var req dmCreateReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.UserID <= 0 || req.UserID == uid {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user_id"})
		return
	}

	a, b := uid, req.UserID
	if a > b {
		a, b = b, a
	}

	var threadID int64
	err = db.QueryRow(
		`INSERT INTO dm_threads(user_a, user_b)
		 VALUES($1,$2)
		 ON CONFLICT (user_a, user_b) DO UPDATE
		   SET user_a = dm_threads.user_a
		 RETURNING id`,
		a, b,
	).Scan(&threadID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}

	var other userPublic
	err = db.QueryRow(`SELECT id, username, email FROM users WHERE id=$1`, req.UserID).
		Scan(&other.ID, &other.Username, &other.Email)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "other user not found"})
		return
	}

	c.JSON(http.StatusOK, dmListItem{ID: threadID, OtherUser: other})
}

func handleDMList(c *gin.Context, db *sql.DB, jwtSecret string) {
	uid, err := requireAuth(c, jwtSecret)
	if err != nil {
		return
	}

	rows, err := db.Query(
		`SELECT t.id,
		        u.id, u.username, u.email
		 FROM dm_threads t
		 JOIN users u ON u.id = CASE WHEN t.user_a=$1 THEN t.user_b ELSE t.user_a END
		 WHERE t.user_a=$1 OR t.user_b=$1
		 ORDER BY t.id DESC
		 LIMIT 100`, uid,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	defer rows.Close()

	out := make([]dmListItem, 0, 100)
	for rows.Next() {
		var item dmListItem
		if err := rows.Scan(&item.ID, &item.OtherUser.ID, &item.OtherUser.Username, &item.OtherUser.Email); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "db scan error"})
			return
		}
		out = append(out, item)
	}
	c.JSON(http.StatusOK, out)
}

func ensureDMParticipant(db *sql.DB, threadID, uid int64) error {
	var ok bool
	err := db.QueryRow(
		`SELECT EXISTS(
			SELECT 1 FROM dm_threads
			WHERE id=$1 AND (user_a=$2 OR user_b=$2)
		)`, threadID, uid,
	).Scan(&ok)
	if err != nil {
		return err
	}
	if !ok {
		return sql.ErrNoRows
	}
	return nil
}

/* ------------------------ ROOMS ------------------------ */

type roomCreateReq struct {
	Name string `json:"name"`
}

type roomJoinReq struct {
	Code string `json:"code"`
}

type roomItem struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	InviteCode string `json:"invite_code"`
	OwnerID    int64  `json:"owner_id"`
}

func handleRoomCreate(c *gin.Context, db *sql.DB, jwtSecret string) {
	uid, err := requireAuth(c, jwtSecret)
	if err != nil {
		return
	}

	var req roomCreateReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" || len(name) > 60 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid name"})
		return
	}

	var roomID int64
	var code string
	for i := 0; i < 8; i++ {
		code = generateInviteCode(6)
		err = db.QueryRow(
			`INSERT INTO rooms(name, owner_id, invite_code)
			 VALUES($1,$2,$3)
			 RETURNING id`,
			name, uid, code,
		).Scan(&roomID)
		if err == nil {
			break
		}
		if !isUniqueViolation(err) {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
			return
		}
	}
	if roomID == 0 {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate invite code"})
		return
	}

	_, err = db.Exec(`INSERT INTO room_members(room_id, user_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, roomID, uid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}

	c.JSON(http.StatusCreated, roomItem{ID: roomID, Name: name, InviteCode: code, OwnerID: uid})
}

func handleRoomList(c *gin.Context, db *sql.DB, jwtSecret string) {
	uid, err := requireAuth(c, jwtSecret)
	if err != nil {
		return
	}

	rows, err := db.Query(
		`SELECT r.id, r.name, r.invite_code, r.owner_id
		 FROM rooms r
		 JOIN room_members m ON m.room_id = r.id
		 WHERE m.user_id = $1
		 ORDER BY r.id DESC
		 LIMIT 100`, uid,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	defer rows.Close()

	out := make([]roomItem, 0, 100)
	for rows.Next() {
		var r roomItem
		if err := rows.Scan(&r.ID, &r.Name, &r.InviteCode, &r.OwnerID); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "db scan error"})
			return
		}
		out = append(out, r)
	}
	c.JSON(http.StatusOK, out)
}

func handleRoomJoin(c *gin.Context, db *sql.DB, jwtSecret string) {
	uid, err := requireAuth(c, jwtSecret)
	if err != nil {
		return
	}

	var req roomJoinReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	code := strings.TrimSpace(req.Code)
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "code is required"})
		return
	}

	var r roomItem
	err = db.QueryRow(`SELECT id, name, invite_code, owner_id FROM rooms WHERE invite_code=$1`, code).
		Scan(&r.ID, &r.Name, &r.InviteCode, &r.OwnerID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "room not found"})
		return
	}

	_, err = db.Exec(`INSERT INTO room_members(room_id, user_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, r.ID, uid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}

	c.JSON(http.StatusOK, r)
}

func ensureRoomMember(db *sql.DB, roomID, uid int64) error {
	var ok bool
	err := db.QueryRow(
		`SELECT EXISTS(
			SELECT 1 FROM room_members
			WHERE room_id=$1 AND user_id=$2
		)`, roomID, uid,
	).Scan(&ok)
	if err != nil {
		return err
	}
	if !ok {
		return sql.ErrNoRows
	}
	return nil
}

/* -------------------- helpers -------------------- */

func generateInviteCode(n int) string {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // без 0/O/1/I
	b := make([]byte, n)
	rnd := make([]byte, n)
	if _, err := rand.Read(rnd); err != nil {
		for i := range b {
			b[i] = alphabet[i%len(alphabet)]
		}
		return string(b)
	}
	for i := 0; i < n; i++ {
		b[i] = alphabet[int(rnd[i])%len(alphabet)]
	}
	return string(b)
}

func isUniqueViolation(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "duplicate key") || strings.Contains(msg, "unique constraint")
}
