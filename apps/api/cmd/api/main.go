package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	_ "github.com/jackc/pgx/v5/stdlib"
	"golang.org/x/crypto/argon2"
	"nhooyr.io/websocket"
)

type Config struct {
	APIPort     string
	CORSOrigins string
	DatabaseURL string
	JWTSecret   string
}

/* ----------------------- WS HUB ----------------------- */

type WSClient struct {
	conn   *websocket.Conn
	uid    int64
	sendMu sync.Mutex
}

type Hub struct {
	mu   sync.RWMutex
	subs map[string]map[*WSClient]struct{}
}

func NewHub() *Hub {
	return &Hub{subs: make(map[string]map[*WSClient]struct{})}
}

func (h *Hub) Subscribe(topic string, c *WSClient) {
	h.mu.Lock()
	defer h.mu.Unlock()
	m, ok := h.subs[topic]
	if !ok {
		m = make(map[*WSClient]struct{})
		h.subs[topic] = m
	}
	m[c] = struct{}{}
}

func (h *Hub) UnsubscribeAll(c *WSClient) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for topic, m := range h.subs {
		delete(m, c)
		if len(m) == 0 {
			delete(h.subs, topic)
		}
	}
}

func (h *Hub) Broadcast(topic string, v any) {
	h.mu.RLock()
	clientsMap := h.subs[topic]
	clients := make([]*WSClient, 0, len(clientsMap))
	for c := range clientsMap {
		clients = append(clients, c)
	}
	h.mu.RUnlock()

	if len(clients) == 0 {
		return
	}

	b, err := json.Marshal(v)
	if err != nil {
		return
	}

	for _, c := range clients {
		c.sendMu.Lock()
		_ = c.conn.Write(context.Background(), websocket.MessageText, b)
		c.sendMu.Unlock()
	}
}

var wsHub = NewHub()

type wsInMsg struct {
	Type    string  `json:"type"`             // "auth" | "subscribe"
	Token   string  `json:"token,omitempty"`  // для auth
	DMIDs   []int64 `json:"dm_ids,omitempty"` // для subscribe
	RoomIDs []int64 `json:"room_ids,omitempty"`
}

type wsOutReady struct {
	Type    string  `json:"type"` // "ready"
	DMIDs   []int64 `json:"dm_ids"`
	RoomIDs []int64 `json:"room_ids"`
}

type wsOutTarget struct {
	Kind string `json:"kind"` // "dm" | "room"
	ID   int64  `json:"id"`
}

type wsOutMessageNew struct {
	Type    string      `json:"type"` // "message:new"
	Target  wsOutTarget `json:"target"`
	Message messageItem `json:"message"`
}

func parseAccessToken(tokenStr, secret string) (int64, error) {
	tok, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(secret), nil
	})
	if err != nil || !tok.Valid {
		return 0, errors.New("invalid token")
	}

	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		return 0, errors.New("bad claims")
	}

	sub, _ := claims["sub"].(string)
	return strconv.ParseInt(sub, 10, 64)
}

func loadUserTopics(ctx context.Context, db *sql.DB, uid int64) (dmIDs []int64, roomIDs []int64) {
	dmRows, err := db.QueryContext(ctx, `SELECT id FROM dm_threads WHERE user_a=$1 OR user_b=$1`, uid)
	if err == nil {
		defer dmRows.Close()
		for dmRows.Next() {
			var id int64
			if dmRows.Scan(&id) == nil {
				dmIDs = append(dmIDs, id)
			}
		}
	}

	roomRows, err := db.QueryContext(ctx, `SELECT room_id FROM room_members WHERE user_id=$1`, uid)
	if err == nil {
		defer roomRows.Close()
		for roomRows.Next() {
			var id int64
			if roomRows.Scan(&id) == nil {
				roomIDs = append(roomIDs, id)
			}
		}
	}
	return
}

/* ----------------------- MAIN ----------------------- */

func main() {
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

	// Users (поиск)
	r.GET("/users/search", func(c *gin.Context) { handleUserSearch(c, db, cfg.JWTSecret) })

	// DM
	r.POST("/dm", func(c *gin.Context) { handleDMCreate(c, db, cfg.JWTSecret) })
	r.GET("/dm", func(c *gin.Context) { handleDMList(c, db, cfg.JWTSecret) })

	// Rooms
	r.POST("/rooms", func(c *gin.Context) { handleRoomCreate(c, db, cfg.JWTSecret) })
	r.GET("/rooms", func(c *gin.Context) { handleRoomList(c, db, cfg.JWTSecret) })
	r.POST("/rooms/join", func(c *gin.Context) { handleRoomJoin(c, db, cfg.JWTSecret) })

	// DM messages
	r.POST("/dm/:id/messages", func(c *gin.Context) { handleDMMessageCreate(c, db, cfg.JWTSecret) })
	r.GET("/dm/:id/messages", func(c *gin.Context) { handleDMMessageList(c, db, cfg.JWTSecret) })

	// Room messages
	r.POST("/rooms/:id/messages", func(c *gin.Context) { handleRoomMessageCreate(c, db, cfg.JWTSecret) })
	r.GET("/rooms/:id/messages", func(c *gin.Context) { handleRoomMessageList(c, db, cfg.JWTSecret) })

	// WebSocket: realtime события (message:new)
	r.GET("/ws", func(c *gin.Context) {
		conn, err := websocket.Accept(c.Writer, c.Request, &websocket.AcceptOptions{
			InsecureSkipVerify: true, // dev
		})
		if err != nil {
			return
		}
		defer conn.Close(websocket.StatusNormalClosure, "bye")

		// ждём auth первым сообщением
		_, data, err := conn.Read(c.Request.Context())
		if err != nil {
			return
		}

		var in wsInMsg
		if err := json.Unmarshal(data, &in); err != nil || in.Type != "auth" || in.Token == "" {
			_ = conn.Close(websocket.StatusPolicyViolation, "auth required")
			return
		}

		uid, err := parseAccessToken(in.Token, cfg.JWTSecret)
		if err != nil {
			_ = conn.Close(websocket.StatusPolicyViolation, "invalid token")
			return
		}

		client := &WSClient{conn: conn, uid: uid}
		defer wsHub.UnsubscribeAll(client)

		// авто-подписка на все DM/Rooms пользователя
		dmIDs, roomIDs := loadUserTopics(c.Request.Context(), db, uid)
		for _, id := range dmIDs {
			wsHub.Subscribe(fmt.Sprintf("dm:%d", id), client)
		}
		for _, id := range roomIDs {
			wsHub.Subscribe(fmt.Sprintf("room:%d", id), client)
		}

		// отправляем ready
		ready := wsOutReady{Type: "ready", DMIDs: dmIDs, RoomIDs: roomIDs}
		b, _ := json.Marshal(ready)
		client.sendMu.Lock()
		_ = conn.Write(c.Request.Context(), websocket.MessageText, b)
		client.sendMu.Unlock()

		// read-loop (subscribe по желанию)
		for {
			_, data, err := conn.Read(c.Request.Context())
			if err != nil {
				return
			}
			var msg wsInMsg
			if err := json.Unmarshal(data, &msg); err != nil {
				continue
			}
			if msg.Type == "subscribe" {
				for _, id := range msg.DMIDs {
					wsHub.Subscribe(fmt.Sprintf("dm:%d", id), client)
				}
				for _, id := range msg.RoomIDs {
					wsHub.Subscribe(fmt.Sprintf("room:%d", id), client)
				}
			}
		}
	})

	log.Printf("API listening on :%s", cfg.APIPort)
	if err := r.Run(":" + cfg.APIPort); err != nil {
		log.Fatal(err)
	}
}

/* ----------------------- AUTH ----------------------- */

type registerReq struct {
	Email    string `json:"email"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func handleRegister(c *gin.Context, db *sql.DB) {
	var req registerReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	req.Username = strings.TrimSpace(req.Username)

	if req.Email == "" || req.Username == "" || len(req.Password) < 6 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid input"})
		return
	}

	hash, err := hashPassword(req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "hash failed"})
		return
	}

	var id int64
	err = db.QueryRow(
		`INSERT INTO users(email, username, password_hash) VALUES($1,$2,$3) RETURNING id`,
		req.Email, req.Username, hash,
	).Scan(&id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "email already used?"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"id": id})
}

type loginReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func handleLogin(c *gin.Context, db *sql.DB, jwtSecret string) {
	var req loginReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	email := strings.TrimSpace(strings.ToLower(req.Email))

	var uid int64
	var passHash string
	err := db.QueryRow(`SELECT id, password_hash FROM users WHERE email=$1`, email).Scan(&uid, &passHash)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}
	if !verifyPassword(req.Password, passHash) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	access, err := makeAccessToken(uid, jwtSecret, 15*time.Minute)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "token error"})
		return
	}

	refreshRaw, refreshHash, err := newRefreshToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "token error"})
		return
	}
	expires := time.Now().Add(30 * 24 * time.Hour)

	_, err = db.Exec(`INSERT INTO sessions(user_id, refresh_hash, expires_at) VALUES($1,$2,$3)`, uid, refreshHash, expires)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "session error"})
		return
	}

	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshRaw,
		Path:     "/auth/refresh",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  expires,
	})

	c.JSON(http.StatusOK, gin.H{"access_token": access})
}

func handleRefresh(c *gin.Context, db *sql.DB, jwtSecret string) {
	cookie, err := c.Request.Cookie("refresh_token")
	if err != nil || cookie.Value == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "no refresh token"})
		return
	}
	raw := cookie.Value
	hash := sha256Hex(raw)

	var sid int64
	var uid int64
	var expires time.Time
	err = db.QueryRow(`SELECT id, user_id, expires_at FROM sessions WHERE refresh_hash=$1`, hash).Scan(&sid, &uid, &expires)
	if err != nil || time.Now().After(expires) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh"})
		return
	}

	_, _ = db.Exec(`DELETE FROM sessions WHERE id=$1`, sid)

	newRaw, newHash, err := newRefreshToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "token error"})
		return
	}
	newExpires := time.Now().Add(30 * 24 * time.Hour)
	_, err = db.Exec(`INSERT INTO sessions(user_id, refresh_hash, expires_at) VALUES($1,$2,$3)`, uid, newHash, newExpires)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "session error"})
		return
	}

	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "refresh_token",
		Value:    newRaw,
		Path:     "/auth/refresh",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  newExpires,
	})

	access, err := makeAccessToken(uid, jwtSecret, 15*time.Minute)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "token error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"access_token": access})
}

func handleLogout(c *gin.Context, db *sql.DB) {
	cookie, err := c.Request.Cookie("refresh_token")
	if err == nil && cookie.Value != "" {
		_, _ = db.Exec(`DELETE FROM sessions WHERE refresh_hash=$1`, sha256Hex(cookie.Value))
	}
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Path:     "/auth/refresh",
		HttpOnly: true,
		MaxAge:   -1,
	})
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func requireAuth(c *gin.Context, secret string) (int64, error) {
	h := c.GetHeader("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing bearer token"})
		return 0, errors.New("no bearer")
	}
	tokenStr := strings.TrimPrefix(h, "Bearer ")

	tok, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(secret), nil
	})
	if err != nil || !tok.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		return 0, err
	}

	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		return 0, errors.New("bad claims")
	}

	sub, _ := claims["sub"].(string)
	uid, err := strconv.ParseInt(sub, 10, 64)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		return 0, err
	}
	return uid, nil
}

func makeAccessToken(uid int64, secret string, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub": strconv.FormatInt(uid, 10),
		"iat": now.Unix(),
		"exp": now.Add(ttl).Unix(),
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return t.SignedString([]byte(secret))
}

func newRefreshToken() (raw string, hash string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", "", err
	}
	raw = base64.RawURLEncoding.EncodeToString(b)
	hash = sha256Hex(raw)
	return raw, hash, nil
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

/* ----------------------- USERS / DM / ROOMS ----------------------- */

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

	otherID := req.UserID
	var other userPublic
	err = db.QueryRow(`SELECT id, username, email FROM users WHERE id=$1`, otherID).
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

/* ------------------------ MESSAGES ------------------------ */

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

/* ----------------- PASSWORD HASH (argon2id) ----------------- */

func hashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	timeCost := uint32(3)
	memCost := uint32(64 * 1024) // 64MB
	threads := uint8(1)
	keyLen := uint32(32)

	key := argon2.IDKey([]byte(password), salt, timeCost, memCost, threads, keyLen)
	return "a2id$" +
		base64.RawURLEncoding.EncodeToString(salt) + "$" +
		base64.RawURLEncoding.EncodeToString(key), nil
}

func verifyPassword(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 3 || parts[0] != "a2id" {
		return false
	}
	salt, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	hash, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}

	timeCost := uint32(3)
	memCost := uint32(64 * 1024)
	threads := uint8(1)
	keyLen := uint32(len(hash))

	key := argon2.IDKey([]byte(password), salt, timeCost, memCost, threads, keyLen)
	return subtleEqual(key, hash)
}

func subtleEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

/* ----------------------- UTILS ----------------------- */

func getenv(k, def string) string {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return def
	}
	return v
}

func mustGetenv(k string) string {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		log.Fatal("missing env: " + k)
	}
	return v
}

func corsMiddleware(origins string) gin.HandlerFunc {
	allowed := map[string]bool{}
	for _, o := range strings.Split(origins, ",") {
		o = strings.TrimSpace(o)
		if o != "" {
			allowed[o] = true
		}
	}
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if origin != "" && (allowed["*"] || allowed[origin]) {
			c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
			c.Writer.Header().Set("Vary", "Origin")
			c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
			c.Writer.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			c.Writer.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
		}
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	}
}
