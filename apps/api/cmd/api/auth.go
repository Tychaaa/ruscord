package main

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/argon2"
)

/* ----------------------- AUTH HTTP ----------------------- */

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
	if err != nil || !verifyPassword(req.Password, passHash) {
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

	// rotation
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

/* ----------------------- JWT ----------------------- */

func parseJWTUserID(tokenStr, secret string) (int64, error) {
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

func requireAuth(c *gin.Context, secret string) (int64, error) {
	h := c.GetHeader("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing bearer token"})
		return 0, errors.New("no bearer")
	}

	tokenStr := strings.TrimPrefix(h, "Bearer ")
	uid, err := parseJWTUserID(tokenStr, secret)
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

/* ----------------------- REFRESH TOKENS ----------------------- */

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
