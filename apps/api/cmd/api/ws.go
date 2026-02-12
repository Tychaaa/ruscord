package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/gin-gonic/gin"
	"nhooyr.io/websocket"
)

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

/* ----------------------- WS Protocol ----------------------- */

type wsInMsg struct {
	Type    string  `json:"type"`             // "auth" | "subscribe"
	Token   string  `json:"token,omitempty"`  // auth
	DMIDs   []int64 `json:"dm_ids,omitempty"` // subscribe
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

/* ----------------------- WS Handler ----------------------- */

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

func handleWS(c *gin.Context, db *sql.DB, jwtSecret string) {
	conn, err := websocket.Accept(c.Writer, c.Request, &websocket.AcceptOptions{
		InsecureSkipVerify: true, // dev
	})
	if err != nil {
		return
	}
	defer conn.Close(websocket.StatusNormalClosure, "bye")

	// auth первым сообщением
	_, data, err := conn.Read(c.Request.Context())
	if err != nil {
		return
	}

	var in wsInMsg
	if err := json.Unmarshal(data, &in); err != nil || in.Type != "auth" || in.Token == "" {
		_ = conn.Close(websocket.StatusPolicyViolation, "auth required")
		return
	}

	uid, err := parseJWTUserID(in.Token, jwtSecret)
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

	ready := wsOutReady{Type: "ready", DMIDs: dmIDs, RoomIDs: roomIDs}
	b, _ := json.Marshal(ready)
	client.sendMu.Lock()
	_ = conn.Write(c.Request.Context(), websocket.MessageText, b)
	client.sendMu.Unlock()

	// дальше можно слать subscribe
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
}
