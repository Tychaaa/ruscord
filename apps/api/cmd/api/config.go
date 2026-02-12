package main

import (
	"log"
	"os"
	"strings"
)

type Config struct {
	APIPort     string
	CORSOrigins string
	DatabaseURL string
	JWTSecret   string
}

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
