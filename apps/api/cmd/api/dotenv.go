package main

import (
	"bufio"
	"os"
	"strings"
)

func loadDotEnv(path string) {
	f, err := os.Open(path)
	if err != nil {
		return // .env не обязателен
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		v = strings.Trim(v, `"'`) // убираем кавычки если есть

		// не перетираем уже выставленные переменные
		if k != "" && os.Getenv(k) == "" {
			_ = os.Setenv(k, v)
		}
	}
}
