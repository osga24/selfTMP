package app

import (
	"log"
	"os"
	"path/filepath"
	"strconv"
)

type Config struct {
	Port       string
	DataDir    string
	FilesDir   string
	DBPath     string
	AdminToken string
	MaxSize    int64
	BaseURL    string
}

func loadConfig() Config {
	c := Config{
		Port:       getenv("PORT", "8080"),
		DataDir:    getenv("DATA_DIR", "./data"),
		AdminToken: os.Getenv("ADMIN_TOKEN"),
		BaseURL:    os.Getenv("BASE_URL"),
	}
	if c.AdminToken == "" {
		log.Fatal("ADMIN_TOKEN environment variable is required")
	}
	max, err := strconv.ParseInt(getenv("MAX_SIZE", "104857600"), 10, 64)
	if err != nil || max <= 0 {
		max = 100 << 20
	}
	c.MaxSize = max
	c.FilesDir = filepath.Join(c.DataDir, "files")
	c.DBPath = filepath.Join(c.DataDir, "metadata.db")
	return c
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
