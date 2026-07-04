package main

import (
	"embed"

	"selfTMP/internal/app"
)

//go:embed templates/*.html
var tplFS embed.FS

//go:embed static/*
var staticFS embed.FS

func main() {
	app.Run(tplFS, staticFS)
}
