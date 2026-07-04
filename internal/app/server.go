package app

import (
	"context"
	"errors"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// Run boots the HTTP server. tplFS must contain templates/*.html and staticFS
// must contain static/* — both are provided by the caller (main.go) so the
// //go:embed directives can sit next to the template/static directories.
func Run(tplFS, staticFS fs.FS) {
	cfg := loadConfig()

	if err := os.MkdirAll(cfg.FilesDir, 0o755); err != nil {
		log.Fatalf("create data dir: %v", err)
	}
	db, err := openDB(cfg.DBPath)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer db.Close()

	tpl, err := template.ParseFS(tplFS, "templates/*.html")
	if err != nil {
		log.Fatalf("parse templates: %v", err)
	}

	srv := &Server{cfg: cfg, db: db, tpl: tpl}
	startJanitor(db)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", srv.handleIndex)
	mux.HandleFunc("POST /api/upload", srv.handleUpload)
	mux.HandleFunc("POST /api/paste", srv.handlePaste)
	mux.HandleFunc("POST /api/shorten", srv.handleShorten)
	mux.HandleFunc("GET /admin", srv.handleAdmin)
	mux.HandleFunc("GET /api/entries", srv.handleAPIList)
	mux.HandleFunc("DELETE /api/entries/{id}", srv.handleAPIDelete)
	mux.HandleFunc("GET /qr/{id}", srv.handleQR)
	mux.HandleFunc("GET /raw/{id}", srv.handleRaw)
	mux.HandleFunc("POST /{id}/unlock", srv.handleUnlock)
	mux.HandleFunc("GET /{id}", srv.handleView)
	mux.Handle("GET /static/", http.FileServer(http.FS(staticFS)))

	httpSrv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           logMiddleware(mux),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("selfTMP listening on :%s (data=%s, maxSize=%d bytes)",
			cfg.Port, cfg.DataDir, cfg.MaxSize)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Println("shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(ctx); err != nil {
		log.Printf("shutdown: %v", err)
	}
}

func logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		lrw := &loggingResponseWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(lrw, r)
		log.Printf("%s %s %d %s", r.Method, r.URL.Path, lrw.status, time.Since(start))
	})
}

type loggingResponseWriter struct {
	http.ResponseWriter
	status int
}

func (l *loggingResponseWriter) WriteHeader(code int) {
	l.status = code
	l.ResponseWriter.WriteHeader(code)
}
