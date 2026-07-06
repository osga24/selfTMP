package app

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type Server struct {
	cfg Config
	db  *sql.DB
	tpl *template.Template
}

// --- auth ----------------------------------------------------------------

func (s *Server) authOK(r *http.Request) bool {
	token := s.cfg.AdminToken
	check := func(v string) bool {
		return v != "" && subtle.ConstantTimeCompare([]byte(v), []byte(token)) == 1
	}
	if h := r.Header.Get("X-Admin-Token"); check(h) {
		return true
	}
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		if check(strings.TrimPrefix(h, "Bearer ")) {
			return true
		}
	}
	if check(r.URL.Query().Get("token")) {
		return true
	}
	// PostFormValue works after ParseForm/ParseMultipartForm.
	if check(r.PostFormValue("token")) {
		return true
	}
	return false
}

func (s *Server) requireAuth(w http.ResponseWriter, r *http.Request) bool {
	if s.authOK(r) {
		return true
	}
	writeError(w, r, http.StatusUnauthorized, "unauthorized")
	return false
}

// --- helpers -------------------------------------------------------------

func (s *Server) baseURL(r *http.Request) string {
	if s.cfg.BaseURL != "" {
		return strings.TrimRight(s.cfg.BaseURL, "/")
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if p := r.Header.Get("X-Forwarded-Proto"); p != "" {
		scheme = p
	}
	host := r.Host
	if h := r.Header.Get("X-Forwarded-Host"); h != "" {
		host = h
	}
	return scheme + "://" + host
}

// pickID returns the caller-supplied custom id if valid and available, or a
// random 6-char id when custom is empty. Returned errors are sentinel values
// (errSlugInvalid / errSlugTaken) so callers can pick the right HTTP status.
func (s *Server) pickID(custom string) (string, error) {
	custom = strings.TrimSpace(custom)
	if custom == "" {
		return newID(6), nil
	}
	if err := validateSlug(custom); err != nil {
		return "", err
	}
	if _, err := getEntry(s.db, custom); err == nil {
		return "", errSlugTaken
	}
	return custom, nil
}

func (s *Server) writeSlugError(w http.ResponseWriter, r *http.Request, err error) {
	code := http.StatusBadRequest
	if errors.Is(err, errSlugTaken) {
		code = http.StatusConflict
	}
	writeError(w, r, code, err.Error())
}

func parseExpiry(s string) int64 {
	s = strings.TrimSpace(s)
	if s == "" || s == "0" || s == "never" {
		return 0
	}
	if strings.HasSuffix(s, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err == nil && n > 0 {
			return time.Now().Add(time.Duration(n) * 24 * time.Hour).Unix()
		}
		return 0
	}
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		return time.Now().Add(d).Unix()
	}
	return 0
}

func wantsJSON(r *http.Request) bool {
	a := r.Header.Get("Accept")
	if strings.Contains(a, "application/json") {
		return true
	}
	// curl and other CLI clients rarely set Accept — infer from User-Agent.
	if !strings.Contains(a, "text/html") {
		return true
	}
	return false
}

func (s *Server) writeCreated(w http.ResponseWriter, r *http.Request, e *Entry) {
	u := s.baseURL(r) + "/" + e.ID
	resp := map[string]any{
		"id":  e.ID,
		"url": u,
	}
	if e.Kind == "paste" {
		resp["raw_url"] = s.baseURL(r) + "/raw/" + e.ID
	}
	if e.ExpiresAt > 0 {
		resp["expires_at"] = e.ExpiresAt
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

func writeError(w http.ResponseWriter, r *http.Request, code int, msg string) {
	if wantsJSON(r) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
		return
	}
	http.Error(w, msg, code)
}

// unlockCookieValue derives an HMAC used to remember a password unlock across
// requests. The admin token acts as the signing key; the value is bound to the
// entry ID and the current password hash so that changing the password
// invalidates prior unlocks.
func (s *Server) unlockCookieValue(id, pwHash string) string {
	mac := hmac.New(sha256.New, []byte(s.cfg.AdminToken))
	mac.Write([]byte(id + "|" + pwHash))
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *Server) hasValidUnlock(r *http.Request, e *Entry) bool {
	c, err := r.Cookie("unlock_" + e.ID)
	if err != nil {
		return false
	}
	want := s.unlockCookieValue(e.ID, e.PasswordHash)
	return subtle.ConstantTimeCompare([]byte(c.Value), []byte(want)) == 1
}

// --- index ---------------------------------------------------------------

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	_ = s.tpl.ExecuteTemplate(w, "index.html", map[string]any{
		"MaxSize": s.cfg.MaxSize,
	})
}

// --- upload (file) -------------------------------------------------------

func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxSize)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid upload: "+err.Error())
		return
	}
	if !s.requireAuth(w, r) {
		return
	}
	file, hdr, err := r.FormFile("file")
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "missing 'file' field")
		return
	}
	defer file.Close()

	id, err := s.pickID(r.FormValue("custom_id"))
	if err != nil {
		s.writeSlugError(w, r, err)
		return
	}
	if err := os.MkdirAll(s.cfg.FilesDir, 0o755); err != nil {
		writeError(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	path := filepath.Join(s.cfg.FilesDir, id)
	out, err := os.Create(path)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	n, copyErr := io.Copy(out, file)
	closeErr := out.Close()
	if copyErr != nil || closeErr != nil {
		os.Remove(path)
		msg := "write failed"
		if copyErr != nil {
			msg = copyErr.Error()
		} else {
			msg = closeErr.Error()
		}
		writeError(w, r, http.StatusInternalServerError, msg)
		return
	}

	ct := hdr.Header.Get("Content-Type")
	if ct == "" {
		ct = "application/octet-stream"
	}
	e := &Entry{
		ID:          id,
		Kind:        "file",
		Filename:    filepath.Base(hdr.Filename),
		ContentType: ct,
		StoragePath: path,
		Size:        n,
		OneTime:     truthy(r.FormValue("one_time")),
		ExpiresAt:   parseExpiry(r.FormValue("expires_in")),
		CreatedAt:   time.Now().Unix(),
	}
	if pw := r.FormValue("password"); pw != "" {
		h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
		if err != nil {
			os.Remove(path)
			writeError(w, r, http.StatusInternalServerError, err.Error())
			return
		}
		e.PasswordHash = string(h)
	}
	if err := insertEntry(s.db, e); err != nil {
		os.Remove(path)
		if isUniqueViolation(err) {
			s.writeSlugError(w, r, errSlugTaken)
			return
		}
		writeError(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeCreated(w, r, e)
}

// --- paste ---------------------------------------------------------------

func (s *Server) handlePaste(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxSize)
	if err := r.ParseForm(); err != nil {
		writeError(w, r, http.StatusBadRequest, err.Error())
		return
	}
	if !s.requireAuth(w, r) {
		return
	}
	content := r.FormValue("content")
	if strings.TrimSpace(content) == "" {
		writeError(w, r, http.StatusBadRequest, "empty content")
		return
	}
	id, err := s.pickID(r.FormValue("custom_id"))
	if err != nil {
		s.writeSlugError(w, r, err)
		return
	}
	e := &Entry{
		ID:        id,
		Kind:      "paste",
		Content:   content,
		Size:      int64(len(content)),
		OneTime:   truthy(r.FormValue("one_time")),
		ExpiresAt: parseExpiry(r.FormValue("expires_in")),
		CreatedAt: time.Now().Unix(),
	}
	if pw := r.FormValue("password"); pw != "" {
		h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, err.Error())
			return
		}
		e.PasswordHash = string(h)
	}
	if err := insertEntry(s.db, e); err != nil {
		if isUniqueViolation(err) {
			s.writeSlugError(w, r, errSlugTaken)
			return
		}
		writeError(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeCreated(w, r, e)
}

// --- shorten -------------------------------------------------------------

func (s *Server) handleShorten(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeError(w, r, http.StatusBadRequest, err.Error())
		return
	}
	if !s.requireAuth(w, r) {
		return
	}
	target := strings.TrimSpace(r.FormValue("url"))
	if target == "" {
		writeError(w, r, http.StatusBadRequest, "missing 'url' field")
		return
	}
	u, err := url.Parse(target)
	if err != nil || !u.IsAbs() || (u.Scheme != "http" && u.Scheme != "https") {
		writeError(w, r, http.StatusBadRequest, "invalid url (must be absolute http/https)")
		return
	}
	id, err := s.pickID(r.FormValue("custom_id"))
	if err != nil {
		s.writeSlugError(w, r, err)
		return
	}
	e := &Entry{
		ID:        id,
		Kind:      "url",
		Content:   target,
		ExpiresAt: parseExpiry(r.FormValue("expires_in")),
		CreatedAt: time.Now().Unix(),
	}
	if err := insertEntry(s.db, e); err != nil {
		if isUniqueViolation(err) {
			s.writeSlugError(w, r, errSlugTaken)
			return
		}
		writeError(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeCreated(w, r, e)
}

// --- view (dispatch) -----------------------------------------------------

func (s *Server) handleView(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	e, err := s.loadLiveEntry(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if e.PasswordHash != "" && !s.hasValidUnlock(r, e) {
		s.renderUnlock(w, r, id, "")
		return
	}
	s.serveEntry(w, r, e)
}

func (s *Server) handleRaw(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	e, err := s.loadLiveEntry(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if e.Kind != "paste" {
		http.Error(w, "not a paste", http.StatusBadRequest)
		return
	}
	if e.PasswordHash != "" && !s.hasValidUnlock(r, e) {
		http.Error(w, "password required", http.StatusUnauthorized)
		return
	}
	ok, err := claimDownload(s.db, e.ID)
	if err != nil || !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = io.WriteString(w, e.Content)
	if e.OneTime {
		_ = deleteEntry(s.db, e.ID)
	}
}

func (s *Server) loadLiveEntry(id string) (*Entry, error) {
	if id == "" {
		return nil, errors.New("empty id")
	}
	e, err := getEntry(s.db, id)
	if err != nil {
		return nil, err
	}
	if e.ExpiresAt > 0 && e.ExpiresAt < time.Now().Unix() {
		return nil, errors.New("expired")
	}
	return e, nil
}

func (s *Server) serveEntry(w http.ResponseWriter, r *http.Request, e *Entry) {
	switch e.Kind {
	case "url":
		ok, err := claimDownload(s.db, e.ID)
		if err != nil || !ok {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, e.Content, http.StatusFound)
		if e.OneTime {
			_ = deleteEntry(s.db, e.ID)
		}
	case "paste":
		ok, err := claimDownload(s.db, e.ID)
		if err != nil || !ok {
			http.NotFound(w, r)
			return
		}
		_ = s.tpl.ExecuteTemplate(w, "paste.html", map[string]any{
			"ID":        e.ID,
			"Content":   e.Content,
			"Size":      e.Size,
			"CreatedAt": time.Unix(e.CreatedAt, 0).Format(time.RFC3339),
			"OneTime":   e.OneTime,
		})
		if e.OneTime {
			_ = deleteEntry(s.db, e.ID)
		}
	case "file":
		s.serveFile(w, r, e)
	default:
		http.Error(w, "unknown entry kind", http.StatusInternalServerError)
	}
}

func (s *Server) serveFile(w http.ResponseWriter, r *http.Request, e *Entry) {
	ok, err := claimDownload(s.db, e.ID)
	if err != nil || !ok {
		http.NotFound(w, r)
		return
	}
	f, err := os.Open(e.StoragePath)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", e.ContentType)
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename*=UTF-8''%s`, url.PathEscape(e.Filename)))
	http.ServeContent(w, r, e.Filename, stat.ModTime(), f)
	if e.OneTime {
		_ = os.Remove(e.StoragePath)
		_ = deleteEntry(s.db, e.ID)
	}
}

// --- unlock (password) ---------------------------------------------------

func (s *Server) handleUnlock(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := r.ParseForm(); err != nil {
		writeError(w, r, http.StatusBadRequest, err.Error())
		return
	}
	e, err := s.loadLiveEntry(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if e.PasswordHash == "" {
		http.Redirect(w, r, "/"+id, http.StatusSeeOther)
		return
	}
	pw := r.FormValue("password")
	if bcrypt.CompareHashAndPassword([]byte(e.PasswordHash), []byte(pw)) != nil {
		s.renderUnlock(w, r, id, "Incorrect password")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "unlock_" + id,
		Value:    s.unlockCookieValue(id, e.PasswordHash),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   3600, // 1h grace window
	})
	http.Redirect(w, r, "/"+id, http.StatusSeeOther)
}

func (s *Server) renderUnlock(w http.ResponseWriter, r *http.Request, id, msg string) {
	w.WriteHeader(http.StatusUnauthorized)
	_ = s.tpl.ExecuteTemplate(w, "password.html", map[string]any{
		"ID":    id,
		"Error": msg,
	})
}

// --- admin ---------------------------------------------------------------

// handleAdmin serves the admin shell page. Authentication happens client-side
// via /api/entries, so the shell itself is public — it renders an empty page
// that JS populates once a token is available in localStorage.
func (s *Server) handleAdmin(w http.ResponseWriter, r *http.Request) {
	_ = s.tpl.ExecuteTemplate(w, "admin.html", nil)
}

// entryDTO is the JSON view of an entry returned by /api/entries. It omits
// storage_path and password_hash — those must never leak to the client.
type entryDTO struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	Filename    string `json:"filename,omitempty"`
	Preview     string `json:"preview,omitempty"`
	Size        int64  `json:"size"`
	OneTime     bool   `json:"one_time"`
	HasPassword bool   `json:"has_password"`
	Downloads   int64  `json:"downloads"`
	ExpiresAt   int64  `json:"expires_at"`
	CreatedAt   int64  `json:"created_at"`
}

func (s *Server) handleAPIList(w http.ResponseWriter, r *http.Request) {
	if !s.requireAuth(w, r) {
		return
	}
	entries, err := listEntries(s.db)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	now := time.Now().Unix()
	out := make([]entryDTO, 0, len(entries))
	for _, e := range entries {
		if e.ExpiresAt > 0 && e.ExpiresAt < now {
			continue
		}
		preview := ""
		switch e.Kind {
		case "url":
			preview = e.Content
		case "paste":
			preview = e.Content
			if len(preview) > 120 {
				preview = preview[:120] + "…"
			}
		case "file":
			preview = e.Filename
		}
		out = append(out, entryDTO{
			ID: e.ID, Kind: e.Kind, Filename: e.Filename, Preview: preview,
			Size: e.Size, OneTime: e.OneTime, HasPassword: e.PasswordHash != "",
			Downloads: e.Downloads, ExpiresAt: e.ExpiresAt, CreatedAt: e.CreatedAt,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func (s *Server) handleAPIDelete(w http.ResponseWriter, r *http.Request) {
	if !s.requireAuth(w, r) {
		return
	}
	id := r.PathValue("id")
	if e, err := getEntry(s.db, id); err == nil && e.StoragePath != "" {
		_ = os.Remove(e.StoragePath)
	}
	if err := deleteEntry(s.db, id); err != nil {
		writeError(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func truthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "on", "yes":
		return true
	}
	return false
}
