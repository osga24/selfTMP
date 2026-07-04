package app

import (
	"database/sql"
	"strings"

	_ "modernc.org/sqlite"
)

// isUniqueViolation detects the SQLite "UNIQUE constraint failed" error. We
// match by message rather than importing the driver-specific error type so the
// caller stays independent of the sqlite package.
func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

const schema = `
CREATE TABLE IF NOT EXISTS entries (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    filename TEXT NOT NULL DEFAULT '',
    content_type TEXT NOT NULL DEFAULT '',
    storage_path TEXT NOT NULL DEFAULT '',
    content TEXT NOT NULL DEFAULT '',
    size INTEGER NOT NULL DEFAULT 0,
    password_hash TEXT NOT NULL DEFAULT '',
    one_time INTEGER NOT NULL DEFAULT 0,
    downloads INTEGER NOT NULL DEFAULT 0,
    expires_at INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_entries_expires ON entries(expires_at);
`

type Entry struct {
	ID           string
	Kind         string // "file" | "paste" | "url"
	Filename     string
	ContentType  string
	StoragePath  string
	Content      string
	Size         int64
	PasswordHash string
	OneTime      bool
	Downloads    int64
	ExpiresAt    int64 // unix seconds; 0 = never
	CreatedAt    int64
}

func openDB(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func insertEntry(db *sql.DB, e *Entry) error {
	_, err := db.Exec(`INSERT INTO entries
        (id, kind, filename, content_type, storage_path, content, size,
         password_hash, one_time, expires_at, created_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		e.ID, e.Kind, e.Filename, e.ContentType, e.StoragePath, e.Content, e.Size,
		e.PasswordHash, boolInt(e.OneTime), e.ExpiresAt, e.CreatedAt)
	return err
}

func getEntry(db *sql.DB, id string) (*Entry, error) {
	e := &Entry{}
	var ot int
	err := db.QueryRow(`SELECT id, kind, filename, content_type, storage_path, content,
        size, password_hash, one_time, downloads, expires_at, created_at
        FROM entries WHERE id = ?`, id).
		Scan(&e.ID, &e.Kind, &e.Filename, &e.ContentType, &e.StoragePath, &e.Content,
			&e.Size, &e.PasswordHash, &ot, &e.Downloads, &e.ExpiresAt, &e.CreatedAt)
	if err != nil {
		return nil, err
	}
	e.OneTime = ot == 1
	return e, nil
}

func deleteEntry(db *sql.DB, id string) error {
	_, err := db.Exec(`DELETE FROM entries WHERE id = ?`, id)
	return err
}

// claimDownload atomically increments the downloads counter, failing (0 rows)
// if this is a one-time entry that has already been consumed. Returns true
// when the caller may proceed to serve the entry.
func claimDownload(db *sql.DB, id string) (bool, error) {
	res, err := db.Exec(`UPDATE entries SET downloads = downloads + 1
        WHERE id = ? AND (one_time = 0 OR downloads = 0)`, id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

func listEntries(db *sql.DB) ([]*Entry, error) {
	rows, err := db.Query(`SELECT id, kind, filename, content, size, one_time,
        downloads, expires_at, created_at, password_hash
        FROM entries ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Entry
	for rows.Next() {
		e := &Entry{}
		var ot int
		if err := rows.Scan(&e.ID, &e.Kind, &e.Filename, &e.Content, &e.Size, &ot,
			&e.Downloads, &e.ExpiresAt, &e.CreatedAt, &e.PasswordHash); err != nil {
			return nil, err
		}
		e.OneTime = ot == 1
		out = append(out, e)
	}
	return out, rows.Err()
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
