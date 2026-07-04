package app

import (
	"database/sql"
	"log"
	"os"
	"time"
)

func startJanitor(db *sql.DB) {
	go func() {
		sweep(db)
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for range t.C {
			sweep(db)
		}
	}()
}

func sweep(db *sql.DB) {
	now := time.Now().Unix()
	rows, err := db.Query(`SELECT id, storage_path FROM entries
        WHERE expires_at > 0 AND expires_at < ?`, now)
	if err != nil {
		log.Printf("janitor: query: %v", err)
		return
	}
	type victim struct{ id, path string }
	var vs []victim
	for rows.Next() {
		var v victim
		if err := rows.Scan(&v.id, &v.path); err != nil {
			log.Printf("janitor: scan: %v", err)
			continue
		}
		vs = append(vs, v)
	}
	rows.Close()

	for _, v := range vs {
		if v.path != "" {
			if err := os.Remove(v.path); err != nil && !os.IsNotExist(err) {
				log.Printf("janitor: remove %s: %v", v.path, err)
			}
		}
		if _, err := db.Exec(`DELETE FROM entries WHERE id = ?`, v.id); err != nil {
			log.Printf("janitor: delete %s: %v", v.id, err)
		}
	}
	if len(vs) > 0 {
		log.Printf("janitor: swept %d expired entries", len(vs))
	}
}
