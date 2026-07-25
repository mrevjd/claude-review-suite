// Package fixture carries deliberately defective Go used to test the review-go skill.
// Every planted defect is annotated with the checklist ID it exercises: one per GO-01..GO-07.
// This file must parse and compile -- a vulnerable fixture has to be vulnerable, not broken.
//
// Reachability: every function below is wired to an unauthenticated HTTP route in routes.go, so
// each defect is reachable with attacker-chosen input. Score severity accordingly -- these are not
// dead-code patterns.
package fixture

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"os"
)

// Config and Event are the payload shapes the functions below decode.
type Config struct {
	Limit int `json:"limit"`
}

type Event struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

func loadConfig(raw []byte) (*Config, error) {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// EffectiveLimit logs the parse failure and then keeps going.
func EffectiveLimit(raw []byte) int {
	cfg, err := loadConfig(raw)
	if err != nil {
		// VULN: GO-01 -- error is logged but not returned, so cfg is nil at the dereference below.
		// ANCHOR: log.Printf("config parse failed: %v", err)
		log.Printf("config parse failed: %v", err)
	}
	return cfg.Limit * 2
}

// TenantName pulls a tenant out of decoded JWT claims.
func TenantName(claims any) string {
	// VULN: GO-02 -- one-value assertions on untrusted decoded JSON; any other shape panics.
	// ANCHOR: m := claims.(map[string]any)
	m := claims.(map[string]any)
	return m["tenant"].(string)
}

// StartWatcher fans updates out to the log.
func StartWatcher(parent context.Context, updates <-chan string) {
	// VULN: GO-03 -- the cancel func is discarded, so the derived context and its timer leak on
	// every call, and the goroutine below never observes ctx.Done() so it blocks forever once the
	// producer stops writing.
	// ANCHOR: ctx, _ := context.WithCancel(parent)
	ctx, _ := context.WithCancel(parent)
	go func() {
		for u := range updates {
			log.Printf("%v: %s", ctx.Value("reqID"), u)
		}
	}()
}

// FindUser looks a user up by name.
func FindUser(db *sql.DB, name string) (*sql.Rows, error) {
	// VULN: GO-04 -- query built by concatenation around a caller-supplied value.
	// ANCHOR: "SELECT id, email FROM users WHERE name = '" + name
	q := "SELECT id, email FROM users WHERE name = '" + name + "'"
	return db.Query(q)
}

// TotalSize adds up the size of every path it is given.
func TotalSize(paths []string) int64 {
	var total int64
	for _, p := range paths {
		// Best-effort: an unreadable path is skipped rather than aborting the whole total, so its
		// error is deliberately not GO-06 -- there is one planted defect in this function, not two.
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		// VULN: GO-05 -- defer runs at function exit, not iteration exit, so every descriptor
		// stays open for the whole loop.
		// ANCHOR: f, err := os.Open(p)
		defer f.Close()
		info, err := f.Stat()
		if err != nil {
			continue
		}
		total += info.Size()
	}
	return total
}

// DecodeEvent turns a payload into an Event.
func DecodeEvent(raw []byte) Event {
	var e Event
	// VULN: GO-06 -- Unmarshal's error is discarded, so malformed input silently yields a zero
	// Event and the caller cannot tell success from failure.
	// ANCHOR: _ = json.Unmarshal(raw, &e)
	_ = json.Unmarshal(raw, &e)
	return e
}

var hitCounts = map[string]int{}

// RecordHit bumps a counter for the given key.
func RecordHit(key string) {
	// VULN: GO-07 -- unsynchronised map write from a new goroutine on every call. Concurrent map
	// write is an unrecoverable fatal error, not a panic that can be recovered.
	// ANCHOR: hitCounts[key]++
	go func() {
		hitCounts[key]++
	}()
}
