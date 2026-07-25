// CLEAN-FIXTURE -- the same seven situations as vulnerable.go, written correctly.
// A review of this file must produce no Critical and no High findings.
package fixture

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

type CleanConfig struct {
	Limit int `json:"limit"`
}

type CleanEvent struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

func loadCleanConfig(raw []byte) (*CleanConfig, error) {
	var c CleanConfig
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return &c, nil
}

// GO-01: the error branch returns, so the pointer is never dereferenced when it may be nil.
func EffectiveLimitSafe(raw []byte) (int, error) {
	cfg, err := loadCleanConfig(raw)
	if err != nil {
		return 0, err
	}
	return cfg.Limit * 2, nil
}

// GO-02: two-value assertions with an explicit failure path.
func TenantNameSafe(claims any) (string, bool) {
	m, ok := claims.(map[string]any)
	if !ok {
		return "", false
	}
	name, ok := m["tenant"].(string)
	if !ok {
		return "", false
	}
	return name, true
}

// GO-03: cancel is always called, and the goroutine selects on ctx.Done() so it cannot outlive
// the context or block on a channel that stops being written.
func StartWatcherSafe(parent context.Context, updates <-chan string, handle func(string)) {
	ctx, cancel := context.WithCancel(parent)
	go func() {
		defer cancel()
		for {
			select {
			case <-ctx.Done():
				return
			case u, ok := <-updates:
				if !ok {
					return
				}
				handle(u)
			}
		}
	}()
}

// GO-04: placeholder plus bound argument. The value never reaches the SQL text.
func FindUserSafe(db *sql.DB, name string) (*sql.Rows, error) {
	return db.Query("SELECT id, email FROM users WHERE name = ?", name)
}

// GO-05: the per-file work lives in its own function, so defer runs once per path.
func fileSize(path string) (int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return 0, fmt.Errorf("stat %s: %w", path, err)
	}
	return info.Size(), nil
}

func TotalSizeSafe(paths []string) (int64, error) {
	var total int64
	for _, p := range paths {
		size, err := fileSize(p)
		if err != nil {
			return 0, fmt.Errorf("size of %s: %w", p, err)
		}
		total += size
	}
	return total, nil
}

// GO-06: the decode error is wrapped and returned, so the caller can tell empty from broken.
func DecodeEventSafe(raw []byte) (CleanEvent, error) {
	var e CleanEvent
	if err := json.Unmarshal(raw, &e); err != nil {
		return CleanEvent{}, fmt.Errorf("decode event: %w", err)
	}
	return e, nil
}

// GO-07: shared state is owned by a type that guards every access.
type HitCounter struct {
	mu     sync.Mutex
	counts map[string]int
}

func NewHitCounter() *HitCounter {
	return &HitCounter{counts: make(map[string]int)}
}

func (c *HitCounter) Record(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.counts[key]++
}

func (c *HitCounter) Count(key string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.counts[key]
}
