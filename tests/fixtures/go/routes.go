// The HTTP surface for vulnerable.go. This file plants no defects of its own -- it exists so the
// ones next door are reachable.
//
// references/rubric.md drives severity from reachability, and caps a dangerous pattern in code
// nothing calls at Medium. Without this file, `package fixture` had no importer, no main and no
// test, so a reviewer scoring GO-04 (SQL built by concatenation) as Medium rather than Critical was
// applying the rubric correctly -- and the fixture, not the reviewer, was wrong. Every handler
// below is registered on a mux with no authentication of any kind, so each defect is reachable by
// an unauthenticated remote caller with attacker-chosen input.
package fixture

import (
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

// maxBodyBytes caps request bodies. Unbounded io.ReadAll on a request body is a review-go
// checklist item in its own right, and this file is not the place to plant one.
const maxBodyBytes = 1 << 20

// encode writes a JSON response. The error is deliberately ignored and this is the one place that
// says why: the status line and headers are already committed by the time Encode can fail, so
// there is no second response to send. Handlers below call this instead of discarding inline, so
// GO-06's "ignored error with no comment" pattern appears exactly once in the package -- planted,
// in vulnerable.go.
func encode(w http.ResponseWriter, v any) {
	_ = json.NewEncoder(w).Encode(v)
}

// Routes returns the application's entire HTTP surface. No middleware, no auth.
func Routes(db *sql.DB) *http.ServeMux {
	mux := http.NewServeMux()

	// GO-04: the raw query parameter is concatenated into SQL inside FindUser.
	mux.HandleFunc("/users", func(w http.ResponseWriter, r *http.Request) {
		rows, err := FindUser(db, r.URL.Query().Get("name"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()
		encode(w, map[string]string{"status": "ok"})
	})

	// GO-01: a malformed body makes loadConfig return nil, which EffectiveLimit dereferences.
	mux.HandleFunc("/limit", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		encode(w, map[string]int{"limit": EffectiveLimit(body)})
	})

	// GO-02: a client-supplied JSON body reaches a one-value type assertion.
	mux.HandleFunc("/tenant", func(w http.ResponseWriter, r *http.Request) {
		var claims any
		if err := json.NewDecoder(r.Body).Decode(&claims); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		encode(w, map[string]string{"tenant": TenantName(claims)})
	})

	// GO-06: the decode error is discarded, so a malformed event reads as a zero-value one.
	mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		encode(w, DecodeEvent(body))
	})

	// GO-05: one request can name arbitrarily many paths, and every descriptor stays open until
	// the handler returns.
	mux.HandleFunc("/sizes", func(w http.ResponseWriter, r *http.Request) {
		paths := strings.Split(r.URL.Query().Get("paths"), ",")
		encode(w, map[string]int64{"total": TotalSize(paths)})
	})

	// GO-03: every request leaks a context and a goroutine that never observes cancellation.
	mux.HandleFunc("/watch", func(w http.ResponseWriter, r *http.Request) {
		StartWatcher(r.Context(), make(chan string))
		w.WriteHeader(http.StatusAccepted)
	})

	// GO-07: concurrent requests race on the same unsynchronised map. Concurrent map write is an
	// unrecoverable fatal error, so this is a remote kill switch, not a recoverable panic.
	mux.HandleFunc("/hit", func(w http.ResponseWriter, r *http.Request) {
		RecordHit(r.URL.Query().Get("key"))
		w.WriteHeader(http.StatusAccepted)
	})

	return mux
}
