package server

import (
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

type loggedResponse struct {
	http.ResponseWriter
	status int
}

func (w *loggedResponse) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *loggedResponse) Flush() {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	if err := http.NewResponseController(w.ResponseWriter).Flush(); err != nil {
		log.Printf("response_flush_failed error=%q", err)
	}
}
func (w *loggedResponse) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}
func (w *loggedResponse) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(p)
}

func requestLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := uuid.NewString()
		w.Header().Set("X-Request-ID", id)
		// Never log query strings, request bodies, cookies or authorization headers.
		path := r.URL.EscapedPath()
		started := time.Now()
		api := strings.HasPrefix(path, "/api/")
		if api {
			log.Printf("request_start id=%s method=%s path=%q", id, r.Method, path)
		}
		rw := &loggedResponse{ResponseWriter: w}
		defer func() {
			panicValue := recover()
			status := rw.status
			if panicValue != nil {
				status = http.StatusInternalServerError
			}
			if status == 0 {
				status = http.StatusOK
			}
			if api || status >= 400 {
				log.Printf("request_end id=%s method=%s path=%q status=%d duration_ms=%d", id, r.Method, path, status, time.Since(started).Milliseconds())
			}
			if panicValue != nil {
				log.Printf("request_panic id=%s", id)
				panic(panicValue)
			}
		}()
		next.ServeHTTP(rw, r)
	})
}
