package server

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRequestLogsCorrelateAndExcludeCredentials(t *testing.T) {
	var output bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&output)
	defer log.SetOutput(previous)
	handler := requestLogging(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "failure", 500) }))
	r := httptest.NewRequest("POST", "http://localhost/api/v1/devices/test/quarantine?token=query-secret", strings.NewReader("body-secret"))
	r.Header.Set("Authorization", "Bearer header-secret")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	id := w.Header().Get("X-Request-ID")
	if id == "" || !strings.Contains(output.String(), "id="+id) || !strings.Contains(output.String(), "status=500") {
		t.Fatalf("missing correlation: %s", output.String())
	}
	for _, secret := range []string{"query-secret", "body-secret", "header-secret"} {
		if strings.Contains(output.String(), secret) {
			t.Fatalf("secret leaked: %s", secret)
		}
	}
}

func TestRequestLoggerPreservesStreaming(t *testing.T) {
	w := httptest.NewRecorder()
	rw := &loggedResponse{ResponseWriter: w}
	rw.Write([]byte("event"))
	rw.Flush()
	if !w.Flushed || rw.status != 200 || rw.Unwrap() != w {
		t.Fatal("streaming broken")
	}
}
