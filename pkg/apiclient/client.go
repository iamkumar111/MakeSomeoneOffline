package apiclient

import (
	"fmt"
	"net/http"
	"os"
	"time"
)

type tokenTransport struct{ token string }

func (t tokenTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	copy := r.Clone(r.Context())
	if t.token != "" {
		copy.Header.Set("Authorization", "Bearer "+t.token)
	}
	return http.DefaultTransport.RoundTrip(copy)
}

// New configures CLI authentication without putting the token in URLs or logs.
func New(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: tokenTransport{os.Getenv("NETCUT_API_TOKEN")},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			if len(via) > 0 && (req.URL.Scheme != via[0].URL.Scheme || req.URL.Host != via[0].URL.Host) {
				return fmt.Errorf("refusing API redirect to a different origin")
			}
			return nil
		},
	}
}
