package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/open-netcut/open-netcut/pkg/events"
	"github.com/open-netcut/open-netcut/pkg/models"
)

// WebhookEndpoint holds configuration for an external alert notification target.
type WebhookEndpoint struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	URL         string `json:"url"`
	MinSeverity string `json:"min_severity"` // "all", "medium", "high", "critical"
	Enabled     bool   `json:"enabled"`
}

// WebhookPayload represents the outgoing notification message.
type WebhookPayload struct {
	Text        string        `json:"text"` // Slack / Discord fallback
	AlertID     string        `json:"alert_id"`
	Type        string        `json:"type"`
	Severity    string        `json:"severity"`
	TargetIP    string        `json:"target_ip,omitempty"`
	TargetMAC   string        `json:"target_mac,omitempty"`
	Timestamp   time.Time     `json:"timestamp"`
	Action      string        `json:"recommended_action"`
	Evidence    []string      `json:"evidence"`
}

// AlertDispatcher manages webhook endpoints and dispatches alerts asynchronously.
type AlertDispatcher struct {
	mu         sync.RWMutex
	endpoints  map[string]*WebhookEndpoint
	httpClient *http.Client
	eventBus   *events.EventBus
	stopCh     chan struct{}
}

// NewAlertDispatcher creates a webhook notification dispatcher.
func NewAlertDispatcher(eventBus *events.EventBus) *AlertDispatcher {
	ad := &AlertDispatcher{
		endpoints: make(map[string]*WebhookEndpoint),
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
		eventBus: eventBus,
		stopCh:   make(chan struct{}),
	}

	if eventBus != nil {
		ad.startListening()
	}

	return ad
}

// RegisterEndpoint adds or updates a webhook URL.
func (ad *AlertDispatcher) RegisterEndpoint(ep *WebhookEndpoint) {
	ad.mu.Lock()
	defer ad.mu.Unlock()
	ad.endpoints[ep.ID] = ep
}

// RemoveEndpoint deletes a webhook endpoint.
func (ad *AlertDispatcher) RemoveEndpoint(id string) {
	ad.mu.Lock()
	defer ad.mu.Unlock()
	delete(ad.endpoints, id)
}

// ListEndpoints returns all registered endpoints.
func (ad *AlertDispatcher) ListEndpoints() []*WebhookEndpoint {
	ad.mu.RLock()
	defer ad.mu.RUnlock()
	list := make([]*WebhookEndpoint, 0, len(ad.endpoints))
	for _, ep := range ad.endpoints {
		list = append(list, ep)
	}
	return list
}

// DispatchAlert sends an alert to all matching and enabled endpoints.
func (ad *AlertDispatcher) DispatchAlert(ctx context.Context, alert *models.Alert) {
	ad.mu.RLock()
	endpoints := make([]*WebhookEndpoint, 0, len(ad.endpoints))
	for _, ep := range ad.endpoints {
		if ep.Enabled && ad.severityMatches(ep.MinSeverity, alert.Severity) {
			endpoints = append(endpoints, ep)
		}
	}
	ad.mu.RUnlock()

	if len(endpoints) == 0 {
		return
	}

	evidenceTexts := make([]string, 0, len(alert.Evidence))
	for _, ev := range alert.Evidence {
		evidenceTexts = append(evidenceTexts, ev.Description)
	}

	payload := WebhookPayload{
		Text:      fmt.Sprintf("[OPEN-NETCUT ALERT] %s: %s (Target: %s)", strings.ToUpper(string(alert.Severity)), alert.Type, alert.TargetIP),
		AlertID:   alert.ID,
		Type:      string(alert.Type),
		Severity:  string(alert.Severity),
		TargetIP:  alert.TargetIP,
		TargetMAC: alert.TargetMAC,
		Timestamp: alert.FirstSeen,
		Action:    alert.RecommendedAction,
		Evidence:  evidenceTexts,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return
	}

	for _, ep := range endpoints {
		go func(url string) {
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
			if err == nil {
				req.Header.Set("Content-Type", "application/json")
				resp, err := ad.httpClient.Do(req)
				if err == nil {
					_ = resp.Body.Close()
				}
			}
		}(ep.URL)
	}
}

func (ad *AlertDispatcher) severityMatches(minSeverity string, actual models.AlertSeverity) bool {
	if minSeverity == "" || minSeverity == "all" {
		return true
	}
	switch minSeverity {
	case "critical":
		return actual == models.SeverityCritical
	case "high":
		return actual == models.SeverityCritical || actual == models.SeverityHigh
	case "medium":
		return actual == models.SeverityCritical || actual == models.SeverityHigh || actual == models.SeverityMedium
	default:
		return true
	}
}

func (ad *AlertDispatcher) startListening() {
	sub := ad.eventBus.Subscribe(50)
	go func() {
		for {
			select {
			case <-ad.stopCh:
				return
			case evt, ok := <-sub:
				if !ok {
					return
				}
				if evt.Type == events.EventAlertCreated {
					if alert, ok := evt.Data.(*models.Alert); ok {
						ad.DispatchAlert(context.Background(), alert)
					}
				}
			}
		}
	}()
}

// Stop terminates the dispatcher.
func (ad *AlertDispatcher) Stop() {
	close(ad.stopCh)
}
