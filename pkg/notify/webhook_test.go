package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/open-netcut/open-netcut/pkg/events"
	"github.com/open-netcut/open-netcut/pkg/models"
)

func TestAlertDispatcherWebhookDelivery(t *testing.T) {
	receivedPayload := make(chan WebhookPayload, 1)

	// Mock receiver server (like Slack or custom webhook)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p WebhookPayload
		_ = json.NewDecoder(r.Body).Decode(&p)
		receivedPayload <- p
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	bus := events.NewEventBus()
	dispatcher := NewAlertDispatcher(bus)
	defer dispatcher.Stop()

	// Register webhook target
	dispatcher.RegisterEndpoint(&WebhookEndpoint{
		ID:          "ep-slack-test",
		Name:        "Test Slack Webhook",
		URL:         server.URL,
		MinSeverity: "high",
		Enabled:     true,
	})

	alert := &models.Alert{
		ID:         "alert-123",
		Type:       models.AlertGatewayImpersonation,
		Severity:   models.SeverityCritical,
		TargetIP:   "192.168.1.1",
		TargetMAC:  "de:ad:be:ef:00:01",
		FirstSeen:  time.Now().UTC(),
		Confidence: 0.99,
		RecommendedAction: "Isolate attacker port immediately",
		Evidence: []models.AlertEvidence{
			{Description: "Gateway MAC changed unexpectedly"},
		},
	}

	dispatcher.DispatchAlert(context.Background(), alert)

	select {
	case payload := <-receivedPayload:
		if payload.AlertID != "alert-123" {
			t.Errorf("expected alert_id 'alert-123', got %s", payload.AlertID)
		}
		if payload.Severity != "critical" {
			t.Errorf("expected severity 'critical', got %s", payload.Severity)
		}
		if len(payload.Evidence) == 0 {
			t.Error("expected evidence in webhook payload")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for webhook delivery")
	}
}
