// Package alert delivers notifications to Slack, Microsoft Teams, Discord
// or a generic JSON webhook.
package alert

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/slash-mark-dev/go-suite/internal/httpx"
)

// Message is a notification.
type Message struct {
	Title string   `json:"title"`
	Lines []string `json:"lines"`
	// Severity is free text ("high", "info"...) for the generic webhook.
	Severity string `json:"severity,omitempty"`
	URL      string `json:"url,omitempty"`
	// Data is included verbatim in the generic webhook payload.
	Data any `json:"data,omitempty"`
}

// Target is a destination.
type Target struct {
	Kind string // slack, teams, discord, webhook
	URL  string
}

// Targets builds the list from flag values / env.
func Targets(slack, teams, discord, webhook string) []Target {
	var out []Target
	add := func(kind, u string) {
		for _, x := range strings.Split(u, ",") {
			if x = strings.TrimSpace(x); x != "" {
				out = append(out, Target{kind, x})
			}
		}
	}
	add("slack", slack)
	add("teams", teams)
	add("discord", discord)
	add("webhook", webhook)
	return out
}

// Payload returns the JSON body for a target kind.
func Payload(kind string, m Message) ([]byte, error) {
	text := m.Title
	if len(m.Lines) > 0 {
		text += "\n" + strings.Join(m.Lines, "\n")
	}
	switch kind {
	case "slack":
		return json.Marshal(map[string]any{"text": text})
	case "teams":
		return json.Marshal(map[string]any{
			"@type": "MessageCard", "@context": "https://schema.org/extensions",
			"summary": m.Title, "title": m.Title, "text": strings.Join(m.Lines, "<br>"),
		})
	case "discord":
		if len(text) > 1900 {
			text = text[:1900] + "…"
		}
		return json.Marshal(map[string]any{"content": text})
	default:
		return json.Marshal(map[string]any{"source": "sm-go", "title": m.Title, "lines": m.Lines,
			"severity": m.Severity, "url": m.URL, "data": m.Data})
	}
}

// Send delivers m to every target and returns the first error.
func Send(ctx context.Context, hc *httpx.Client, targets []Target, m Message) error {
	var first error
	for _, t := range targets {
		body, err := Payload(t.Kind, m)
		if err != nil {
			return err
		}
		r, err := hc.Post(ctx, t.URL, "application/json", body)
		if err == nil && r.Status >= 300 {
			err = fmt.Errorf("%s webhook returned %d", t.Kind, r.Status)
		}
		if err != nil && first == nil {
			first = fmt.Errorf("%s alert: %v", t.Kind, err)
		}
	}
	return first
}
