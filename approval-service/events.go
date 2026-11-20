package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coder/websocket"
)

const (
	eventApprovalRequested = "approval_requested"
	eventApprovalCancelled = "approval_cancelled"

	eventsHeartbeatSeconds = "30"
	eventsReconnectMax     = 30 * time.Second
)

// cwpEvent is the CWP WebSocket ClientEvent shape (Type + Payload).
type cwpEvent struct {
	Type    string          `json:"Type"`
	Payload json.RawMessage `json:"Payload"`
}

type approvalEventPayload struct {
	OperationID string `json:"OperationID"`
}

// eventsWebSocketURL is the CWP GET /events WebSocket URL for this base.
// Subscribed types are approval_requested and approval_cancelled. heartbeat
// asks the server to ping so a dead connection is closed.
func eventsWebSocketURL(cwpBaseURL string) (string, error) {
	u, err := url.Parse(strings.TrimRight(strings.TrimSpace(cwpBaseURL), "/"))
	if err != nil {
		return "", fmt.Errorf("cwp_base_url: %w", err)
	}
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	case "wss", "ws":
	default:
		return "", fmt.Errorf("cwp_base_url scheme %q must be http, https, ws, or wss", u.Scheme)
	}
	if u.Host == "" {
		return "", fmt.Errorf("cwp_base_url is missing a host")
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/events"
	q := u.Query()
	q.Add("type", eventApprovalRequested)
	q.Add("type", eventApprovalCancelled)
	q.Set("heartbeat", eventsHeartbeatSeconds)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// watchLoop subscribes to CWP events and reconnects until ctx is cancelled.
// Events are not replayed, so each connection also lists pending approvals once.
func (s *Server) watchLoop(ctx context.Context) {
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		start := time.Now()
		err := s.watchOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		delay := backoff
		if time.Since(start) > 5*time.Second {
			delay = time.Second
			backoff = time.Second
		} else if backoff < eventsReconnectMax {
			backoff *= 2
		}
		s.logger.Error().Err(err).Dur("retry_in", delay).Msg("cwp events websocket closed; reconnecting")
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// watchOnce dials the events socket, catches up the pending list, then handles
// events until the connection or ctx ends.
func (s *Server) watchOnce(ctx context.Context) error {
	wsURL, err := eventsWebSocketURL(s.cfg.CWPBaseURL)
	if err != nil {
		return err
	}
	s.logger.Info().Str("url", wsURL).Msg("subscribing to CWP events")

	conn, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": []string{bearerToken(s.cfg.APIKey)}},
	})
	if err != nil {
		return fmt.Errorf("dial events: %w", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	events := make(chan cwpEvent, 32)
	readErr := make(chan error, 1)
	go func() {
		readErr <- s.readEvents(ctx, conn, events)
		close(events)
	}()

	syncErr := s.syncPending(ctx)
	if syncErr != nil && ctx.Err() == nil {
		s.logger.Error().Err(syncErr).Msg("pending approval catch-up failed")
		// Drop the socket so the reconnect loop lists again. Events already
		// read stay in the channel and are handled before we return.
		_ = conn.Close(websocket.StatusGoingAway, "catch-up failed")
	}

	for ev := range events {
		s.handleEvent(ctx, ev)
	}
	err = <-readErr
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if syncErr != nil {
		return syncErr
	}
	return err
}

func (s *Server) readEvents(ctx context.Context, conn *websocket.Conn, out chan<- cwpEvent) error {
	for {
		_, data, err := conn.Read(ctx)
		if err != nil {
			return err
		}
		var ev cwpEvent
		if err := json.Unmarshal(data, &ev); err != nil {
			s.logger.Warn().Err(err).Msg("ignored malformed CWP event")
			continue
		}
		s.logEvent(ev)
		if ev.Type == eventApprovalCancelled {
			if opID := eventOperationID(ev); opID != "" {
				s.markCancelled(opID)
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case out <- ev:
		}
	}
}

func (s *Server) handleEvent(ctx context.Context, ev cwpEvent) {
	switch ev.Type {
	case eventApprovalRequested:
		opID := eventOperationID(ev)
		if opID == "" {
			s.logger.Warn().Msg("approval_requested missing OperationID")
			return
		}
		s.handleRequested(ctx, opID)
	case eventApprovalCancelled:
		opID := eventOperationID(ev)
		if opID == "" {
			return
		}
		s.markCancelled(opID)
		s.markSeen(opID)
		s.logger.Info().
			Str("operation_id", opID).
			Str("reason", "approval cancelled").
			Msg("skipped")
	default:
		// Unknown types are non-breaking additions. Ignore them.
	}
}

func eventOperationID(ev cwpEvent) string {
	var payload approvalEventPayload
	if err := json.Unmarshal(ev.Payload, &payload); err != nil {
		return ""
	}
	return payload.OperationID
}

// handleRequested loads the pending approval and signs it. A 404 means the
// request is already gone. Other failures are retried a few times; the id
// stays unseen so the next reconnect catch-up tries again.
func (s *Server) logEvent(ev cwpEvent) {
	eventLog := s.logger.Debug().
		Str("type", ev.Type).
		Str("operation_id", eventOperationID(ev))
	if json.Valid(ev.Payload) {
		eventLog = eventLog.RawJSON("payload", ev.Payload)
	}
	eventLog.Msg("cwp event")
}

func (s *Server) handleRequested(ctx context.Context, operationID string) {
	if reason := s.skipReason(operationID); reason != "" {
		s.logger.Debug().
			Str("operation_id", operationID).
			Str("reason", reason).
			Msg("skipped")
		return
	}
	s.logger.Debug().Str("operation_id", operationID).Msg("approval requested")
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		if reason := s.skipReason(operationID); reason != "" {
			s.logger.Debug().
				Str("operation_id", operationID).
				Str("reason", reason).
				Msg("skipped")
			return
		}
		lastErr = s.fetchAndProcess(ctx, operationID)
		if lastErr == nil || ctx.Err() != nil {
			return
		}
		s.logger.Warn().
			Err(lastErr).
			Str("operation_id", operationID).
			Int("attempt", attempt).
			Msg("approval handling failed")
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
	s.logger.Error().
		Err(lastErr).
		Str("operation_id", operationID).
		Msg("giving up on approval until reconnect")
}

func (s *Server) fetchAndProcess(ctx context.Context, operationID string) error {
	entry, err := s.cwp.Get(ctx, operationID)
	if errors.Is(err, errApprovalNotFound) {
		s.markSeen(operationID)
		s.logger.Info().
			Str("operation_id", operationID).
			Str("reason", "approval not found").
			Msg("skipped")
		return nil
	}
	if err != nil {
		return err
	}
	if entry.OperationID == "" {
		entry.OperationID = operationID
	}
	if err := s.processEntry(ctx, entry); err != nil {
		return err
	}
	s.markSeen(operationID)
	return nil
}

func (s *Server) shouldSkip(operationID string) bool {
	return s.skipReason(operationID) != ""
}

func (s *Server) skipReason(operationID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.seen[operationID]; ok {
		return "already handled"
	}
	if _, ok := s.cancelled[operationID]; ok {
		return "approval cancelled"
	}
	return ""
}

func (s *Server) markSeen(operationID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seen == nil {
		s.seen = map[string]struct{}{}
	}
	s.seen[operationID] = struct{}{}
}

func (s *Server) markCancelled(operationID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancelled == nil {
		s.cancelled = map[string]struct{}{}
	}
	s.cancelled[operationID] = struct{}{}
}

func (s *Server) isCancelled(operationID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.cancelled[operationID]
	return ok
}

func bearerToken(apiKey string) string {
	token := strings.TrimSpace(apiKey)
	if !strings.HasPrefix(strings.ToLower(token), "bearer ") {
		token = "Bearer " + token
	}
	return token
}
