package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestEventsWebSocketURL(t *testing.T) {
	got, err := eventsWebSocketURL("https://vault.example.com/api/cwp/")
	require.NoError(t, err)
	require.Equal(t, "wss://vault.example.com/api/cwp/events?heartbeat=30&type=approval_requested&type=approval_cancelled", got)

	_, err = eventsWebSocketURL("ftp://vault.example.com/api/cwp")
	require.Error(t, err)
}

func TestWatchOnce_ApprovesOnApprovalRequested(t *testing.T) {
	b64, _ := makeTxIntentB64(t)
	entry := approvalListEntry{
		OperationID:   "op-1",
		OperationType: operationTypeMakeTransaction,
		Intent:        b64,
	}
	var mu sync.Mutex
	var approveCount int

	srv, conns := newEventsServer(t, func(w http.ResponseWriter, r *http.Request) bool {
		switch r.URL.Path {
		case "/approvals/list":
			_, _ = w.Write([]byte("[]"))
			return true
		case "/approvals/id/op-1":
			raw, err := json.Marshal(entry)
			require.NoError(t, err)
			_, _ = w.Write(raw)
			return true
		case "/approvals/approve":
			mu.Lock()
			approveCount++
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
			return true
		default:
			return false
		}
	})

	s := eventTestServer(t, srv.URL)
	var logs bytes.Buffer
	s.logger = zerolog.New(&logs).Level(zerolog.DebugLevel)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.watchOnce(ctx) }()

	conn := <-conns
	writeEvent(t, ctx, conn, eventApprovalRequested, "op-1")
	writeEvent(t, ctx, conn, eventApprovalRequested, "op-1")
	require.NoError(t, conn.Close(websocket.StatusNormalClosure, ""))

	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for websocket close")
	}
	mu.Lock()
	require.Equal(t, 1, approveCount)
	mu.Unlock()
	require.Contains(t, logs.String(), `"message":"cwp event"`)
	require.Contains(t, logs.String(), `"type":"approval_requested"`)
	require.Contains(t, logs.String(), `"message":"approval intent"`)
	require.Contains(t, logs.String(), `"message":"approval signature"`)
	require.Contains(t, logs.String(), `"message":"approved"`)
	cancel()
}

func TestWatchOnce_CatchUpListsPendingBeforeEvents(t *testing.T) {
	b64, _ := makeTxIntentB64(t)
	entry := approvalListEntry{
		OperationID:   "op-list",
		OperationType: operationTypeMakeTransaction,
		Intent:        b64,
	}
	body, err := json.Marshal([]approvalListEntry{entry})
	require.NoError(t, err)

	approved := make(chan struct{}, 1)
	srv, _ := newEventsServer(t, func(w http.ResponseWriter, r *http.Request) bool {
		switch r.URL.Path {
		case "/approvals/list":
			_, _ = w.Write(body)
			return true
		case "/approvals/approve":
			approved <- struct{}{}
			w.WriteHeader(http.StatusNoContent)
			return true
		default:
			return false
		}
	})

	s := eventTestServer(t, srv.URL)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.watchOnce(ctx) }()

	select {
	case <-approved:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for catch-up approve")
	}
	require.Eventually(t, func() bool { return s.shouldSkip("op-list") }, time.Second, 5*time.Millisecond)

	cancel()
	require.Eventually(t, func() bool {
		select {
		case <-done:
			return true
		default:
			return false
		}
	}, 5*time.Second, 10*time.Millisecond)
}

func TestWatchOnce_CancelBeforeRequestDoesNotApprove(t *testing.T) {
	b64, _ := makeTxIntentB64(t)
	entry := approvalListEntry{
		OperationID:   "op-cancel",
		OperationType: operationTypeMakeTransaction,
		Intent:        b64,
	}
	var mu sync.Mutex
	var approved bool

	srv, conns := newEventsServer(t, func(w http.ResponseWriter, r *http.Request) bool {
		switch r.URL.Path {
		case "/approvals/list":
			_, _ = w.Write([]byte("[]"))
			return true
		case "/approvals/id/op-cancel":
			raw, err := json.Marshal(entry)
			require.NoError(t, err)
			_, _ = w.Write(raw)
			return true
		case "/approvals/approve":
			mu.Lock()
			approved = true
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
			return true
		default:
			return false
		}
	})

	s := eventTestServer(t, srv.URL)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.watchOnce(ctx) }()

	conn := <-conns
	writeEvent(t, ctx, conn, eventApprovalCancelled, "op-cancel")
	writeEvent(t, ctx, conn, eventApprovalRequested, "op-cancel")
	require.NoError(t, conn.Close(websocket.StatusNormalClosure, ""))

	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for websocket close")
	}
	mu.Lock()
	require.False(t, approved)
	mu.Unlock()
	require.True(t, s.shouldSkip("op-cancel"))
	cancel()
}

func eventTestServer(t *testing.T, baseURL string) *Server {
	t.Helper()
	s := testServer(t, &fakeApprovalAPI{})
	s.cwp = newCWPClient(baseURL, "cwp_test")
	s.cfg.CWPBaseURL = baseURL
	s.cfg.APIKey = "cwp_test"
	return s
}

func newEventsServer(t *testing.T, handle func(http.ResponseWriter, *http.Request) bool) (*httptest.Server, <-chan *websocket.Conn) {
	t.Helper()
	conns := make(chan *websocket.Conn, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/events" {
			require.Equal(t, "Bearer cwp_test", r.Header.Get("Authorization"))
			conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
			require.NoError(t, err)
			conns <- conn
			_ = conn.CloseRead(context.Background())
			return
		}
		if handle(w, r) {
			return
		}
		body, _ := io.ReadAll(r.Body)
		t.Errorf("unexpected %s %s %s", r.Method, r.URL.Path, body)
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, conns
}

func writeEvent(t *testing.T, ctx context.Context, conn *websocket.Conn, eventType, operationID string) {
	t.Helper()
	payload, err := json.Marshal(approvalEventPayload{OperationID: operationID})
	require.NoError(t, err)
	raw, err := json.Marshal(cwpEvent{Type: eventType, Payload: payload})
	require.NoError(t, err)
	require.NoError(t, conn.Write(ctx, websocket.MessageText, raw))
}
