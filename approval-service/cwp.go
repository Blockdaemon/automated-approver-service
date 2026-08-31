package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const defaultHTTPTimeout = 30 * time.Second

// approvalListEntry is the CWP GET /approvals/list JSON shape.
// Intent is base64 of the stored operation intent; Approve verifies the
// signature against those decoded bytes.
type approvalListEntry struct {
	OperationID   string `json:"OperationID"`
	OperationType string `json:"OperationType"`
	Intent        string `json:"Intent"`
}

type cwpApproveBody struct {
	OperationID     string `json:"OperationID"`
	IntentSignature []byte `json:"IntentSignature"`
}

type cwpRejectBody struct {
	OperationID string `json:"OperationID"`
}

// approvalAPI is the outbound CWP approvals surface (IV /api/cwp or standalone).
// Identity comes from the cwp_ API key; request bodies must not include UserID
// (the Vault gateway rejects unknown JSON fields).
type approvalAPI interface {
	List(ctx context.Context) ([]approvalListEntry, error)
	Approve(ctx context.Context, operationID string, signature []byte) error
	Reject(ctx context.Context, operationID string) error
}

type cwpClient struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

func newCWPClient(baseURL, apiKey string) *cwpClient {
	return &cwpClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: defaultHTTPTimeout,
		},
	}
}

func (c *cwpClient) List(ctx context.Context) ([]approvalListEntry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/approvals/list", nil)
	if err != nil {
		return nil, err
	}
	c.setAuth(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET /approvals/list: status %d: %s", resp.StatusCode, truncate(body, 512))
	}

	if len(bytes.TrimSpace(body)) == 0 || bytes.Equal(bytes.TrimSpace(body), []byte("null")) {
		return nil, nil
	}

	var entries []approvalListEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("GET /approvals/list: decode: %w", err)
	}
	return entries, nil
}

func (c *cwpClient) Approve(ctx context.Context, operationID string, signature []byte) error {
	payload, err := json.Marshal(cwpApproveBody{
		OperationID:     operationID,
		IntentSignature: signature,
	})
	if err != nil {
		return err
	}
	return c.post(ctx, "/approvals/approve", payload)
}

func (c *cwpClient) Reject(ctx context.Context, operationID string) error {
	payload, err := json.Marshal(cwpRejectBody{OperationID: operationID})
	if err != nil {
		return err
	}
	return c.post(ctx, "/approvals/reject", payload)
}

func (c *cwpClient) post(ctx context.Context, path string, payload []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	c.setAuth(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("POST %s: status %d: %s", path, resp.StatusCode, truncate(body, 512))
	}
	return nil
}

func (c *cwpClient) setAuth(req *http.Request) {
	token := c.apiKey
	if !strings.HasPrefix(strings.ToLower(token), "bearer ") {
		token = "Bearer " + token
	}
	req.Header.Set("Authorization", token)
}

func truncate(b []byte, n int) string {
	s := strings.TrimSpace(string(b))
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
