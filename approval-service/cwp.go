package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const defaultHTTPTimeout = 30 * time.Second

// errApprovalNotFound is returned by Get when CWP has no pending approval
// for this user and operation (HTTP 404).
var errApprovalNotFound = errors.New("approval not found")

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
	Get(ctx context.Context, operationID string) (approvalListEntry, error)
	Approve(ctx context.Context, operationID string, signature []byte) error
	Reject(ctx context.Context, operationID string) error
	// Me returns the authenticated user's ID (email) from GET /users/me.
	Me(ctx context.Context) (string, error)
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

func (c *cwpClient) Get(ctx context.Context, operationID string) (approvalListEntry, error) {
	path := "/approvals/id/" + url.PathEscape(operationID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return approvalListEntry{}, err
	}
	c.setAuth(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return approvalListEntry{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return approvalListEntry{}, err
	}
	if resp.StatusCode == http.StatusNotFound {
		return approvalListEntry{}, errApprovalNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return approvalListEntry{}, fmt.Errorf("GET %s: status %d: %s", path, resp.StatusCode, truncate(body, 512))
	}

	var entry approvalListEntry
	if err := json.Unmarshal(body, &entry); err != nil {
		return approvalListEntry{}, fmt.Errorf("GET %s: decode: %w", path, err)
	}
	return entry, nil
}

// Me calls CWP GET /users/me and returns the caller ID. On Institutional Vault
// that route is /api/cwp/users/me when cwp_base_url includes /api/cwp.
func (c *cwpClient) Me(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/users/me", nil)
	if err != nil {
		return "", err
	}
	c.setAuth(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("GET /users/me: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET /users/me: status %d: %s", resp.StatusCode, truncate(body, 256))
	}

	var user struct {
		ID string `json:"ID"`
	}
	if err := json.Unmarshal(body, &user); err != nil {
		return "", fmt.Errorf("GET /users/me: decode: %w", err)
	}
	if strings.TrimSpace(user.ID) == "" {
		return "", fmt.Errorf("GET /users/me: response missing ID")
	}
	return user.ID, nil
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
	req.Header.Set("Authorization", bearerToken(c.apiKey))
}

func truncate(b []byte, n int) string {
	s := strings.TrimSpace(string(b))
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
