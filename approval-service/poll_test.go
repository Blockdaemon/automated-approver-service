package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/synctest"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

type fakeApprovalAPI struct {
	entries []approvalListEntry
	approve func(context.Context, string, []byte) error

	approvedOp  string
	approvedSig []byte
	rejectedOp  string
}

func (f *fakeApprovalAPI) List(context.Context) ([]approvalListEntry, error) {
	return f.entries, nil
}

func (f *fakeApprovalAPI) Approve(ctx context.Context, operationID string, signature []byte) error {
	if f.approve != nil {
		return f.approve(ctx, operationID, signature)
	}
	f.approvedOp = operationID
	f.approvedSig = signature
	return nil
}

func (f *fakeApprovalAPI) Reject(_ context.Context, operationID string) error {
	f.rejectedOp = operationID
	return nil
}

func testServer(t *testing.T, api *fakeApprovalAPI) *Server {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return &Server{
		logger:     zerolog.Nop(),
		privateKey: key,
		cwp:        api,
	}
}

func makeTxIntentB64(t *testing.T) (string, []byte) {
	t.Helper()
	intent := []byte(`{"OperationType":"make transaction","OperationID":"op-1","Asset":"ETH","InitiatorID":"bot@example.com","Source":{"MasterKeyName":"Default"},"Destination":[{"Address":"0xab","Amount":"1"}]}`)
	return base64.StdEncoding.EncodeToString(intent), intent
}

func TestProcessEntry_ApprovesMakeTransaction(t *testing.T) {
	b64, intent := makeTxIntentB64(t)
	api := &fakeApprovalAPI{}
	s := testServer(t, api)

	err := s.processEntry(context.Background(), approvalListEntry{
		OperationID:   "op-1",
		OperationType: operationTypeMakeTransaction,
		Intent:        b64,
	})
	require.NoError(t, err)
	require.Equal(t, "op-1", api.approvedOp)
	require.Empty(t, api.rejectedOp)
	require.NoError(t, verifySignature(intent, getPublicKey(s.privateKey), api.approvedSig))
}

func TestProcessEntry_ApprovesCallAndDeployContract(t *testing.T) {
	for _, opType := range []string{operationTypeCallContract, operationTypeDeployContract} {
		t.Run(opType, func(t *testing.T) {
			intent := []byte(`{"OperationType":"` + opType + `","OperationID":"op-contract","InitiatorID":"bot@example.com"}`)
			api := &fakeApprovalAPI{}
			s := testServer(t, api)

			err := s.processEntry(context.Background(), approvalListEntry{
				OperationID:   "op-contract",
				OperationType: opType,
				Intent:        base64.StdEncoding.EncodeToString(intent),
			})
			require.NoError(t, err)
			require.Equal(t, "op-contract", api.approvedOp)
			require.Empty(t, api.rejectedOp)
			require.NoError(t, verifySignature(intent, getPublicKey(s.privateKey), api.approvedSig))
		})
	}
}

func TestProcessEntry_ApprovesTransfer(t *testing.T) {
	intent := []byte(`{"OperationType":"transfer","OperationID":"op-xfer","Asset":"ETH"}`)
	api := &fakeApprovalAPI{}
	s := testServer(t, api)

	err := s.processEntry(context.Background(), approvalListEntry{
		OperationID:   "op-xfer",
		OperationType: operationTypeTransfer,
		Intent:        base64.StdEncoding.EncodeToString(intent),
	})
	require.NoError(t, err)
	require.Equal(t, "op-xfer", api.approvedOp)
	require.NoError(t, verifySignature(intent, getPublicKey(s.privateKey), api.approvedSig))
}

func TestProcessEntry_SkipsUnsupportedType(t *testing.T) {
	api := &fakeApprovalAPI{}
	s := testServer(t, api)

	err := s.processEntry(context.Background(), approvalListEntry{
		OperationID:   "op-2",
		OperationType: "update config restriction",
		Intent:        base64.StdEncoding.EncodeToString([]byte(`{}`)),
	})
	require.NoError(t, err)
	require.Empty(t, api.approvedOp)
	require.Empty(t, api.rejectedOp)
}

func TestProcessEntry_RejectsWhenCheckFails(t *testing.T) {
	b64, _ := makeTxIntentB64(t)
	api := &fakeApprovalAPI{}
	s := testServer(t, api)
	s.checkHook = func(MakeTransactionIntent, GenericIntent) error {
		return errors.New("amount too high")
	}

	err := s.processEntry(context.Background(), approvalListEntry{
		OperationID:   "op-3",
		OperationType: operationTypeMakeTransaction,
		Intent:        b64,
	})
	require.NoError(t, err)
	require.Equal(t, "op-3", api.rejectedOp)
	require.Empty(t, api.approvedOp)
}

func TestPollOnce_ProcessesListedOps(t *testing.T) {
	b64, _ := makeTxIntentB64(t)
	api := &fakeApprovalAPI{
		entries: []approvalListEntry{{
			OperationID:   "op-1",
			OperationType: operationTypeMakeTransaction,
			Intent:        b64,
		}},
	}
	s := testServer(t, api)
	require.NoError(t, s.pollOnce(context.Background()))
	require.Equal(t, "op-1", api.approvedOp)
}

// A slow approval must not block unrelated approvals or allow an unbounded batch.
func TestPollOnce_ConcurrentApprovals(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		api := &fakeApprovalAPI{}
		for i := range 10 {
			id := fmt.Sprintf("op-%d", i)
			intent := fmt.Sprintf(`{"OperationType":"make transaction","OperationID":%q,"InitiatorID":"bot@example.com"}`, id)
			api.entries = append(api.entries, approvalListEntry{
				OperationID: id, OperationType: operationTypeMakeTransaction,
				Intent: base64.StdEncoding.EncodeToString([]byte(intent)),
			})
		}
		started := make(chan string, len(api.entries))
		releaseOne := make(chan struct{})
		api.approve = func(ctx context.Context, id string, _ []byte) error {
			started <- id
			if id == "op-1" {
				select {
				case <-releaseOne:
					return errors.New("approval request failed")
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			<-ctx.Done()
			return ctx.Err()
		}
		s := testServer(t, api)
		done := make(chan error, 1)
		go func() { done <- s.pollOnce(ctx) }()
		synctest.Wait()
		require.Len(t, started, 8)

		close(releaseOne)
		synctest.Wait()
		require.Len(t, started, 9, "a failed request must free its slot while other approvals are blocked")
		require.Empty(t, done, "the next poll must wait for this batch")

		cancel()
		synctest.Wait()
		require.ErrorIs(t, <-done, context.Canceled)
		require.Len(t, started, 9, "cancellation must leave the queued approval unprocessed")
	})
}

func TestProcessEntry_ConfirmerOnlySkipsOtherInitiator(t *testing.T) {
	b64, _ := makeTxIntentB64(t) // InitiatorID = "bot@example.com"
	api := &fakeApprovalAPI{}
	s := testServer(t, api)
	s.confirmerOnly = true
	s.selfUserID = "someone-else@example.com"

	err := s.processEntry(context.Background(), approvalListEntry{
		OperationID:   "op-skip",
		OperationType: operationTypeMakeTransaction,
		Intent:        b64,
	})
	require.NoError(t, err)
	require.Empty(t, api.approvedOp, "should not approve when initiator is not self")
	require.Empty(t, api.rejectedOp, "should not reject when initiator is not self")
}

func TestProcessEntry_ConfirmerOnlyApprovesSelf(t *testing.T) {
	b64, intent := makeTxIntentB64(t) // InitiatorID = "bot@example.com"
	api := &fakeApprovalAPI{}
	s := testServer(t, api)
	s.confirmerOnly = true
	s.selfUserID = "bot@example.com"

	err := s.processEntry(context.Background(), approvalListEntry{
		OperationID:   "op-self",
		OperationType: operationTypeMakeTransaction,
		Intent:        b64,
	})
	require.NoError(t, err)
	require.Equal(t, "op-self", api.approvedOp)
	require.NoError(t, verifySignature(intent, getPublicKey(s.privateKey), api.approvedSig))
}

func TestProcessEntry_ConfirmerOnlyCaseInsensitive(t *testing.T) {
	b64, _ := makeTxIntentB64(t) // InitiatorID = "bot@example.com"
	api := &fakeApprovalAPI{}
	s := testServer(t, api)
	s.confirmerOnly = true
	s.selfUserID = "BOT@EXAMPLE.COM"

	err := s.processEntry(context.Background(), approvalListEntry{
		OperationID:   "op-case",
		OperationType: operationTypeMakeTransaction,
		Intent:        b64,
	})
	require.NoError(t, err)
	require.Equal(t, "op-case", api.approvedOp)
}

func TestProcessEntry_DefaultModeApprovesAllInitiators(t *testing.T) {
	b64, _ := makeTxIntentB64(t)
	api := &fakeApprovalAPI{}
	s := testServer(t, api)
	// confirmerOnly defaults to false

	err := s.processEntry(context.Background(), approvalListEntry{
		OperationID:   "op-any",
		OperationType: operationTypeMakeTransaction,
		Intent:        b64,
	})
	require.NoError(t, err)
	require.Equal(t, "op-any", api.approvedOp)
}

func TestCWPClient_ApproveOmitsUserID(t *testing.T) {
	var gotBody map[string]json.RawMessage
	var gotAuth string
	srv := newCWPTestServer(t, http.MethodPost, "/approvals/approve", http.StatusNoContent, nil, func(r *http.Request, body []byte) {
		gotAuth = r.Header.Get("Authorization")
		require.NoError(t, json.Unmarshal(body, &gotBody))
	})
	c := newCWPClient(srv.URL, "cwp_testkey")
	require.NoError(t, c.Approve(context.Background(), "op-9", []byte("sig")))
	require.Equal(t, "Bearer cwp_testkey", gotAuth)
	_, hasUser := gotBody["UserID"]
	require.False(t, hasUser)
	require.Contains(t, gotBody, "OperationID")
	require.Contains(t, gotBody, "IntentSignature")
}

func TestCWPClient_ListNullBody(t *testing.T) {
	srv := newCWPTestServer(t, http.MethodGet, "/approvals/list", http.StatusOK, []byte("null"), nil)
	c := newCWPClient(srv.URL, "cwp_testkey")
	entries, err := c.List(context.Background())
	require.NoError(t, err)
	require.Empty(t, entries)
}

func TestCWPClient_RejectOmitsUserID(t *testing.T) {
	var gotBody map[string]json.RawMessage
	srv := newCWPTestServer(t, http.MethodPost, "/approvals/reject", http.StatusNoContent, nil, func(_ *http.Request, body []byte) {
		require.NoError(t, json.Unmarshal(body, &gotBody))
	})
	c := newCWPClient(srv.URL, "cwp_testkey")
	require.NoError(t, c.Reject(context.Background(), "op-reject"))
	_, hasUser := gotBody["UserID"]
	require.False(t, hasUser)
	require.Contains(t, gotBody, "OperationID")
}

func newCWPTestServer(
	t *testing.T,
	method, path string,
	status int,
	respBody []byte,
	inspect func(*http.Request, []byte),
) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, method, r.Method)
		require.Equal(t, path, r.URL.Path)
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		if inspect != nil {
			inspect(r, body)
		}
		w.WriteHeader(status)
		if len(respBody) > 0 {
			_, _ = w.Write(respBody)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}
