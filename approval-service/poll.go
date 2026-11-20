package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// syncPending lists approvals already waiting for this user. The events
// socket does not replay, so each connection (and -once) runs this once.
func (s *Server) syncPending(ctx context.Context) error {
	entries, err := s.cwp.List(ctx)
	if err != nil {
		return err
	}
	s.logger.Debug().Int("count", len(entries)).Msg("pending approval catch-up")
	for _, entry := range entries {
		if reason := s.skipReason(entry.OperationID); reason != "" {
			s.logger.Debug().
				Str("operation_id", entry.OperationID).
				Str("operation_type", entry.OperationType).
				Str("reason", reason).
				Msg("skipped")
			continue
		}
		s.logger.Debug().
			Str("operation_id", entry.OperationID).
			Str("operation_type", entry.OperationType).
			Msg("pending approval")
		if err := s.processEntry(ctx, entry); err != nil {
			s.logger.Error().
				Err(err).
				Str("operation_id", entry.OperationID).
				Str("operation_type", entry.OperationType).
				Msg("failed to process pending approval")
			continue
		}
		s.markSeen(entry.OperationID)
	}
	return nil
}

func (s *Server) processEntry(ctx context.Context, entry approvalListEntry) error {
	if !isSignableOperationType(entry.OperationType) {
		s.logger.Info().
			Str("operation_id", entry.OperationID).
			Str("operation_type", entry.OperationType).
			Str("reason", "unsupported operation type").
			Msg("skipped")
		return nil
	}

	intentBytes, err := base64.StdEncoding.DecodeString(entry.Intent)
	if err != nil {
		return fmt.Errorf("decode intent: %w", err)
	}

	if s.isCancelled(entry.OperationID) {
		s.logger.Info().
			Str("operation_id", entry.OperationID).
			Str("operation_type", entry.OperationType).
			Str("reason", "approval cancelled").
			Msg("skipped")
		return nil
	}

	if s.confirmerOnly {
		initiator := extractInitiatorID(intentBytes)
		if !strings.EqualFold(initiator, s.selfUserID) {
			s.logger.Info().
				Str("operation_id", entry.OperationID).
				Str("operation_type", entry.OperationType).
				Str("initiator_id", initiator).
				Str("reason", "confirmer-only").
				Msg("skipped")
			return nil
		}
	}

	if entry.OperationType == operationTypeMakeTransaction {
		var makeTxIntent MakeTransactionIntent
		if err := json.Unmarshal(intentBytes, &makeTxIntent); err != nil {
			return fmt.Errorf("unmarshal make transaction intent: %w", err)
		}

		genericIntent := GenericIntent{
			OperationType: entry.OperationType,
			Intent:        intentBytes,
		}
		genericIntent.Initiator.UserID = makeTxIntent.InitiatorID
		if err := s.checkMakeTransactionIntent(makeTxIntent, genericIntent); err != nil {
			s.logger.Warn().
				Err(err).
				Str("operation_id", entry.OperationID).
				RawJSON("intent", intentBytes).
				Msg("make transaction intent did not pass automated checks")
			if s.isCancelled(entry.OperationID) {
				s.logger.Info().
					Str("operation_id", entry.OperationID).
					Str("operation_type", entry.OperationType).
					Str("reason", "approval cancelled").
					Msg("skipped")
				return nil
			}
			if rejectErr := s.cwp.Reject(ctx, entry.OperationID); rejectErr != nil {
				return rejectErr
			}
			s.logger.Info().
				Str("operation_id", entry.OperationID).
				Str("operation_type", entry.OperationType).
				Err(err).
				Msg("rejected")
			return nil
		}

		s.logIntent(entry, intentBytes)
		if strings.EqualFold(makeTxIntent.Asset, "CC") && makeTxIntent.RawTransaction != "" {
			if decoded, err := decodeProtoWireFromBase64(makeTxIntent.RawTransaction); err != nil {
				s.logger.Warn().Err(err).Msg("failed to decode CC RawTransaction as protobuf wire format")
			} else if decodedJSON, err := json.Marshal(decoded); err == nil {
				s.logger.Debug().
					Str("operation_id", entry.OperationID).
					RawJSON("raw_transaction", decodedJSON).
					Msg("decoded canton raw transaction")
			}
		}
	} else {
		s.logIntent(entry, intentBytes)
	}

	signature, err := signIntent(s.privateKey, intentBytes)
	if err != nil {
		return fmt.Errorf("sign intent: %w", err)
	}

	s.logger.Debug().
		Str("operation_id", entry.OperationID).
		Str("signature_b64", base64.StdEncoding.EncodeToString(signature)).
		Str("signature_hex", fmt.Sprintf("%x", signature)).
		Msg("approval signature")

	if s.isCancelled(entry.OperationID) {
		s.logger.Info().
			Str("operation_id", entry.OperationID).
			Str("operation_type", entry.OperationType).
			Str("reason", "approval cancelled").
			Msg("skipped")
		return nil
	}

	if err := s.cwp.Approve(ctx, entry.OperationID, signature); err != nil {
		return err
	}
	s.logger.Info().
		Str("operation_id", entry.OperationID).
		Str("operation_type", entry.OperationType).
		Msg("approved")
	return nil
}

func (s *Server) logIntent(entry approvalListEntry, intentBytes []byte) {
	eventLog := s.logger.Debug().
		Str("operation_id", entry.OperationID).
		Str("operation_type", entry.OperationType)
	if json.Valid(intentBytes) {
		eventLog = eventLog.RawJSON("intent", intentBytes)
	}
	eventLog.Msg("approval intent")
}

func isSignableOperationType(opType string) bool {
	switch opType {
	case operationTypeMakeTransaction, operationTypeTransfer, operationTypeCallContract, operationTypeDeployContract:
		return true
	default:
		return false
	}
}
