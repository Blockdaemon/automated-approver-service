package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

func (s *Server) pollLoop(ctx context.Context) {
	s.logger.Info().
		Dur("interval", s.pollInterval).
		Msg("polling CWP approvals")

	if err := s.pollOnce(ctx); err != nil {
		s.logger.Error().Err(err).Msg("approvals poll failed")
	}

	ticker := time.NewTicker(s.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.pollOnce(ctx); err != nil {
				s.logger.Error().Err(err).Msg("approvals poll failed")
			}
		}
	}
}

func (s *Server) pollOnce(ctx context.Context) error {
	entries, err := s.cwp.List(ctx)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err := s.processEntry(ctx, entry); err != nil {
			s.logger.Error().
				Err(err).
				Str("operation_id", entry.OperationID).
				Str("operation_type", entry.OperationType).
				Msg("failed to process pending approval")
		}
	}
	return nil
}

func (s *Server) processEntry(ctx context.Context, entry approvalListEntry) error {
	if !isSignableOperationType(entry.OperationType) {
		s.logger.Info().
			Str("operation_id", entry.OperationID).
			Str("operation_type", entry.OperationType).
			Msg("skipping unsupported operation type")
		return nil
	}

	intentBytes, err := base64.StdEncoding.DecodeString(entry.Intent)
	if err != nil {
		return fmt.Errorf("decode intent: %w", err)
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
				Msg("make transaction intent did not pass automated checks; rejecting")
			return s.cwp.Reject(ctx, entry.OperationID)
		}

		intentJSON, _ := json.MarshalIndent(makeTxIntent, "", "  ")
		fmt.Printf("\n=== MAKE TRANSACTION INTENT ===\n%s\n", string(intentJSON))

		if strings.EqualFold(makeTxIntent.Asset, "CC") && makeTxIntent.RawTransaction != "" {
			if decoded, err := decodeProtoWireFromBase64(makeTxIntent.RawTransaction); err != nil {
				s.logger.Warn().Err(err).Msg("failed to decode CC RawTransaction as protobuf wire format")
			} else if decodedJSON, err := json.MarshalIndent(decoded, "", "  "); err == nil {
				fmt.Printf("\n=== DECODED RAW TX (PROTO WIRE, CC) ===\n%s\n", string(decodedJSON))
			}
		}
	} else {
		fmt.Printf("\n=== INTENT (%s) ===\n%s\n", entry.OperationType, intentBytes)
	}

	signature, err := signIntent(s.privateKey, intentBytes)
	if err != nil {
		return fmt.Errorf("sign intent: %w", err)
	}

	signatureB64 := base64.StdEncoding.EncodeToString(signature)
	fmt.Printf("\n=== SIGNATURE (APPROVED) ===\n")
	fmt.Printf("Signature (Base64): %s\n", signatureB64)
	fmt.Printf("Signature (Hex): %x\n", signature)
	fmt.Printf("========================\n\n")

	return s.cwp.Approve(ctx, entry.OperationID, signature)
}

func isSignableOperationType(opType string) bool {
	return opType == operationTypeMakeTransaction || opType == operationTypeTransfer
}
