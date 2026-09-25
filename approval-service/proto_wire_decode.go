package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	damlv2 "github.com/digital-asset/dazl-client/v8/go/api/com/daml/ledger/api/v2"
	"github.com/digital-asset/dazl-client/v8/go/api/com/daml/ledger/api/v2/interactive"
)

// decodeProtoWireFromBase64 decodes a base64 string into a JSON-marshalable
// structure (similar to `protoc --decode_raw`).
//
// It supports two common encodings:
//  1. b64(protobuf-bytes)                          -> decoded message map
//  2. b64(json(["b64(protobuf-bytes)", ...]))      -> array of decoded messages
//  3. b64(json("b64(protobuf-bytes)"))             -> decoded message map
//
// This is intentionally schema-less: field numbers are used as keys. For
// length-delimited fields, we emit the raw bytes (base64), and optionally also:
// - "string" if the bytes are valid UTF-8
// - "message" if the bytes can be decoded as an embedded protobuf message
func decodeProtoWireFromBase64(b64 string) (any, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}

	trimmed := strings.TrimSpace(string(raw))
	if len(trimmed) > 0 && (trimmed[0] == '[' || trimmed[0] == '{' || trimmed[0] == '"') {
		var v any
		if err := json.Unmarshal([]byte(trimmed), &v); err == nil {
			switch vv := v.(type) {
			case string:
				inner, err := base64.StdEncoding.DecodeString(vv)
				if err != nil {
					return nil, fmt.Errorf("inner base64 decode: %w", err)
				}
				if decoded, ok := decodeInteractiveProtoToJSONable(inner); ok {
					return decoded, nil
				}
				if decoded, ok := decodeCantonTopologyProtoToJSONable(inner); ok {
					return decoded, nil
				}
				return decodeProtoMessage(inner, 6)
			case []any:
				out := make([]any, 0, len(vv))
				for idx, el := range vv {
					s, ok := el.(string)
					if !ok {
						out = append(out, map[string]any{
							"_error": fmt.Sprintf("element %d is not a string", idx),
							"value":  el,
						})
						continue
					}
					inner, err := base64.StdEncoding.DecodeString(s)
					if err != nil {
						out = append(out, map[string]any{
							"_error": fmt.Sprintf("element %d inner base64 decode failed: %v", idx, err),
							"value":  s,
						})
						continue
					}
					if decoded, ok := decodeInteractiveProtoToJSONable(inner); ok {
						out = append(out, decoded)
					} else if decoded, ok := decodeCantonTopologyProtoToJSONable(inner); ok {
						out = append(out, decoded)
					} else if decoded, err := decodeProtoMessage(inner, 6); err != nil {
						out = append(out, map[string]any{
							"_error": fmt.Sprintf("element %d proto decode failed: %v", idx, err),
							"value":  s,
						})
					} else {
						out = append(out, decoded)
					}
				}
				return out, nil
			}
		}
	}

	if decoded, ok := decodeInteractiveProtoToJSONable(raw); ok {
		return decoded, nil
	}
	if decoded, ok := decodeCantonTopologyProtoToJSONable(raw); ok {
		return decoded, nil
	}
	return decodeProtoMessage(raw, 6)
}

// decodeInteractiveProtoToJSONable tries to interpret b as one of the common
// DAML Ledger API interactive-submission protobuf messages (via dazl-client
// generated types). If it matches, returns the message rendered as a JSON value
// (decoded into an `any` so the caller can marshal it nicely).
//
// This is best-effort; if it can’t confidently match a type, it returns ok=false.
func decodeInteractiveProtoToJSONable(b []byte) (decoded any, ok bool) {
	type candidate struct {
		name string
		new  func() proto.Message
	}

	// NOTE: order is not important; we pick best by a simple score.
	candidates := []candidate{
		{"ExecuteSubmissionRequest", func() proto.Message { return &interactive.ExecuteSubmissionRequest{} }},
		{"PreparedTransaction", func() proto.Message { return &interactive.PreparedTransaction{} }},
		{"DamlTransaction", func() proto.Message { return &interactive.DamlTransaction{} }},
		{"DamlTransaction_Node", func() proto.Message { return &interactive.DamlTransaction_Node{} }},
		{"Metadata", func() proto.Message { return &interactive.Metadata{} }},
		{"PartySignatures", func() proto.Message { return &interactive.PartySignatures{} }},
		{"SinglePartySignatures", func() proto.Message { return &interactive.SinglePartySignatures{} }},
		{"Signature", func() proto.Message { return &damlv2.Signature{} }},
	}

	bestScore := 0
	var bestMsg proto.Message

	for _, c := range candidates {
		_ = c.name // reserved for debugging if needed
		m := c.new()
		if err := proto.Unmarshal(b, m); err != nil {
			continue
		}
		s := scoreProtoMessage(m)
		if s > bestScore {
			bestScore = s
			bestMsg = m
		}
	}

	// Require at least a couple of populated fields to avoid “matches” that only
	// decode as empty shells.
	if bestMsg == nil || bestScore < 2 {
		return nil, false
	}

	mo := protojson.MarshalOptions{
		Indent:          "  ",
		Multiline:       true,
		EmitUnpopulated: false,
		UseProtoNames:   true,
	}
	j, err := mo.Marshal(bestMsg)
	if err != nil {
		return nil, false
	}

	var v any
	if err := json.Unmarshal(j, &v); err != nil {
		// If protojson produced JSON, this shouldn’t fail, but keep safe.
		return map[string]any{"_raw_json": string(j)}, true
	}
	return v, true
}

func scoreProtoMessage(m proto.Message) int {
	rm := m.ProtoReflect()
	fields := rm.Descriptor().Fields()

	score := 0
	for i := 0; i < fields.Len(); i++ {
		f := fields.Get(i)
		if rm.Has(f) {
			score++
		}
	}
	return score
}

// decodeCantonTopologyProtoToJSONable decodes the Canton topology wrapper:
// com.digitalasset.canton.version.v1.UntypedVersionedMessage { data=1, version=2 }
//
// In your samples, version==30 and data is either:
// - com.digitalasset.canton.protocol.v30.TopologyTransaction
// - or com.digitalasset.canton.protocol.v30.SignedTopologyTransaction (then decode .transaction as TopologyTransaction)
//
// This is schema-guided (field numbers) without requiring compiled Canton protos.
func decodeCantonTopologyProtoToJSONable(b []byte) (decoded any, ok bool) {
	uvm, ok := parseUntypedVersionedMessage(b)
	if !ok || uvm.version == 0 || len(uvm.data) == 0 {
		return nil, false
	}

	// Currently we only special-case the protocol version you called out.
	if uvm.version != 30 {
		return map[string]any{
			"type":           "com.digitalasset.canton.version.v1.UntypedVersionedMessage",
			"version":        uvm.version,
			"data_bytes_b64": base64.StdEncoding.EncodeToString(uvm.data),
		}, true
	}

	// Try TopologyTransaction first.
	if tx, ok := parseTopologyTransactionV30(uvm.data); ok {
		return map[string]any{
			"type":    "com.digitalasset.canton.version.v1.UntypedVersionedMessage",
			"version": uvm.version,
			"data": map[string]any{
				"type": "com.digitalasset.canton.protocol.v30.TopologyTransaction",
				"tx":   tx,
			},
		}, true
	}

	// If it isn't a plain TopologyTransaction, try SignedTopologyTransaction.
	if stx, innerTxBytes, ok := parseSignedTopologyTransactionV30(uvm.data); ok {
		out := map[string]any{
			"type":    "com.digitalasset.canton.version.v1.UntypedVersionedMessage",
			"version": uvm.version,
			"data": map[string]any{
				"type": "com.digitalasset.canton.protocol.v30.SignedTopologyTransaction",
				"tx":   stx,
			},
		}
		if inner, ok := parseTopologyTransactionV30(innerTxBytes); ok {
			out["data"].(map[string]any)["decoded_transaction"] = inner
		}
		return out, true
	}

	// We recognized the wrapper but not the payload.
	return map[string]any{
		"type":           "com.digitalasset.canton.version.v1.UntypedVersionedMessage",
		"version":        uvm.version,
		"data_bytes_b64": base64.StdEncoding.EncodeToString(uvm.data),
	}, true
}

type untypedVersionedMessage struct {
	version int32
	data    []byte
}

func parseUntypedVersionedMessage(b []byte) (untypedVersionedMessage, bool) {
	// message UntypedVersionedMessage {
	//   oneof wrapper { bytes data = 1; }
	//   int32 version = 2;
	// }
	var out untypedVersionedMessage
	i := 0
	for i < len(b) {
		tag, n := readUvarint(b[i:])
		if n <= 0 {
			return untypedVersionedMessage{}, false
		}
		i += n
		fieldNum := tag >> 3
		wireType := tag & 0x7
		switch fieldNum {
		case 1: // data (bytes)
			if wireType != 2 {
				return untypedVersionedMessage{}, false
			}
			l, n := readUvarint(b[i:])
			if n <= 0 {
				return untypedVersionedMessage{}, false
			}
			i += n
			if l > uint64(len(b)-i) {
				return untypedVersionedMessage{}, false
			}
			out.data = b[i : i+int(l)]
			i += int(l)
		case 2: // version (int32 varint)
			if wireType != 0 {
				return untypedVersionedMessage{}, false
			}
			v, n := readUvarint(b[i:])
			if n <= 0 {
				return untypedVersionedMessage{}, false
			}
			out.version = int32(v)
			i += n
		default:
			// skip unknown fields
			next, ok := skipWireValue(b, i, wireType)
			if !ok {
				return untypedVersionedMessage{}, false
			}
			i = next
		}
	}
	return out, out.version != 0 && len(out.data) > 0
}

func parseTopologyTransactionV30(b []byte) (map[string]any, bool) {
	// message TopologyTransaction {
	//   Enums.TopologyChangeOp operation = 1;
	//   uint32 serial = 2;
	//   TopologyMapping mapping = 3;
	// }
	var (
		opSet, serialSet, mappingSet bool
		op                           uint64
		serial                       uint64
		mappingBytes                 []byte
	)
	i := 0
	for i < len(b) {
		tag, n := readUvarint(b[i:])
		if n <= 0 {
			return nil, false
		}
		i += n
		fieldNum := tag >> 3
		wireType := tag & 0x7
		switch fieldNum {
		case 1: // operation
			if wireType != 0 {
				return nil, false
			}
			v, n := readUvarint(b[i:])
			if n <= 0 {
				return nil, false
			}
			op, opSet = v, true
			i += n
		case 2: // serial
			if wireType != 0 {
				return nil, false
			}
			v, n := readUvarint(b[i:])
			if n <= 0 {
				return nil, false
			}
			serial, serialSet = v, true
			i += n
		case 3: // mapping
			if wireType != 2 {
				return nil, false
			}
			l, n := readUvarint(b[i:])
			if n <= 0 {
				return nil, false
			}
			i += n
			if l > uint64(len(b)-i) {
				return nil, false
			}
			mappingBytes, mappingSet = b[i:i+int(l)], true
			i += int(l)
		default:
			next, ok := skipWireValue(b, i, wireType)
			if !ok {
				return nil, false
			}
			i = next
		}
	}
	// If it doesn't have mapping, it's not the message we care about (avoid false positives).
	if !mappingSet {
		return nil, false
	}
	out := map[string]any{}
	if opSet {
		out["operation"] = topologyChangeOpName(op)
		out["operation_value"] = op
	}
	if serialSet {
		out["serial"] = serial
	}
	if mappingSet {
		if mapping, ok := parseTopologyMappingV30(mappingBytes); ok {
			out["mapping"] = mapping
		} else {
			out["mapping_bytes_b64"] = base64.StdEncoding.EncodeToString(mappingBytes)
		}
	}
	return out, true
}

func parseTopologyMappingV30(b []byte) (map[string]any, bool) {
	// message TopologyMapping { oneof mapping { ... party_to_participant = 9; ... } }
	i := 0
	for i < len(b) {
		tag, n := readUvarint(b[i:])
		if n <= 0 {
			return nil, false
		}
		i += n
		fieldNum := tag >> 3
		wireType := tag & 0x7
		if wireType != 2 {
			next, ok := skipWireValue(b, i, wireType)
			if !ok {
				return nil, false
			}
			i = next
			continue
		}
		l, n := readUvarint(b[i:])
		if n <= 0 {
			return nil, false
		}
		i += n
		if l > uint64(len(b)-i) {
			return nil, false
		}
		payload := b[i : i+int(l)]
		i += int(l)

		// We only special-case the one you asked about.
		if fieldNum == 9 {
			if ptp, ok := parsePartyToParticipantV30(payload); ok {
				return map[string]any{
					"mapping_type":         "party_to_participant",
					"party_to_participant": ptp,
				}, true
			}
			return map[string]any{
				"mapping_type": "party_to_participant",
				"bytes_b64":    base64.StdEncoding.EncodeToString(payload),
			}, true
		}
	}
	return nil, false
}

func parsePartyToParticipantV30(b []byte) (map[string]any, bool) {
	// message PartyToParticipant {
	//   string party = 1;
	//   uint32 threshold = 2;
	//   repeated HostingParticipant participants = 3;
	// }
	var (
		party        string
		thresholdSet bool
		threshold    uint64
		participants []any
	)
	i := 0
	for i < len(b) {
		tag, n := readUvarint(b[i:])
		if n <= 0 {
			return nil, false
		}
		i += n
		fieldNum := tag >> 3
		wireType := tag & 0x7
		switch fieldNum {
		case 1: // party (string)
			if wireType != 2 {
				return nil, false
			}
			s, next, ok := readString(b, i)
			if !ok {
				return nil, false
			}
			party = s
			i = next
		case 2: // threshold (varint)
			if wireType != 0 {
				return nil, false
			}
			v, n := readUvarint(b[i:])
			if n <= 0 {
				return nil, false
			}
			threshold, thresholdSet = v, true
			i += n
		case 3: // participants (bytes)
			if wireType != 2 {
				return nil, false
			}
			payload, next, ok := readBytes(b, i)
			if !ok {
				return nil, false
			}
			if hp, ok := parseHostingParticipantV30(payload); ok {
				participants = append(participants, hp)
			} else {
				participants = append(participants, map[string]any{
					"bytes_b64": base64.StdEncoding.EncodeToString(payload),
				})
			}
			i = next
		default:
			next, ok := skipWireValue(b, i, wireType)
			if !ok {
				return nil, false
			}
			i = next
		}
	}
	if party == "" && !thresholdSet && len(participants) == 0 {
		return nil, false
	}
	out := map[string]any{
		"party":        party,
		"participants": participants,
	}
	if thresholdSet {
		out["threshold"] = threshold
	}
	return out, true
}

func parseHostingParticipantV30(b []byte) (map[string]any, bool) {
	// message HostingParticipant {
	//   string participant_uid = 1;
	//   Enums.ParticipantPermission permission = 2;
	//   Onboarding onboarding = 3; // optional (empty message)
	// }
	var (
		uid        string
		permSet    bool
		permVal    uint64
		onboarding bool
	)
	i := 0
	for i < len(b) {
		tag, n := readUvarint(b[i:])
		if n <= 0 {
			return nil, false
		}
		i += n
		fieldNum := tag >> 3
		wireType := tag & 0x7
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return nil, false
			}
			s, next, ok := readString(b, i)
			if !ok {
				return nil, false
			}
			uid = s
			i = next
		case 2:
			if wireType != 0 {
				return nil, false
			}
			v, n := readUvarint(b[i:])
			if n <= 0 {
				return nil, false
			}
			permVal, permSet = v, true
			i += n
		case 3:
			// Onboarding is an empty message; presence matters.
			if wireType != 2 {
				return nil, false
			}
			_, next, ok := readBytes(b, i)
			if !ok {
				return nil, false
			}
			onboarding = true
			i = next
		default:
			next, ok := skipWireValue(b, i, wireType)
			if !ok {
				return nil, false
			}
			i = next
		}
	}
	if uid == "" && !permSet && !onboarding {
		return nil, false
	}
	out := map[string]any{
		"participant_uid": uid,
	}
	if permSet {
		out["permission"] = participantPermissionName(permVal)
		out["permission_value"] = permVal
	}
	if onboarding {
		out["onboarding"] = true
	}
	return out, true
}

func parseSignedTopologyTransactionV30(b []byte) (map[string]any, []byte, bool) {
	// message SignedTopologyTransaction {
	//   bytes transaction = 1; // serialized TopologyTransaction
	//   repeated Signature signatures = 2;
	//   bool proposal = 3;
	//   repeated MultiTransactionSignatures multi_transaction_signatures = 4;
	// }
	var (
		txBytes  []byte
		proposal bool
	)
	i := 0
	for i < len(b) {
		tag, n := readUvarint(b[i:])
		if n <= 0 {
			return nil, nil, false
		}
		i += n
		fieldNum := tag >> 3
		wireType := tag & 0x7
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return nil, nil, false
			}
			payload, next, ok := readBytes(b, i)
			if !ok {
				return nil, nil, false
			}
			txBytes = payload
			i = next
		case 3:
			if wireType != 0 {
				return nil, nil, false
			}
			v, n := readUvarint(b[i:])
			if n <= 0 {
				return nil, nil, false
			}
			proposal = v != 0
			i += n
		default:
			next, ok := skipWireValue(b, i, wireType)
			if !ok {
				return nil, nil, false
			}
			i = next
		}
	}
	if len(txBytes) == 0 {
		return nil, nil, false
	}
	return map[string]any{
		"proposal":              proposal,
		"transaction_bytes_b64": base64.StdEncoding.EncodeToString(txBytes),
	}, txBytes, true
}

func topologyChangeOpName(v uint64) string {
	switch v {
	case 1:
		return "TOPOLOGY_CHANGE_OP_ADD_REPLACE"
	case 2:
		return "TOPOLOGY_CHANGE_OP_REMOVE"
	default:
		return "TOPOLOGY_CHANGE_OP_UNSPECIFIED"
	}
}

func participantPermissionName(v uint64) string {
	switch v {
	case 1:
		return "PARTICIPANT_PERMISSION_SUBMISSION"
	case 2:
		return "PARTICIPANT_PERMISSION_CONFIRMATION"
	case 3:
		return "PARTICIPANT_PERMISSION_OBSERVATION"
	default:
		return "PARTICIPANT_PERMISSION_UNSPECIFIED"
	}
}

func readBytes(b []byte, i int) ([]byte, int, bool) {
	l, n := readUvarint(b[i:])
	if n <= 0 {
		return nil, i, false
	}
	i2 := i + n
	if l > uint64(len(b)-i2) {
		return nil, i, false
	}
	return b[i2 : i2+int(l)], i2 + int(l), true
}

func readString(b []byte, i int) (string, int, bool) {
	payload, next, ok := readBytes(b, i)
	if !ok {
		return "", i, false
	}
	if !utf8.Valid(payload) {
		return "", i, false
	}
	return string(payload), next, true
}

func skipWireValue(b []byte, i int, wireType uint64) (int, bool) {
	switch wireType {
	case 0: // varint
		_, n := readUvarint(b[i:])
		if n <= 0 {
			return i, false
		}
		return i + n, true
	case 1: // fixed64
		if i+8 > len(b) {
			return i, false
		}
		return i + 8, true
	case 2: // bytes
		_, next, ok := readBytes(b, i)
		return next, ok
	case 5: // fixed32
		if i+4 > len(b) {
			return i, false
		}
		return i + 4, true
	default:
		return i, false
	}
}

func decodeProtoMessage(b []byte, depth int) (map[string]any, error) {
	if depth <= 0 {
		return map[string]any{
			"_truncated": true,
			"bytes_b64":  base64.StdEncoding.EncodeToString(b),
		}, nil
	}

	out := map[string]any{}
	i := 0
	for i < len(b) {
		tag, n := readUvarint(b[i:])
		if n <= 0 {
			return nil, fmt.Errorf("invalid varint tag at offset %d", i)
		}
		i += n
		fieldNum := tag >> 3
		wireType := tag & 0x7
		if fieldNum == 0 {
			return nil, fmt.Errorf("invalid field number 0 at offset %d", i-n)
		}

		key := fmt.Sprintf("%d", fieldNum)
		val, next, err := decodeProtoValue(b, i, wireType, depth)
		if err != nil {
			return nil, err
		}
		i = next

		// Protobuf fields may repeat; keep an array.
		if existing, ok := out[key]; ok {
			switch e := existing.(type) {
			case []any:
				out[key] = append(e, val)
			default:
				out[key] = []any{e, val}
			}
		} else {
			out[key] = val
		}
	}

	return out, nil
}

func decodeProtoValue(b []byte, i int, wireType uint64, depth int) (any, int, error) {
	switch wireType {
	case 0: // varint
		v, n := readUvarint(b[i:])
		if n <= 0 {
			return nil, i, fmt.Errorf("invalid varint at offset %d", i)
		}
		return map[string]any{
			"wire":  "varint",
			"value": v,
		}, i + n, nil

	case 1: // 64-bit
		if i+8 > len(b) {
			return nil, i, fmt.Errorf("truncated fixed64 at offset %d", i)
		}
		v := uint64(b[i]) |
			(uint64(b[i+1]) << 8) |
			(uint64(b[i+2]) << 16) |
			(uint64(b[i+3]) << 24) |
			(uint64(b[i+4]) << 32) |
			(uint64(b[i+5]) << 40) |
			(uint64(b[i+6]) << 48) |
			(uint64(b[i+7]) << 56)
		return map[string]any{
			"wire":  "fixed64",
			"value": v,
		}, i + 8, nil

	case 2: // length-delimited
		l, n := readUvarint(b[i:])
		if n <= 0 {
			return nil, i, fmt.Errorf("invalid length varint at offset %d", i)
		}
		i2 := i + n
		if l > uint64(len(b)-i2) {
			return nil, i, fmt.Errorf("truncated length-delimited at offset %d (len=%d)", i, l)
		}
		payload := b[i2 : i2+int(l)]

		obj := map[string]any{
			"wire":      "bytes",
			"bytes_b64": base64.StdEncoding.EncodeToString(payload),
		}

		if utf8.Valid(payload) {
			obj["string"] = string(payload)
		}

		// Try to interpret as embedded message (best-effort).
		if len(payload) > 0 {
			if m, err := decodeProtoMessage(payload, depth-1); err == nil && len(m) > 0 {
				obj["message"] = m
			}
		}

		return obj, i2 + int(l), nil

	case 5: // 32-bit
		if i+4 > len(b) {
			return nil, i, fmt.Errorf("truncated fixed32 at offset %d", i)
		}
		v := uint32(b[i]) |
			(uint32(b[i+1]) << 8) |
			(uint32(b[i+2]) << 16) |
			(uint32(b[i+3]) << 24)
		return map[string]any{
			"wire":  "fixed32",
			"value": v,
		}, i + 4, nil

	default:
		return nil, i, fmt.Errorf("unsupported wire type %d at offset %d", wireType, i)
	}
}

// readUvarint reads a protobuf base-128 varint.
// Returns (value, bytesRead). bytesRead <= 0 indicates failure.
func readUvarint(b []byte) (uint64, int) {
	var (
		x uint64
		s uint
	)
	for i := 0; i < len(b); i++ {
		c := b[i]
		if c < 0x80 {
			if i > 9 || (i == 9 && c > 1) {
				return 0, -1 // overflow
			}
			return x | uint64(c)<<s, i + 1
		}
		x |= uint64(c&0x7f) << s
		s += 7
	}
	return 0, 0
}
