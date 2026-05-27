package main

import (
	"encoding/json"
	"time"
)

// MakeTransactionIntent mirrors MPA's TransactionIntent JSON (operation type "make transaction").
// Transfers, contract calls, deploys, and raw-sign flows use this shape via CWP makeTransaction.
type MakeTransactionIntent struct {
	OperationType string    `json:"OperationType"`
	OperationID   string    `json:"OperationID"`
	InitiatorID   string    `json:"InitiatorID"`
	InitiatorName string    `json:"InitiatorName"`
	Timestamp     time.Time `json:"Timestamp"`
	ChainName     string    `json:"ChainName,omitempty"`
	CAIP19        string    `json:"CAIP19,omitempty"`
	Asset         string    `json:"Asset"`
	TestNetwork   bool      `json:"TestNetwork"`
	Source        struct {
		MasterKeyName string `json:"MasterKeyName,omitempty"`
		AccountName   string `json:"AccountName,omitempty"`
		AddressIndex  *int   `json:"AddressIndex,omitempty"`
		Address       string `json:"Address,omitempty"`
	} `json:"Source"`
	Destination []struct {
		MasterKeyName string `json:"MasterKeyName,omitempty"`
		AccountName   string `json:"AccountName,omitempty"`
		AddressIndex  *int   `json:"AddressIndex,omitempty"`
		Address       string `json:"Address,omitempty"`
		Amount        string `json:"Amount"`
	} `json:"Destination"`
	RawTransaction        string `json:"RawTransaction,omitempty"`
	DecodedRawTransaction string `json:"DecodedRawTransaction,omitempty"`
	TxHash                string `json:"TxHash,omitempty"`
	Function              *struct {
		Name string `json:"Name,omitempty"`
	} `json:"Function,omitempty"`

	// ChainParameters are embedded (promoted) on MPA TransactionIntent, not nested under BlockchainSpec.
	EVM       *EVMSpec        `json:"EVM,omitempty"`
	Bitcoin   json.RawMessage `json:"Bitcoin,omitempty"`
	Substrate json.RawMessage `json:"Substrate,omitempty"`
	Solana    json.RawMessage `json:"Solana,omitempty"`
	TVM       json.RawMessage `json:"TVM,omitempty"`
	Canton    json.RawMessage `json:"Canton,omitempty"`
	Stellar   json.RawMessage `json:"Stellar,omitempty"`
}

type EVMSpec struct {
	Gas                  json.Number `json:"Gas,omitempty"`
	MaxPriorityFeePerGas json.Number `json:"MaxPriorityFeePerGas,omitempty"`
	MaxFeePerGas         json.Number `json:"MaxFeePerGas,omitempty"`
	Nonce                json.Number `json:"Nonce,omitempty"`
	Data                 string      `json:"Data,omitempty"`
}

type GenericIntent struct {
	OperationType  string `json:"OperationType"`
	Intent         []byte `json:"Intent"`
	IntentMetadata struct {
		RateInfo struct {
			Rate         float64 `json:"Rate"`
			FromCurrency string  `json:"FromCurrency"`
			ToCurrency   string  `json:"ToCurrency"`
		} `json:"RateInfo"`
	} `json:"IntentMetadata"`
	Initiator struct {
		UserName string `json:"UserName"`
		UserID   string `json:"UserID"`
	} `json:"Initiator"`
	Timestamp time.Time `json:"Timestamp"`
}
