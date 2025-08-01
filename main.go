package main

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"time"

	"github.com/ethereum/go-ethereum/common/math" // For HexOrDecimal256
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

const (
	exchangeURL = "https://api.hyperliquid.xyz/exchange"
	infoURL     = "https://api.hyperliquid.xyz/info"
	chainID     = 42161    // Arbitrum One Chain ID
	chainIDHex  = "0xa4b1" // Arbitrum One Chain ID in hex
)

// DelegateAction represents the action payload for delegation/undelegation.
// This structure is used both for the JSON request and for EIP-712 signing.
type DelegateAction struct {
	Type             string   `json:"type"`
	HyperliquidChain string   `json:"hyperliquidChain"`
	SignatureChainId string   `json:"signatureChainId"`
	Validator        string   `json:"validator"`
	IsUndelegate     bool     `json:"isUndelegate"`
	Wei              *big.Int `json:"wei"`   // Reverted: JSON should be a number, not a string
	Nonce            int64    `json:"nonce"` // Nonce is required inside the action for EIP-712 signing
}

// Signature represents the R, S, V components of an Ethereum signature
type Signature struct {
	R string `json:"r"`
	S string `json:"s"`
	V uint8  `json:"v"`
}

// DelegateRequest is the top-level request body sent to the exchange API
type DelegateRequest struct {
	Action    DelegateAction `json:"action"`
	Nonce     int64          `json:"nonce"` // Outer nonce, must match action.Nonce
	Signature Signature      `json:"signature"`
}

// DelegationQuery for fetching existing delegations
type DelegationQuery struct {
	Type string `json:"type"`
	User string `json:"user"`
}

// DelegationItem represents a single delegation entry returned by the info API
type DelegationItem struct {
	Validator            string `json:"validator"`
	Amount               string `json:"amount"` // Amount is returned as a string (e.g., "41.71977419")
	LockedUntilTimestamp int64  `json:"lockedUntilTimestamp"`
}

// BalanceQuery for fetching user balances
type BalanceQuery struct {
	Type string `json:"type"`
	User string `json:"user"`
}

// BalanceItem represents a single coin balance
type BalanceItem struct {
	Coin  string `json:"coin"`
	Hold  string `json:"hold"`
	Total string `json:"total"`
}

// BalanceResponse is the structure for the balances API response
type BalanceResponse struct {
	Balances []BalanceItem `json:"balances"`
}

// fetchDelegations retrieves the current delegations for a given user address.
func fetchDelegations(masterAddress string) ([]DelegationItem, error) {
	q := DelegationQuery{
		Type: "delegations",
		User: masterAddress,
	}
	b, err := json.Marshal(q)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal delegation query: %w", err)
	}

	resp, err := http.Post(infoURL, "application/json", bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("failed to send delegation query request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := ioutil.ReadAll(resp.Body) // Read body even on error for more info
		return nil, fmt.Errorf("delegation query failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read delegation query response body: %w", err)
	}

	var respData []DelegationItem
	if err := json.Unmarshal(body, &respData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal delegation query response: %w", err)
	}
	return respData, nil
}

// fetchBalances retrieves the spot balances for a given user address.
func fetchBalances(masterAddress string) (*BalanceResponse, error) {
	q := BalanceQuery{
		Type: "spotClearinghouseState", // As per previous code, this type is used for balances
		User: masterAddress,
	}
	b, err := json.Marshal(q)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal balance query: %w", err)
	}

	resp, err := http.Post(infoURL, "application/json", bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("failed to send balance query request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("balance query failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read balance query response body: %w", err)
	}

	var respData BalanceResponse
	if err := json.Unmarshal(body, &respData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal balance query response: %w", err)
	}
	return &respData, nil
}

// signEIP712 generates an EIP-712 signature for the DelegateAction.
func signEIP712(priv *ecdsa.PrivateKey, action DelegateAction) (Signature, error) {
	types := apitypes.Types{
		"EIP712Domain": []apitypes.Type{
			{Name: "name", Type: "string"},
			{Name: "version", Type: "string"},
			{Name: "chainId", Type: "uint256"},
			// Optional: add if Hyperliquid's domain requires it (e.g., verifyingContract, salt)
			// {Name: "verifyingContract", Type: "address"},
			// {Name: "salt", Type: "bytes32"},
		},
		"tokenDelegate": []apitypes.Type{
			{Name: "type", Type: "string"},
			{Name: "hyperliquidChain", Type: "string"},
			{Name: "signatureChainId", Type: "string"},
			{Name: "validator", Type: "address"},
			{Name: "isUndelegate", Type: "bool"},
			{Name: "wei", Type: "uint256"},  // Type definition for EIP-712
			{Name: "nonce", Type: "uint64"}, // Type definition for EIP-712
		},
	}

	chainIDBig := big.NewInt(chainID)
	// Convert big.Int to *math.HexOrDecimal256 as required by apitypes.TypedDataDomain
	chainIDHexOrDec := (*math.HexOrDecimal256)(chainIDBig)

	typedData := apitypes.TypedData{
		Types:       types,
		PrimaryType: "tokenDelegate",
		Domain: apitypes.TypedDataDomain{
			Name:    "Hyperliquid",
			Version: "1",
			ChainId: chainIDHexOrDec, // Use the converted type
		},
		Message: map[string]interface{}{
			"type":             action.Type,
			"hyperliquidChain": action.HyperliquidChain,
			"signatureChainId": action.SignatureChainId,
			"validator":        action.Validator,
			"isUndelegate":     action.IsUndelegate,
			"wei":              action.Wei.String(),             // Important: Pass wei as a string to preserve large integer precision for hashing
			"nonce":            fmt.Sprintf("%d", action.Nonce), // Important: Pass nonce as a string for hashing uint64 types
		},
	}

	domainSeparator, err := typedData.HashStruct("EIP712Domain", typedData.Domain.Map())
	if err != nil {
		return Signature{}, fmt.Errorf("failed to hash EIP712Domain: %w", err)
	}
	messageHash, err := typedData.HashStruct(typedData.PrimaryType, typedData.Message)
	if err != nil {
		return Signature{}, fmt.Errorf("failed to hash primary type message: %w", err)
	}

	// EIP-712 signature standard prefix (0x1901) + domainSeparator + messageHash
	dataToSign := append([]byte("\x19\x01"), append(domainSeparator, messageHash...)...)
	hash := crypto.Keccak256(dataToSign)

	sig, err := crypto.Sign(hash, priv)
	if err != nil {
		return Signature{}, fmt.Errorf("failed to sign hash: %w", err)
	}

	// Extract R, S, V components. V needs to be adjusted (+27) for Ethereum standard.
	return Signature{
		R: fmt.Sprintf("0x%x", sig[:32]),
		S: fmt.Sprintf("0x%x", sig[32:64]),
		V: sig[64] + 27,
	}, nil
}

// undelegateAll fetches all current delegations and attempts to undelegate them one by one.
func undelegateAll(privKey *ecdsa.PrivateKey, masterAddress string) error {
	delegations, err := fetchDelegations(masterAddress)
	if err != nil {
		return fmt.Errorf("error fetching delegations: %w", err)
	}

	if len(delegations) == 0 {
		fmt.Println("No delegations found to undelegate.")
		return nil // No error if nothing to undelegate
	}

	for _, d := range delegations {
		// Convert the human-readable amount string to wei (big.Int)
		amountFloat := new(big.Float)
		if _, ok := amountFloat.SetString(d.Amount); !ok {
			return fmt.Errorf("invalid amount string '%s' for delegation", d.Amount)
		}
		// Assuming 18 decimals for the token (common for ETH and many ERC-20s)
		weiPerToken := new(big.Float).SetFloat64(1e18)
		amountWei := new(big.Float).Mul(amountFloat, weiPerToken)
		amountWeiInt, _ := amountWei.Int(nil) // Convert to *big.Int, discarding accuracy info for the fractional part

		currentTimestampMilli := time.Now().UnixMilli()

		action := DelegateAction{
			Type:             "tokenDelegate",
			HyperliquidChain: "Mainnet", // Use "Testnet" for testnet environment if needed
			SignatureChainId: chainIDHex,
			Validator:        d.Validator,
			IsUndelegate:     true,
			Wei:              amountWeiInt,
			Nonce:            currentTimestampMilli, // This nonce is part of the signed message and JSON payload
		}

		sig, err := signEIP712(privKey, action)
		if err != nil {
			return fmt.Errorf("failed to sign undelegate action for validator %s: %w", d.Validator, err)
		}

		req := DelegateRequest{
			Action:    action,
			Nonce:     currentTimestampMilli,
			Signature: sig,
		}

		body, err := json.Marshal(req)
		if err != nil {
			return fmt.Errorf("failed to marshal undelegate request body: %w", err)
		}

		fmt.Printf("\nAttempting to undelegate %s from %s...\n", d.Amount, d.Validator)
		fmt.Printf("Sending JSON: %s\n", string(body)) // For debugging: print the raw JSON being sent

		client := &http.Client{Timeout: 30 * time.Second} // Add a timeout to the HTTP client
		resp, err := client.Post(exchangeURL, "application/json", bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("failed to send undelegate request: %w", err)
		}
		defer resp.Body.Close()

		respBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read undelegate response body: %w", err)
		}

		fmt.Println("--- Undelegate Response ---")
		fmt.Println(string(respBody))

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("undelegation for validator %s failed with status %d: %s", d.Validator, resp.StatusCode, string(respBody))
		}
		fmt.Printf("Successfully sent undelegate request for validator %s.\n", d.Validator)
		time.Sleep(500 * time.Millisecond)
	}
	return nil
}

func main() {
	privHex := "a6121f8763a5c29d2fe176d4d7168bdb727b6d6ef6e625e7775d3a258e8e36e7"

	privKeyBytes, err := hex.DecodeString(privHex)
	if err != nil {
		log.Fatalf("Invalid hex private key: %v", err)
	}
	privKey, err := crypto.ToECDSA(privKeyBytes)
	if err != nil {
		log.Fatalf("Invalid private key: %v", err)
	}

	masterAddress := crypto.PubkeyToAddress(privKey.PublicKey).Hex()
	fmt.Println("Master Address:", masterAddress)

	fmt.Println("\n--- Fetching Delegations ---")
	delegations, err := fetchDelegations(masterAddress)
	if err != nil {
		log.Fatalf("Error fetching delegations: %v", err)
	}
	if len(delegations) == 0 {
		fmt.Println("No active delegations found.")
	} else {
		for _, d := range delegations {
			fmt.Printf("Validator: %s, Amount: %s, LockedUntil: %d\n", d.Validator, d.Amount, d.LockedUntilTimestamp)
		}
	}

	fmt.Println("\n--- Fetching Spot Balances ---")
	balances, err := fetchBalances(masterAddress)
	if err != nil {
		log.Fatalf("Error fetching balances: %v", err)
	}
	if len(balances.Balances) == 0 {
		fmt.Println("No spot balances found.")
	} else {
		for _, b := range balances.Balances {
			fmt.Printf("Coin: %s, Total: %s, Hold: %s\n", b.Coin, b.Total, b.Hold)
		}
	}

	fmt.Println("\n--- Starting Undelegate All Process ---")
	if err := undelegateAll(privKey, masterAddress); err != nil {
		log.Fatalf("Undelegation process failed: %v", err)
	}
	fmt.Println("\n--- Undelegation process completed ---")
}
