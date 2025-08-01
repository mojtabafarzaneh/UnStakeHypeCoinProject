package main

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"time"

	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

const (
	exchangeURL = "https://api.hyperliquid.xyz/exchange"
	chainID     = 42161
	chainIDHex  = "0xa4b1"
)

type DelegateAction struct {
	Type             string   `json:"type"`
	HyperliquidChain string   `json:"hyperliquidChain"`
	SignatureChainId string   `json:"signatureChainId"`
	Validator        string   `json:"validator"`
	IsUndelegate     bool     `json:"isUndelegate"`
	Wei              *big.Int `json:"wei"`
	Nonce            int64    `json:"nonce"`
}

type DelegateRequest struct {
	Action    DelegateAction `json:"action"`
	Nonce     int64          `json:"nonce"`
	Signature Signature      `json:"signature"`
}

type Signature struct {
	R string `json:"r"`
	S string `json:"s"`
	V uint8  `json:"v"`
}

func signEIP712(priv *ecdsa.PrivateKey, action DelegateAction) (Signature, error) {
	types := apitypes.Types{
		"EIP712Domain": []apitypes.Type{
			{Name: "name", Type: "string"},
			{Name: "version", Type: "string"},
			{Name: "chainId", Type: "uint256"},
		},
		"tokenDelegate": []apitypes.Type{
			{Name: "type", Type: "string"},
			{Name: "hyperliquidChain", Type: "string"},
			{Name: "signatureChainId", Type: "string"},
			{Name: "validator", Type: "address"},
			{Name: "isUndelegate", Type: "bool"},
			{Name: "wei", Type: "uint256"},
			{Name: "nonce", Type: "uint64"},
		},
	}

	chainIDBig := big.NewInt(chainID)
	chainIDHexOrDec := (*math.HexOrDecimal256)(chainIDBig)

	typedData := apitypes.TypedData{
		Types:       types,
		PrimaryType: "tokenDelegate",
		Domain: apitypes.TypedDataDomain{
			Name:    "Hyperliquid",
			Version: "1",
			ChainId: chainIDHexOrDec,
		},
		Message: map[string]interface{}{
			"type":             action.Type,
			"hyperliquidChain": action.HyperliquidChain,
			"signatureChainId": action.SignatureChainId,
			"validator":        action.Validator,
			"isUndelegate":     action.IsUndelegate,
			"wei":              action.Wei.String(),
			"nonce":            fmt.Sprintf("%d", action.Nonce),
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

	dataToSign := append([]byte("\x19\x01"), append(domainSeparator, messageHash...)...)
	hash := crypto.Keccak256(dataToSign)

	sig, err := crypto.Sign(hash, priv)
	if err != nil {
		return Signature{}, fmt.Errorf("failed to sign hash: %w", err)
	}

	return Signature{
		R: fmt.Sprintf("0x%x", sig[:32]),
		S: fmt.Sprintf("0x%x", sig[32:64]),
		V: sig[64] + 27,
	}, nil
}

func undelegateAll(privKey *ecdsa.PrivateKey, masterAddress string) error {
	delegations, err := fetchDelegations(masterAddress)
	if err != nil {
		return fmt.Errorf("error fetching delegations: %w", err)
	}

	if len(delegations) == 0 {
		fmt.Println("No delegations found to undelegate.")
		return nil
	}

	for _, d := range delegations {
		amountFloat := new(big.Float)
		if _, ok := amountFloat.SetString(d.Amount); !ok {
			return fmt.Errorf("invalid amount string '%s' for delegation", d.Amount)
		}
		weiPerToken := new(big.Float).SetFloat64(1e18)
		amountWei := new(big.Float).Mul(amountFloat, weiPerToken)
		amountWeiInt, _ := amountWei.Int(nil)

		currentTimestampMilli := time.Now().UnixMilli()

		action := DelegateAction{
			Type:             "tokenDelegate",
			HyperliquidChain: "Mainnet",
			SignatureChainId: chainIDHex,
			Validator:        d.Validator,
			IsUndelegate:     true,
			Wei:              amountWeiInt,
			Nonce:            currentTimestampMilli,
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
		fmt.Printf("Sending JSON: %s\n", string(body))
		client := &http.Client{Timeout: 30 * time.Second}
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
