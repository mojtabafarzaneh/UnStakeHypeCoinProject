package main

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
)

const (
	exchangeURL = "https://api.hyperliquid.xyz/exchange"
	chainIDHex  = "0xa4b1"
)

type DelegateAction struct {
	Type             string `json:"type"`
	HyperliquidChain string `json:"hyperliquidChain"`
	SignatureChainId string `json:"signatureChainId"`
	Validator        string `json:"validator"`
	IsUndelegate     bool   `json:"isUndelegate"`
	Wei              string `json:"wei"`
	Time             int64  `json:"time"`
}

type Signature struct {
	R string `json:"r"`
	S string `json:"s"`
	V uint8  `json:"v"`
}

type DelegateRequest struct {
	Action    DelegateAction `json:"action"`
	Nonce     int64          `json:"nonce"`
	Signature Signature      `json:"signature"`
}

func sign(priv *ecdsa.PrivateKey, msg []byte) (Signature, error) {
	hash := crypto.Keccak256(msg)
	sig, err := crypto.Sign(hash, priv)
	if err != nil {
		return Signature{}, err
	}
	return Signature{
		R: fmt.Sprintf("0x%x", sig[:32]),
		S: fmt.Sprintf("0x%x", sig[32:64]),
		V: sig[64] + 27,
	}, nil
}

func main() {
	privHex := "0xa6121f8763a5c29d2fe176d4d7168bdb727b6d6ef6e625e7775d3a258e8e36e7"
	validator := "0xVALIDATOR_ADDRESS"
	amountWei := "1000000000000000000"

	privKeyBytes, err := hex.DecodeString(privHex)
	if err != nil {
		log.Fatalf("Invalid hex private key: %v", err)
	}
	privKey, err := crypto.ToECDSA(privKeyBytes)
	if err != nil {
		log.Fatalf("Invalid private key: %v", err)
	}

	timestamp := time.Now().UnixMilli()
	action := DelegateAction{
		Type:             "tokenDelegate",
		HyperliquidChain: "Mainnet",
		SignatureChainId: chainIDHex,
		Validator:        validator,
		IsUndelegate:     true,
		Wei:              amountWei,
		Time:             timestamp,
	}

	actionBytes, _ := json.Marshal(action)
	signature, err := sign(privKey, actionBytes)
	if err != nil {
		log.Fatalf("Signing failed: %v", err)
	}

	request := DelegateRequest{
		Action:    action,
		Nonce:     timestamp,
		Signature: signature,
	}

	body, _ := json.Marshal(request)
	resp, err := http.Post(exchangeURL, "application/json", bytes.NewReader(body))
	if err != nil {
		log.Fatalf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	fmt.Println("--- Unstake Response ---")
	fmt.Println(string(respBody))
}
