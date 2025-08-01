package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

const infoURL = "https://api.hyperliquid.xyz/info"

type DelegationQuery struct {
	Type string `json:"type"`
	User string `json:"user"`
}

type DelegationItem struct {
	Validator            string `json:"validator"`
	Amount               string `json:"amount"`
	LockedUntilTimestamp int64  `json:"lockedUntilTimestamp"`
}

type BalanceQuery struct {
	Type string `json:"type"`
	User string `json:"user"`
}

type BalanceItem struct {
	Coin  string `json:"coin"`
	Hold  string `json:"hold"`
	Total string `json:"total"`
}

type BalanceResponse struct {
	Balances []BalanceItem `json:"balances"`
}

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
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("delegation query failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read delegation query response body: %w", err)
	}

	var respData []DelegationItem
	if err := json.Unmarshal(body, &respData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal delegation query response: %w", err)
	}
	return respData, nil
}

func fetchBalances(masterAddress string) (*BalanceResponse, error) {
	q := BalanceQuery{
		Type: "spotClearinghouseState",
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
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("balance query failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read balance query response body: %w", err)
	}

	var respData BalanceResponse
	if err := json.Unmarshal(body, &respData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal balance query response: %w", err)
	}
	return &respData, nil
}
