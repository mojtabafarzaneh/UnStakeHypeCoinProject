package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/ethereum/go-ethereum/crypto"
)

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
