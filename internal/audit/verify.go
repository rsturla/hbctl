package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
)

type VerifyResult struct {
	TotalEvents int
	ValidEvents int
	BrokenChain int
	FirstBreak  int
	InvalidHash int
}

func VerifyLog(logPath, keyPath string) (*VerifyResult, error) {
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read HMAC key: %w", err)
	}
	defer clear(key)

	if len(key) != 32 {
		return nil, fmt.Errorf("invalid HMAC key length: %d", len(key))
	}

	f, err := os.Open(logPath)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	defer func() { _ = f.Close() }()

	verifier := &FileLogger{hmacKey: key}

	result := &VerifyResult{}
	prevHash := "genesis"
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		result.TotalEvents++

		var event Event
		if err := json.Unmarshal(line, &event); err != nil {
			result.InvalidHash++
			continue
		}

		if event.PrevHash != prevHash {
			result.BrokenChain++
			if result.FirstBreak == 0 {
				result.FirstBreak = result.TotalEvents
			}
		}

		expected := verifier.computeHash(event)
		if event.Hash != expected {
			result.InvalidHash++
			if result.FirstBreak == 0 {
				result.FirstBreak = result.TotalEvents
			}
		} else {
			result.ValidEvents++
		}

		prevHash = event.Hash
	}

	return result, scanner.Err()
}
