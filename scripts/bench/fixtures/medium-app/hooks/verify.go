package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"os"
)

func validSignature(body []byte, given string) bool {
	key := os.Getenv("HOOK_SIGNING_KEY")
	if key == "" {
		return false
	}
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write(body)
	want := mac.Sum(nil)
	got, err := hex.DecodeString(given)
	return err == nil && hmac.Equal(got, want)
}
