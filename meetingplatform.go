package main

import (
	"crypto/sha256"
	"encoding/hex"
)

type meetingPlatform map[string][]byte

func createMeetingPoint(keymaterial []byte) string {
	h := sha256.New()
	h.Write(keymaterial)

	return hex.EncodeToString(h.Sum(nil))
}
