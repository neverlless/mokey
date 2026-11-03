package server

import (
	"bufio"
	"crypto/sha1" // #nosec G505 -- the Pwned Passwords API is keyed by SHA-1
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"
)

var (
	pwnedRangeURL = "https://api.pwnedpasswords.com/range/"
	pwnedClient   = &http.Client{Timeout: 5 * time.Second}
)

// passwordBreached asks Have I Been Pwned whether the password appears in a
// known breach. Only the first five hex digits of its SHA-1 leave the host
// (k-anonymity); the suffixes are compared here.
func passwordBreached(password string) (bool, error) {
	sum := sha1.Sum([]byte(password)) // #nosec G401 -- lookup key, not password storage
	hash := strings.ToUpper(hex.EncodeToString(sum[:]))
	prefix, suffix := hash[:5], hash[5:]

	req, err := http.NewRequest(http.MethodGet, pwnedRangeURL+prefix, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("User-Agent", "mokey")
	// padding hides the real size of the response from on-path observers
	req.Header.Set("Add-Padding", "true")

	resp, err := pwnedClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("pwned passwords API returned %s", resp.Status)
	}

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		s, count, ok := strings.Cut(strings.TrimSpace(scanner.Text()), ":")
		// padding entries carry a count of 0
		if ok && s == suffix && strings.TrimLeft(count, "0") != "" {
			return true, nil
		}
	}
	return false, scanner.Err()
}
