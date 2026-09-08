package server

import (
	"crypto/sha512"
	"encoding/base64"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Local assets are pinned with subresource integrity hashes maintained by
// hand. A stale hash does not degrade gracefully — the browser drops the
// stylesheet or script entirely, so a one-character CSS edit silently ships
// an unstyled UI. Recompute with:
//
//	openssl dgst -sha384 -binary <file> | openssl base64 -A
var sriTag = regexp.MustCompile(`(?:href|src)="(/static/[^"?]+)[^"]*"[^>]*integrity="sha384-([^"]+)"`)

func TestLocalAssetIntegrityHashes(t *testing.T) {
	assert := assert.New(t)

	templates, err := filepath.Glob("templates/*.html")
	assert.NoError(err)

	checked := 0
	for _, tmpl := range templates {
		markup, err := os.ReadFile(tmpl)
		if !assert.NoError(err) {
			continue
		}

		for _, m := range sriTag.FindAllStringSubmatch(string(markup), -1) {
			assetPath := filepath.Join("templates", strings.TrimPrefix(m[1], "/"))
			content, err := os.ReadFile(assetPath)
			if !assert.NoError(err, "%s references %s", tmpl, m[1]) {
				continue
			}

			sum := sha512.Sum384(content)
			assert.Equal(base64.StdEncoding.EncodeToString(sum[:]), m[2],
				"stale integrity hash for %s in %s", m[1], tmpl)
			checked++
		}
	}

	assert.NotZero(checked, "found no integrity-pinned assets to check")
}
