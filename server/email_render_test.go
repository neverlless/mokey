package server

import (
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"testing"

	ipa "github.com/neverlless/goipa"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

// mailParts decodes (multipart.Reader already undoes quoted-printable) a captured message into its text and html bodies
func mailParts(t *testing.T, raw string) (txt, html string) {
	t.Helper()
	msg, err := mail.ReadMessage(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("parse mail: %s", err)
	}
	_, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil {
		t.Fatalf("content type: %s", err)
	}
	mr := multipart.NewReader(msg.Body, params["boundary"])
	for {
		p, err := mr.NextPart()
		if err != nil {
			break
		}
		body, _ := io.ReadAll(p)
		if strings.HasPrefix(p.Header.Get("Content-Type"), "text/html") {
			html = string(body)
		} else {
			txt = string(body)
		}
	}
	return txt, html
}

func renderTestMail(t *testing.T, send func(r *Router) error) (txt, html string) {
	t.Helper()
	_, router, _ := newTestAppWith(t, func() {
		viper.Set("site.name", "Acme Widgets")
		viper.Set("email.token_max_age", 86400)
		viper.Set("email.base_url", "https://sso.example.com")
	})
	sink := newFakeSMTP(t)
	if err := send(router); err != nil {
		t.Fatal(err)
	}
	if sink.count() != 1 {
		t.Fatalf("want 1 mail, got %d", sink.count())
	}
	return mailParts(t, sink.all()[0])
}

func assertCommonMailFixes(t *testing.T, txt, html string) {
	t.Helper()
	for name, body := range map[string]string{"txt": txt, "html": html} {
		assert.NotContains(t, body, "Hi ,", name)
		assert.NotContains(t, body, "[Acme Widgets]", name)
		assert.Contains(t, body, "1 day", name)
		assert.NotContains(t, body, "23 hours", name)
	}
	// only the URL element may break anywhere; the sentence keeps its words
	assert.Equal(t, 1, strings.Count(html, "break-all"))
	assert.Contains(t, html, "word-break: break-all;\">http")
}

func TestInviteEmailRender(t *testing.T) {
	txt, html := renderTestMail(t, func(r *Router) error {
		return r.emailer.SendInviteEmail("kim@example.com", "", "", "", "Walter White", nil)
	})
	assertCommonMailFixes(t, txt, html)
	assert.Contains(t, txt, "Hi,")
	assert.NotContains(t, html, `class="attributes"`)
	for _, body := range []string{txt, html} {
		assert.Contains(t, body, "Walter White invited you to Acme Widgets")
		assert.Contains(t, body, "If you did not expect this invitation")
		assert.NotContains(t, body, "received from")
	}

	txt, html = renderTestMail(t, func(r *Router) error {
		return r.emailer.SendInviteEmail("kim@example.com", "kim.w", "Kim", "Wexler", "Walter White", nil)
	})
	assert.Contains(t, txt, "Hi Kim,")
	assert.Contains(t, html, "Hi Kim,")
	assert.Contains(t, html, `class="attributes"`)
	for _, body := range []string{txt, html} {
		assert.Contains(t, body, "Your username: ")
		assert.Contains(t, body, "kim.w")
	}
}

func TestPasswordResetEmailRender(t *testing.T) {
	txt, html := renderTestMail(t, func(r *Router) error {
		return r.emailer.SendPasswordResetEmail(&ipa.User{Username: "walter", Email: "walter@example.com"}, nil)
	})
	assertCommonMailFixes(t, txt, html)
	assert.Contains(t, txt, "Hi,")
}
