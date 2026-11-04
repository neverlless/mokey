package server

import (
	"net/url"
	"testing"

	"github.com/gofiber/fiber/v2"
	ipa "github.com/neverlless/goipa"
	"github.com/neverlless/goipa/ipatest"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

// ipatest does not model config_show (goipa gap), so the server-wide
// ipauserauthtype is served by an override
func setDefaultAuthTypes(fake *ipatest.Server, types ...string) {
	fake.Handle("config_show", func(ipatest.Call) (any, *ipa.IpaError) {
		return map[string]any{"result": map[string]any{"ipauserauthtype": types}, "summary": nil}, nil
	})
}

func TestPasswordElsewhere(t *testing.T) {
	for _, tc := range []struct {
		name         string
		user, global []string
		wantKey      string
	}{
		{"no types", nil, nil, ""},
		{"password", []string{"password"}, nil, ""},
		{"otp means password plus token", []string{"otp"}, nil, ""},
		{"hardened", []string{"hardened"}, nil, ""},
		{"idp", []string{"idp"}, nil, "password.managed_by_idp"},
		{"radius", []string{"radius"}, nil, "password.managed_by_radius"},
		{"idp or password", []string{"idp", "password"}, nil, ""},
		{"pkinit and passkey", []string{"pkinit", "passkey"}, nil, "password.not_used"},
		{"global default applies", nil, []string{"idp"}, "password.managed_by_idp"},
		{"own types beat the default", []string{"password"}, []string{"idp"}, ""},
		{"disabled forces the default", []string{"password"}, []string{"disabled", "radius"}, "password.managed_by_radius"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, router, fake := newTestApp(t)
			if tc.global != nil {
				setDefaultAuthTypes(fake, tc.global...)
			}
			want := ""
			if tc.wantKey != "" {
				want = T(tc.wantKey)
			}
			assert.Equal(t, want, router.passwordElsewhere(&ipa.User{AuthTypes: tc.user}))
		})
	}
}

func TestPasswordPageForUserWithoutFreeIPAPassword(t *testing.T) {
	for _, tc := range []struct {
		name          string
		types, global []string
		wantKey       string
	}{
		{"idp", []string{"idp"}, nil, "password.managed_by_idp"},
		{"radius", []string{"radius"}, nil, "password.managed_by_radius"},
		{"default idp", nil, []string{"idp"}, "password.managed_by_idp"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			app, _, fake := newTestApp(t)
			// ipatest's login_password ignores ipauserauthtype, so the
			// session can be had with a password
			fake.AddUser("walter", ipatest.User{Password: "OldSecret123!", AuthTypes: tc.types})
			if tc.global != nil {
				setDefaultAuthTypes(fake, tc.global...)
			}

			tc2 := newTestClient(t, app)
			tc2.login("walter", "OldSecret123!")

			body := readBody(t, tc2.get("/password"))
			assert.Contains(body, T(tc.wantKey))
			assert.NotContains(body, `name="newpassword"`)

			resp := tc2.postForm("/password/change", url.Values{
				"password":     {"OldSecret123!"},
				"newpassword":  {"NewSecret456!"},
				"newpassword2": {"NewSecret456!"},
			}, htmx)
			assert.Equal(fiber.StatusForbidden, resp.StatusCode)
			assert.Equal("OldSecret123!", fakeUser(fake, "walter").Password)
		})
	}
}

func TestPasswordPageForOTPUser(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestApp(t)
	fake.AddUser("walter", ipatest.User{Password: "OldSecret123!", AuthTypes: []string{"password", "otp"}})

	tc := newTestClient(t, app)
	tc.login("walter", "OldSecret123!")

	assert.Contains(readBody(t, tc.get("/password")), `name="newpassword"`)

	resp := tc.postForm("/password/change", url.Values{
		"password":     {"OldSecret123!"},
		"newpassword":  {"NewSecret456!"},
		"newpassword2": {"NewSecret456!"},
	}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	assert.Equal("NewSecret456!", fakeUser(fake, "walter").Password)
}

func TestForgotPasswordForIdPUser(t *testing.T) {
	assert := assert.New(t)
	app, router, fake := newTestAppWith(t, func() {
		viper.Set("accounts.enable_captcha", false)
	})
	sink := newFakeSMTP(t)
	fake.AddUser("walter", ipatest.User{Password: "Secret123!", AuthTypes: []string{"idp"}, Email: "walter@example.com"})

	tc := newTestClient(t, app)
	tc.getCSRF("/auth/forgotpw")

	external := readBody(t, tc.postForm("/auth/forgotpw", url.Values{"username": {"walter"}}, nil))
	unknown := readBody(t, tc.postForm("/auth/forgotpw", url.Values{"username": {"nobody"}}, nil))
	assert.Equal(unknown, external, "the page must not single out external users")

	msgs := sink.all()
	if assert.Len(msgs, 1) {
		assert.Contains(msgs[0], T("email_template.password_elsewhere_subject"))
		assert.NotContains(msgs[0], "/auth/resetpw/")
	}

	// a reset link issued before the switch to the IdP no longer works
	token, err := NewToken("walter", "walter@example.com", TokenPasswordReset, router.storage)
	assert.NoError(err)
	assert.Equal(fiber.StatusNotFound, tc.get("/auth/resetpw/"+token).StatusCode)
}

func TestADTrustUsernames(t *testing.T) {
	for _, hide := range []bool{false, true} {
		assert := assert.New(t)
		app, _, fake := newTestAppWith(t, func() {
			viper.Set("accounts.enable_captcha", false)
			viper.Set("accounts.hide_invalid_username_error", hide)
		})
		sink := newFakeSMTP(t)
		fake.AddUser("walter", ipatest.User{Password: "Secret123!"})

		tc := newTestClient(t, app)
		tc.getCSRF("/auth/login")

		for _, name := range []string{"jane@ad.example.com", `AD\jane`} {
			for _, path := range []string{"/auth/login", "/auth/forgotpw"} {
				resp := tc.postForm(path, url.Values{"username": {name}}, nil)
				assert.Equal(fiber.StatusBadRequest, resp.StatusCode, path)
				assert.Equal(T("password.managed_by_ad"), readBody(t, resp), path)
			}
			resp := tc.postForm("/auth/authenticate", url.Values{"username": {name}, "password": {"x"}}, nil)
			assert.Equal(T("password.managed_by_ad"), readBody(t, resp))
		}
		assert.Equal(0, sink.count())

		// FreeIPA's own realm is not an AD domain
		resp := tc.postForm("/auth/login", url.Values{"username": {"walter@" + fake.Realm()}}, nil)
		assert.NotEqual(T("password.managed_by_ad"), readBody(t, resp))
	}
}

func TestLoginExplainsExternalSignIn(t *testing.T) {
	for _, hide := range []bool{false, true} {
		assert := assert.New(t)
		app, _, fake := newTestAppWith(t, func() {
			viper.Set("accounts.hide_invalid_username_error", hide)
		})
		fake.AddUser("walter", ipatest.User{Password: "Secret123!", AuthTypes: []string{"idp"}})

		tc := newTestClient(t, app)
		tc.getCSRF("/auth/login")
		body := readBody(t, tc.postForm("/auth/login", url.Values{"username": {"walter"}}, nil))
		if hide {
			assert.NotContains(body, T("password.managed_by_idp"), "hidden account state must stay hidden")
		} else {
			assert.Equal(T("password.managed_by_idp"), body)
		}
	}
}
