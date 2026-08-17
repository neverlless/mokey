package server

// Fake FreeIPA server for handler tests. Speaks just enough of the FreeIPA
// web API (login_password, change_password, JSON-RPC) to satisfy goipa.
// State is an in-memory user map; extend the rpc switch as tests need more
// methods.

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"

	ipa "github.com/ubccr/goipa"
)

type fakeUser struct {
	Password    string
	Expired     bool // password expired: login fails, change_password required
	Locked      bool
	Groups      []string
	AuthTypes   []string
	Email       string
	First       string
	Last        string
	Category    string
	DisplayName string
	Telephone   string
	Mobile      string
	Shell       string
	// FailedLogins simulates FreeIPA's krbloginfailedcount; at
	// fakeLockoutThreshold the account rejects even correct passwords
	FailedLogins int
	PasswdExpire time.Time
}

// mirrors FreeIPA's default krbpwdmaxfailure
const fakeLockoutThreshold = 6

type fakeOTPToken struct {
	UUID        string
	Owner       string
	Secret      string
	Disabled    bool
	Description string
}

type fakeSubid struct {
	SubUID int64
	SubGID int64
}

type fakeIPA struct {
	srv *httptest.Server

	mu         sync.Mutex
	users      map[string]*fakeUser
	stageusers map[string]*fakeUser
	subids     map[string]*fakeSubid // owner uid -> range
	sessions   map[string]string     // ipa_session sid -> username
	// randomPasswords holds the last user_mod random:true password per user
	randomPasswords map[string]string
	tokens          []*fakeOTPToken
	// last ipatokennotbefore value received by otptoken_add (raw string)
	lastNotBefore string
}

func newFakeIPA() *fakeIPA {
	f := &fakeIPA{
		users:           make(map[string]*fakeUser),
		stageusers:      make(map[string]*fakeUser),
		subids:          make(map[string]*fakeSubid),
		sessions:        make(map[string]string),
		randomPasswords: make(map[string]string),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/ipa/session/login_password", f.handleLogin)
	mux.HandleFunc("/ipa/session/change_password", f.handleChangePassword)
	mux.HandleFunc("/ipa/session/json", f.handleRPC)
	mux.HandleFunc("/ipa/json", f.handleRPC)

	f.srv = httptest.NewTLSServer(mux)

	return f
}

func (f *fakeIPA) Close() { f.srv.Close() }

// host returns host:port suitable for goipa's https://%s URL scheme
func (f *fakeIPA) host() string {
	return strings.TrimPrefix(f.srv.URL, "https://")
}

// client returns a goipa client wired to this fake server
func (f *fakeIPA) client() *ipa.Client {
	return ipa.NewClientCustomHttp(f.host(), "TEST.LOCAL", f.srv.Client())
}

func (f *fakeIPA) addUser(username string, u *fakeUser) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if u.Email == "" {
		u.Email = username + "@example.com"
	}
	if u.First == "" {
		u.First = "Test"
	}
	if u.Last == "" {
		u.Last = "User"
	}
	f.users[username] = u
}

func newSID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b) // 32 chars, satisfies goipa's cookie check
}

func setSessionCookie(w http.ResponseWriter, sid string) {
	w.Header().Set("Set-Cookie", fmt.Sprintf("ipa_session=%s; Path=/ipa; Secure; HttpOnly", sid))
}

func (f *fakeIPA) handleLogin(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	username := r.PostFormValue("user")
	password := r.PostFormValue("password")

	// Test seam: mokey rebuilds clients from a stored session id
	// (newIPAClientWithSession); the fake restores any sid it issued earlier.
	if username == "__restore__" {
		setSessionCookie(w, password)
		w.WriteHeader(http.StatusOK)
		return
	}

	// Test seam: stands in for the keytab-based admin service account login
	if username == "__admin__" {
		f.mu.Lock()
		sid := newSID()
		f.sessions[sid] = username
		f.mu.Unlock()
		setSessionCookie(w, sid)
		w.WriteHeader(http.StatusOK)
		return
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	u, ok := f.users[username]
	if !ok || u.Password != password {
		if ok {
			u.FailedLogins++
		}
		w.Header().Set("X-IPA-Rejection-Reason", "invalid-password")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if u.FailedLogins >= fakeLockoutThreshold {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	u.FailedLogins = 0

	if u.Expired {
		w.Header().Set("X-IPA-Rejection-Reason", "password-expired")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if u.Locked {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	sid := newSID()
	f.sessions[sid] = username
	setSessionCookie(w, sid)
	w.WriteHeader(http.StatusOK)
}

func (f *fakeIPA) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	username := r.PostFormValue("user")
	oldPassword := r.PostFormValue("old_password")
	newPassword := r.PostFormValue("new_password")

	f.mu.Lock()
	defer f.mu.Unlock()

	u, ok := f.users[username]
	if !ok || u.Password != oldPassword {
		w.Header().Set("x-ipa-pwchange-result", "invalid-password")
		w.WriteHeader(http.StatusOK)
		return
	}

	if len(newPassword) < 8 {
		w.Header().Set("x-ipa-pwchange-result", "policy-error")
		w.WriteHeader(http.StatusOK)
		return
	}

	u.Password = newPassword
	u.Expired = false
	w.Header().Set("x-ipa-pwchange-result", "ok")
	w.WriteHeader(http.StatusOK)
}

type rpcRequest struct {
	Method string        `json:"method"`
	Params []interface{} `json:"params"`
}

func (rr *rpcRequest) args() []string {
	out := []string{}
	if len(rr.Params) < 1 {
		return out
	}
	list, _ := rr.Params[0].([]interface{})
	for _, v := range list {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func (rr *rpcRequest) options() map[string]interface{} {
	if len(rr.Params) < 2 {
		return map[string]interface{}{}
	}
	opts, _ := rr.Params[1].(map[string]interface{})
	return opts
}

func rpcResult(w http.ResponseWriter, result interface{}) {
	resp := map[string]interface{}{
		"error":     nil,
		"id":        0,
		"principal": "admin@TEST.LOCAL",
		"version":   "4.10.0",
		"result": map[string]interface{}{
			"summary": "",
			"value":   "",
			"result":  result,
		},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func rpcError(w http.ResponseWriter, code int, message string) {
	resp := map[string]interface{}{
		"error": map[string]interface{}{
			"code":    code,
			"message": message,
		},
		"id": 0,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// lastActiveTokenOfOTPOnlyUser mirrors FreeIPA's guard: an OTP-only user
// cannot remove or disable their only enabled token (error 4203)
func (f *fakeIPA) lastActiveTokenOfOTPOnlyUser(tok *fakeOTPToken) bool {
	owner, ok := f.users[tok.Owner]
	if !ok || len(owner.AuthTypes) != 1 || owner.AuthTypes[0] != "otp" {
		return false
	}
	active := 0
	for _, t := range f.tokens {
		if t.Owner == tok.Owner && !t.Disabled {
			active++
		}
	}
	return active <= 1 && !tok.Disabled
}

func (tok *fakeOTPToken) uri() string {
	return fmt.Sprintf(
		"otpauth://totp/TEST.LOCAL:%s@TEST.LOCAL?secret=%s&algorithm=SHA1&digits=6&period=30&issuer=TEST.LOCAL",
		tok.Owner, tok.Secret)
}

func (f *fakeIPA) tokenJSON(tok *fakeOTPToken) map[string]interface{} {
	uri := tok.uri()
	rec := map[string]interface{}{
		"dn":                   "ipatokenuniqueid=" + tok.UUID + ",cn=otp,dc=test,dc=local",
		"ipatokenuniqueid":     []string{tok.UUID},
		"ipatokenowner":        []string{tok.Owner},
		"ipatokenotpalgorithm": []string{"sha1"},
		"ipatokenotpdigits":    []string{"6"},
		"ipatokentotptimestep": []string{"30"},
		"ipatokendisabled":     []bool{tok.Disabled},
		"type":                 "totp",
		"uri":                  uri,
	}
	if tok.Description != "" {
		rec["description"] = []string{tok.Description}
	}
	return rec
}

// subidJSON renders a subordinate id range in FreeIPA's attribute-list form
func (f *fakeIPA) subidJSON(owner string, sub *fakeSubid) map[string]interface{} {
	return map[string]interface{}{
		"ipauniqueid":     []string{"fake-" + owner},
		"ipaowner":        []string{owner},
		"ipasubuidnumber": []string{fmt.Sprintf("%d", sub.SubUID)},
		"ipasubuidcount":  []string{"65536"},
		"ipasubgidnumber": []string{fmt.Sprintf("%d", sub.SubGID)},
		"ipasubgidcount":  []string{"65536"},
	}
}

// userJSON renders a user in FreeIPA's attribute-list form consumed by
// goipa's User.fromJSON
func (f *fakeIPA) userJSON(username string, u *fakeUser) map[string]interface{} {
	rec := map[string]interface{}{
		"dn":             "uid=" + username + ",cn=users,cn=accounts,dc=test,dc=local",
		"uid":            []string{username},
		"givenname":      []string{u.First},
		"sn":             []string{u.Last},
		"mail":           []string{u.Email},
		"memberof_group": u.Groups,
		"nsaccountlock":  u.Locked,
		"has_password":   true,
	}
	if len(u.AuthTypes) > 0 {
		rec["ipauserauthtype"] = u.AuthTypes
	}
	if u.Category != "" {
		rec["userclass"] = []string{u.Category}
	}
	if u.DisplayName != "" {
		rec["displayname"] = []string{u.DisplayName}
	}
	if u.Telephone != "" {
		rec["telephonenumber"] = []string{u.Telephone}
	}
	if u.Mobile != "" {
		rec["mobile"] = []string{u.Mobile}
	}
	if u.Shell != "" {
		rec["loginshell"] = []string{u.Shell}
	}
	if !u.PasswdExpire.IsZero() {
		rec["krbpasswordexpiration"] = []map[string]string{{"__datetime__": u.PasswdExpire.UTC().Format(ipa.IpaDatetimeFormat)}}
	}
	if p, ok := f.randomPasswords[username]; ok {
		rec["randompassword"] = p
	}
	return rec
}

func (f *fakeIPA) handleRPC(w http.ResponseWriter, r *http.Request) {
	// Session-authenticated endpoint requires a session cookie the fake issued
	var caller string
	if strings.HasPrefix(r.URL.Path, "/ipa/session/") {
		cookie, err := r.Cookie("ipa_session")
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		f.mu.Lock()
		username, known := f.sessions[cookie.Value]
		f.mu.Unlock()
		if !known {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		caller = username
	}

	// Non-session endpoint (/ipa/json, SPNEGO in real FreeIPA): issue a
	// session cookie like the real server does, so goipa's sticky-session
	// capture works for the keytab-bound admin client
	if !strings.HasPrefix(r.URL.Path, "/ipa/session/") {
		f.mu.Lock()
		sid := newSID()
		f.sessions[sid] = "__admin__"
		f.mu.Unlock()
		setSessionCookie(w, sid)
	}

	var req rpcRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	args := req.args()
	opts := req.options()

	f.mu.Lock()
	defer f.mu.Unlock()

	switch req.Method {
	case "ping":
		rpcResult(w, map[string]interface{}{"summary": "pong"})

	case "user_show":
		username := args[0]
		u, ok := f.users[username]
		if !ok {
			rpcError(w, 4001, username+": user not found")
			return
		}
		rpcResult(w, f.userJSON(username, u))

	case "user_find":
		users := []map[string]interface{}{}
		for name, u := range f.users {
			users = append(users, f.userJSON(name, u))
		}
		rpcResult(w, users)

	case "user_mod":
		username := args[0]
		u, ok := f.users[username]
		if !ok {
			rpcError(w, 4001, username+": user not found")
			return
		}
		if random, _ := opts["random"].(bool); random {
			u.Password = "random-" + newSID()
			u.Expired = true // FreeIPA marks reset passwords expired
			f.randomPasswords[username] = u.Password
		}
		// apply modifiable attributes when present (UserMod sends them all)
		if v, ok := opts["givenname"].(string); ok {
			u.First = v
		}
		if v, ok := opts["sn"].(string); ok {
			u.Last = v
		}
		if v, ok := opts["mail"].(string); ok {
			u.Email = v
		}
		if v, ok := opts["userclass"].(string); ok {
			u.Category = v
		}
		if v, ok := opts["displayname"].(string); ok {
			u.DisplayName = v
		}
		if v, ok := opts["telephonenumber"].(string); ok {
			u.Telephone = v
		}
		if v, ok := opts["mobile"].(string); ok {
			u.Mobile = v
		}
		if v, ok := opts["loginshell"].(string); ok {
			u.Shell = v
		}
		if v, ok := opts["ipauserauthtype"]; ok {
			types := []string{}
			if list, ok := v.([]interface{}); ok {
				for _, item := range list {
					if s, ok := item.(string); ok {
						types = append(types, s)
					}
				}
			}
			u.AuthTypes = types
		}
		rpcResult(w, f.userJSON(username, u))
		delete(f.randomPasswords, username)

	case "user_add":
		username := args[0]
		if _, exists := f.users[username]; exists {
			rpcError(w, 4002, username+": user already exists")
			return
		}
		str := func(key string) string { s, _ := opts[key].(string); return s }
		u := &fakeUser{
			First:    str("givenname"),
			Last:     str("sn"),
			Email:    str("mail"),
			Category: str("userclass"),
		}
		if random, _ := opts["random"].(bool); random {
			u.Password = "random-" + newSID()
			u.Expired = true
			f.randomPasswords[username] = u.Password
		}
		f.users[username] = u
		rpcResult(w, f.userJSON(username, u))
		delete(f.randomPasswords, username)

	case "subid_generate":
		owner, _ := opts["ipaowner"].(string)
		if owner == "" {
			rpcError(w, 3007, "'ipaowner' is required")
			return
		}
		if _, exists := f.subids[owner]; exists {
			rpcError(w, 4002, "subid already exists for user \""+owner+"\"")
			return
		}
		// mirrors FreeIPA's sequential allocation from 2^31 up
		sub := &fakeSubid{
			SubUID: 2147483648 + int64(len(f.subids))*65536,
			SubGID: 2147483648 + int64(len(f.subids))*65536,
		}
		f.subids[owner] = sub
		rpcResult(w, f.subidJSON(owner, sub))

	case "subid_find":
		owner, _ := opts["ipaowner"].(string)
		results := []map[string]interface{}{}
		for name, sub := range f.subids {
			if owner == "" || name == owner {
				results = append(results, f.subidJSON(name, sub))
			}
		}
		rpcResult(w, results)

	case "stageuser_add":
		username := args[0]
		if _, exists := f.stageusers[username]; exists {
			rpcError(w, 4002, username+": stage user already exists")
			return
		}
		str := func(key string) string { s, _ := opts[key].(string); return s }
		u := &fakeUser{
			First:    str("givenname"),
			Last:     str("sn"),
			Email:    str("mail"),
			Category: str("userclass"),
			Password: str("userpassword"),
			Shell:    str("loginshell"),
		}
		f.stageusers[username] = u
		rpcResult(w, f.userJSON(username, u))

	case "stageuser_show":
		username := args[0]
		u, ok := f.stageusers[username]
		if !ok {
			rpcError(w, 4001, username+": stage user not found")
			return
		}
		rpcResult(w, f.userJSON(username, u))

	case "stageuser_find":
		users := []map[string]interface{}{}
		for name, u := range f.stageusers {
			users = append(users, f.userJSON(name, u))
		}
		rpcResult(w, users)

	case "stageuser_mod":
		username := args[0]
		u, ok := f.stageusers[username]
		if !ok {
			rpcError(w, 4001, username+": stage user not found")
			return
		}
		if v, ok := opts["userclass"].(string); ok {
			u.Category = v
		}
		rpcResult(w, f.userJSON(username, u))

	case "stageuser_del":
		username := args[0]
		if _, ok := f.stageusers[username]; !ok {
			rpcError(w, 4001, username+": stage user not found")
			return
		}
		delete(f.stageusers, username)
		rpcResult(w, map[string]interface{}{})

	case "stageuser_activate":
		username := args[0]
		u, ok := f.stageusers[username]
		if !ok {
			rpcError(w, 4001, username+": stage user not found")
			return
		}
		if _, exists := f.users[username]; exists {
			rpcError(w, 4002, username+": user already exists")
			return
		}
		delete(f.stageusers, username)
		u.Expired = true // FreeIPA expires the password on activation
		f.users[username] = u
		rpcResult(w, f.userJSON(username, u))

	case "user_del":
		username := args[0]
		if _, ok := f.users[username]; !ok {
			rpcError(w, 4001, username+": user not found")
			return
		}
		delete(f.users, username)
		rpcResult(w, map[string]interface{}{})

	case "user_disable":
		username := args[0]
		u, ok := f.users[username]
		if !ok {
			rpcError(w, 4001, username+": user not found")
			return
		}
		u.Locked = true
		rpcResult(w, map[string]interface{}{})

	case "user_enable":
		username := args[0]
		u, ok := f.users[username]
		if !ok {
			rpcError(w, 4001, username+": user not found")
			return
		}
		u.Locked = false
		rpcResult(w, map[string]interface{}{})

	case "passwd":
		username := args[0]
		current, _ := opts["current_password"].(string)
		newpass, _ := opts["password"].(string)
		u, ok := f.users[username]
		if !ok {
			rpcError(w, 4001, username+": user not found")
			return
		}
		if u.Password != current {
			rpcError(w, 2100, "invalid current password")
			return
		}
		u.Password = newpass
		rpcResult(w, map[string]interface{}{})

	case "user_status":
		username := args[0]
		u, ok := f.users[username]
		if !ok {
			rpcError(w, 4001, username+": user not found")
			return
		}
		rpcResult(w, []map[string]interface{}{{
			"server":              []string{"ipa.test.local"},
			"krbloginfailedcount": []string{fmt.Sprintf("%d", u.FailedLogins)},
		}})

	case "user_unlock":
		username := args[0]
		u, ok := f.users[username]
		if !ok {
			rpcError(w, 4001, username+": user not found")
			return
		}
		u.FailedLogins = 0
		rpcResult(w, map[string]interface{}{})

	case "pwpolicy_show":
		rpcResult(w, map[string]interface{}{
			"krbpwdmaxfailure":      []string{fmt.Sprintf("%d", fakeLockoutThreshold)},
			"krbpwdlockoutduration": []string{"600"},
			"krbminpwdlife":         []string{"1"},
			"krbmaxpwdlife":         []string{"90"},
			"krbpwdminlength":       []string{"8"},
			"krbpwdmindiffchars":    []string{"2"},
			"krbpwdhistorylength":   []string{"5"},
		})

	case "otptoken_add":
		secret := base32.StdEncoding.EncodeToString([]byte(newSID()[:20]))
		s := newSID() + newSID()
		desc, _ := opts["description"].(string)
		if nb, ok := opts["ipatokennotbefore"].(map[string]interface{}); ok {
			f.lastNotBefore, _ = nb["__datetime__"].(string)
		}
		tok := &fakeOTPToken{
			UUID:        s[0:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:32],
			Owner:       caller,
			Secret:      secret,
			Description: desc,
		}
		f.tokens = append(f.tokens, tok)
		rpcResult(w, f.tokenJSON(tok))

	case "otptoken_find":
		owner, _ := opts["ipatokenowner"].(string)
		out := []map[string]interface{}{}
		for _, tok := range f.tokens {
			if owner == "" || tok.Owner == owner {
				out = append(out, f.tokenJSON(tok))
			}
		}
		rpcResult(w, out)

	case "otptoken_del":
		uuid := args[0]
		idx := -1
		for i, tok := range f.tokens {
			if tok.UUID == uuid {
				idx = i
			}
		}
		if idx == -1 {
			rpcError(w, 4001, uuid+": otp token not found")
			return
		}
		if f.lastActiveTokenOfOTPOnlyUser(f.tokens[idx]) {
			rpcError(w, 4203, "Can't delete last active token while OTP is enabled")
			return
		}
		f.tokens = append(f.tokens[:idx], f.tokens[idx+1:]...)
		rpcResult(w, map[string]interface{}{})

	case "otptoken_mod":
		uuid := args[0]
		var tok *fakeOTPToken
		for _, t := range f.tokens {
			if t.UUID == uuid {
				tok = t
			}
		}
		if tok == nil {
			rpcError(w, 4001, uuid+": otp token not found")
			return
		}
		if disabled, ok := opts["ipatokendisabled"].(bool); ok {
			if disabled && f.lastActiveTokenOfOTPOnlyUser(tok) {
				rpcError(w, 4203, "Can't disable last active token while OTP is enabled")
				return
			}
			tok.Disabled = disabled
		}
		rpcResult(w, f.tokenJSON(tok))

	default:
		rpcError(w, 902, "unknown command "+req.Method)
	}
}
