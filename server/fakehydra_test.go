package server

// Fake Ory Hydra admin API for OIDC flow tests. Implements just the
// endpoints mokey calls via hydra-client-go v26. Challenges are seeded by
// tests; accept calls are recorded for assertions.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
)

// fakeConsentSession is one granted app for a subject, keyed by client ID
type fakeConsentSession struct {
	ClientID   string
	ClientName string
	Scope      []string
	HandledAt  string // RFC3339
}

type revokedConsent struct {
	Subject string
	Client  string
}

type fakeHydra struct {
	srv *httptest.Server

	mu sync.Mutex
	// seeded challenges
	loginRequests  map[string]map[string]interface{} // login_challenge -> response object
	consentSubject map[string]string                 // consent_challenge -> subject
	consentClient  map[string]string                 // consent_challenge -> client_id
	consentScope   map[string][]string               // consent_challenge -> requested_scope
	logoutSubject  map[string]string                 // logout_challenge -> subject
	// consent sessions ("connected apps"), keyed by subject
	consentSessions map[string][]fakeConsentSession
	// recorded accept calls
	acceptedLogins   []string               // subjects passed to login/accept
	acceptedConsent  map[string]interface{} // last consent accept body
	rejectedConsent  map[string]interface{} // last consent reject body
	acceptedLogouts  []string               // logout challenges accepted
	revokedSubjects  []string               // DELETE sessions/login subjects
	revokedConsents  []revokedConsent       // DELETE sessions/consent calls
	rememberDuration int64
	// OAuth2 clients served by /admin/clients, clientsPage per page
	clients     []map[string]interface{}
	clientsPage int
	// GET sessions/consent calls, to see the sweep stop early
	consentLists int
	// POST/PUT/DELETE calls on clients
	clientWrites int
}

func newFakeHydra() *fakeHydra {
	f := &fakeHydra{
		loginRequests:   make(map[string]map[string]interface{}),
		consentSubject:  make(map[string]string),
		consentClient:   make(map[string]string),
		consentScope:    make(map[string][]string),
		logoutSubject:   make(map[string]string),
		consentSessions: make(map[string][]fakeConsentSession),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/admin/oauth2/auth/requests/login", f.getLogin)
	mux.HandleFunc("/admin/oauth2/auth/requests/login/accept", f.acceptLogin)
	mux.HandleFunc("/admin/oauth2/auth/requests/consent", f.getConsent)
	mux.HandleFunc("/admin/oauth2/auth/requests/consent/accept", f.acceptConsent)
	mux.HandleFunc("/admin/oauth2/auth/requests/consent/reject", f.rejectConsent)
	mux.HandleFunc("/admin/oauth2/auth/requests/logout", f.getLogout)
	mux.HandleFunc("/admin/oauth2/auth/requests/logout/accept", f.acceptLogout)
	mux.HandleFunc("/admin/oauth2/auth/sessions/login", f.revokeSessions)
	mux.HandleFunc("/admin/oauth2/auth/sessions/consent", f.consentSessionsHandler)
	mux.HandleFunc("/admin/clients", f.clientsHandler)
	mux.HandleFunc("/admin/clients/{id}", f.clientHandler)

	f.srv = httptest.NewServer(mux)
	return f
}

func (f *fakeHydra) Close() { f.srv.Close() }

func (f *fakeHydra) seedLogin(challenge, subject string, skip bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.loginRequests[challenge] = map[string]interface{}{
		"challenge":       challenge,
		"subject":         subject,
		"skip":            skip,
		"requested_scope": []string{"openid"},
		"request_url":     "https://client.example.com/cb",
		"client":          map[string]interface{}{"client_id": "test-client"},
	}
}

func (f *fakeHydra) seedConsent(challenge, subject string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.consentSubject[challenge] = subject
}

func (f *fakeHydra) seedConsentForClient(challenge, subject, clientID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.consentSubject[challenge] = subject
	f.consentClient[challenge] = clientID
}

func (f *fakeHydra) seedConsentWithScope(challenge, subject string, scope []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.consentSubject[challenge] = subject
	f.consentScope[challenge] = scope
}

func (f *fakeHydra) seedLogout(challenge, subject string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.logoutSubject[challenge] = subject
}

func (f *fakeHydra) seedConsentSession(subject string, s fakeConsentSession) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.consentSessions[subject] = append(f.consentSessions[subject], s)
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func (f *fakeHydra) getLogin(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	req, ok := f.loginRequests[r.URL.Query().Get("login_challenge")]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	writeJSON(w, req)
}

func (f *fakeHydra) acceptLogin(w http.ResponseWriter, r *http.Request) {
	var body map[string]interface{}
	json.NewDecoder(r.Body).Decode(&body)

	f.mu.Lock()
	defer f.mu.Unlock()
	subject, _ := body["subject"].(string)
	f.acceptedLogins = append(f.acceptedLogins, subject)
	if remember, ok := body["remember_for"].(float64); ok {
		f.rememberDuration = int64(remember)
	}
	writeJSON(w, map[string]string{"redirect_to": "https://hydra.example.com/continue-login"})
}

func (f *fakeHydra) getConsent(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	challenge := r.URL.Query().Get("consent_challenge")
	subject, ok := f.consentSubject[challenge]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	clientID := f.consentClient[challenge]
	if clientID == "" {
		clientID = "test-client"
	}
	scope := f.consentScope[challenge]
	if scope == nil {
		scope = []string{"openid", "profile"}
	}
	// Hydra embeds the full client, metadata included
	client := map[string]interface{}{"client_id": clientID}
	for _, cl := range f.clients {
		if cl["client_id"] == clientID {
			client = cl
		}
	}
	writeJSON(w, map[string]interface{}{
		"challenge":       challenge,
		"subject":         subject,
		"requested_scope": scope,
		"client":          client,
	})
}

func (f *fakeHydra) rejectConsent(w http.ResponseWriter, r *http.Request) {
	var body map[string]interface{}
	json.NewDecoder(r.Body).Decode(&body)

	f.mu.Lock()
	defer f.mu.Unlock()
	f.rejectedConsent = body
	writeJSON(w, map[string]string{"redirect_to": "https://client.example.com/cb?error=access_denied"})
}

func (f *fakeHydra) acceptConsent(w http.ResponseWriter, r *http.Request) {
	var body map[string]interface{}
	json.NewDecoder(r.Body).Decode(&body)

	f.mu.Lock()
	defer f.mu.Unlock()
	f.acceptedConsent = body
	writeJSON(w, map[string]string{"redirect_to": "https://hydra.example.com/continue-consent"})
}

func (f *fakeHydra) getLogout(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	subject, ok := f.logoutSubject[r.URL.Query().Get("logout_challenge")]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	writeJSON(w, map[string]interface{}{
		"challenge": r.URL.Query().Get("logout_challenge"),
		"subject":   subject,
	})
}

func (f *fakeHydra) acceptLogout(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.acceptedLogouts = append(f.acceptedLogouts, r.URL.Query().Get("logout_challenge"))
	writeJSON(w, map[string]string{"redirect_to": "https://client.example.com/logged-out"})
}

func (f *fakeHydra) revokeSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revokedSubjects = append(f.revokedSubjects, r.URL.Query().Get("subject"))
	w.WriteHeader(http.StatusNoContent)
}

// consentSessionsHandler serves ListOAuth2ConsentSessions (GET) and
// RevokeOAuth2ConsentSessions (DELETE), both scoped by ?subject=.
func (f *fakeHydra) consentSessionsHandler(w http.ResponseWriter, r *http.Request) {
	subject := r.URL.Query().Get("subject")

	f.mu.Lock()
	defer f.mu.Unlock()

	switch r.Method {
	case http.MethodGet:
		f.consentLists++
		sessions := []map[string]interface{}{}
		for _, s := range f.consentSessions[subject] {
			session := map[string]interface{}{
				"consent_request": map[string]interface{}{
					"challenge": "consent-" + s.ClientID,
					"client": map[string]interface{}{
						"client_id":   s.ClientID,
						"client_name": s.ClientName,
					},
				},
				"grant_scope": s.Scope,
			}
			if s.HandledAt != "" {
				session["handled_at"] = s.HandledAt
			}
			sessions = append(sessions, session)
		}
		writeJSON(w, sessions)

	case http.MethodDelete:
		client := r.URL.Query().Get("client")
		f.revokedConsents = append(f.revokedConsents, revokedConsent{Subject: subject, Client: client})
		kept := f.consentSessions[subject][:0]
		for _, s := range f.consentSessions[subject] {
			if s.ClientID != client && r.URL.Query().Get("all") != "true" {
				kept = append(kept, s)
			}
		}
		f.consentSessions[subject] = kept
		w.WriteHeader(http.StatusNoContent)

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (f *fakeHydra) seedClient(client map[string]interface{}) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.clients = append(f.clients, client)
}

func (f *fakeHydra) clientsHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		f.listClients(w, r)
	case http.MethodPost:
		f.createClient(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// client returns the stored client and its index, or -1.
func (f *fakeHydra) client(id string) (map[string]interface{}, int) {
	for i, cl := range f.clients {
		if cl["client_id"] == id {
			return cl, i
		}
	}
	return nil, -1
}

// storedClient is a copy of the stored client, secret included
func (f *fakeHydra) storedClient(id string) map[string]interface{} {
	f.mu.Lock()
	defer f.mu.Unlock()
	cl, _ := f.client(id)
	if cl == nil {
		return nil
	}
	b, _ := json.Marshal(cl)
	var out map[string]interface{}
	json.Unmarshal(b, &out)
	return out
}

// withoutSecret is what Hydra returns on GET: never the secret
func withoutSecret(cl map[string]interface{}) map[string]interface{} {
	out := map[string]interface{}{}
	for k, v := range cl {
		if k != "client_secret" {
			out[k] = v
		}
	}
	return out
}

func (f *fakeHydra) createClient(w http.ResponseWriter, r *http.Request) {
	var body map[string]interface{}
	if json.NewDecoder(r.Body).Decode(&body) != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.clientWrites++
	id, _ := body["client_id"].(string)
	if id == "" {
		id = fmt.Sprintf("generated-%d", len(f.clients)+1)
		body["client_id"] = id
	}
	if cl, _ := f.client(id); cl != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		writeJSON(w, map[string]string{"error": "resource_conflict"})
		return
	}
	if _, ok := body["client_secret"]; !ok && body["token_endpoint_auth_method"] != "none" {
		body["client_secret"] = "hydra-generated-placeholder"
	}
	f.clients = append(f.clients, body)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, body)
}

// clientHandler: GET without the secret; PUT replaces the client and keeps
// the stored secret when the body has none, as Hydra v2 does; DELETE also
// drops the client's consent sessions (Hydra cascades them).
func (f *fakeHydra) clientHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	f.mu.Lock()
	defer f.mu.Unlock()
	cl, i := f.client(id)
	if r.Method != http.MethodGet {
		f.clientWrites++
	}
	if cl == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		writeJSON(w, map[string]string{"error": "Unable to locate the resource"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, withoutSecret(cl))
	case http.MethodPut:
		var body map[string]interface{}
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		body["client_id"] = id
		if _, ok := body["client_secret"]; !ok {
			if s, ok := cl["client_secret"]; ok {
				body["client_secret"] = s
			}
		}
		f.clients[i] = body
		writeJSON(w, body)
	case http.MethodDelete:
		f.clients = append(f.clients[:i], f.clients[i+1:]...)
		for subject, sessions := range f.consentSessions {
			kept := sessions[:0]
			for _, s := range sessions {
				if s.ClientID != id {
					kept = append(kept, s)
				}
			}
			f.consentSessions[subject] = kept
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// listClients pages like Hydra: page_token is an offset here, the next
// page is announced in the Link header
func (f *fakeHydra) listClients(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	start, _ := strconv.Atoi(r.URL.Query().Get("page_token"))
	end := len(f.clients)
	if f.clientsPage > 0 && start+f.clientsPage < end {
		end = start + f.clientsPage
		w.Header().Set("Link", fmt.Sprintf(`</admin/clients?page_size=%d&page_token=%d>; rel="next"`, f.clientsPage, end))
	}
	writeJSON(w, f.clients[start:end])
}
