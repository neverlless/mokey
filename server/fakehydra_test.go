package server

// Fake Ory Hydra admin API for OIDC flow tests. Implements just the
// endpoints mokey calls via hydra-client-go v26. Challenges are seeded by
// tests; accept calls are recorded for assertions.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
	logoutSubject  map[string]string                 // logout_challenge -> subject
	// consent sessions ("connected apps"), keyed by subject
	consentSessions map[string][]fakeConsentSession
	// recorded accept calls
	acceptedLogins   []string               // subjects passed to login/accept
	acceptedConsent  map[string]interface{} // last consent accept body
	acceptedLogouts  []string               // logout challenges accepted
	revokedSubjects  []string               // DELETE sessions/login subjects
	revokedConsents  []revokedConsent       // DELETE sessions/consent calls
	rememberDuration int64
}

func newFakeHydra() *fakeHydra {
	f := &fakeHydra{
		loginRequests:   make(map[string]map[string]interface{}),
		consentSubject:  make(map[string]string),
		logoutSubject:   make(map[string]string),
		consentSessions: make(map[string][]fakeConsentSession),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/admin/oauth2/auth/requests/login", f.getLogin)
	mux.HandleFunc("/admin/oauth2/auth/requests/login/accept", f.acceptLogin)
	mux.HandleFunc("/admin/oauth2/auth/requests/consent", f.getConsent)
	mux.HandleFunc("/admin/oauth2/auth/requests/consent/accept", f.acceptConsent)
	mux.HandleFunc("/admin/oauth2/auth/requests/logout", f.getLogout)
	mux.HandleFunc("/admin/oauth2/auth/requests/logout/accept", f.acceptLogout)
	mux.HandleFunc("/admin/oauth2/auth/sessions/login", f.revokeSessions)
	mux.HandleFunc("/admin/oauth2/auth/sessions/consent", f.consentSessionsHandler)

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
	subject, ok := f.consentSubject[r.URL.Query().Get("consent_challenge")]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	writeJSON(w, map[string]interface{}{
		"challenge":       r.URL.Query().Get("consent_challenge"),
		"subject":         subject,
		"requested_scope": []string{"openid", "profile"},
	})
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
			if s.ClientID != client {
				kept = append(kept, s)
			}
		}
		f.consentSessions[subject] = kept
		w.WriteHeader(http.StatusNoContent)

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
