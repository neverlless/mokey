package server

// Minimal SMTP sink for tests: accepts any mail and records the DATA
// payloads so tests can assert on delivered emails.

import (
	"bufio"
	"encoding/base64"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/spf13/viper"
)

type fakeSMTP struct {
	ln net.Listener

	// behaviour knobs, set before the first connection
	authMechs  string // advertised after EHLO; empty means no AUTH extension
	rejectData bool   // reply 5xx to the final dot instead of accepting

	mu       sync.Mutex
	messages []string // raw DATA payloads
	commands []string // command lines seen, excluding DATA payloads
	authUser string
	authPass string
}

// newFakeSMTP starts the sink and points mokey's mailer config at it
func newFakeSMTP(t *testing.T) *fakeSMTP {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fake smtp listen: %s", err)
	}

	f := &fakeSMTP{ln: ln}
	go f.serve()
	t.Cleanup(func() { ln.Close() })

	addr := ln.Addr().(*net.TCPAddr)
	viper.Set("email.smtp_host", "127.0.0.1")
	viper.Set("email.smtp_port", addr.Port)

	return f
}

func (f *fakeSMTP) serve() {
	for {
		conn, err := f.ln.Accept()
		if err != nil {
			return
		}
		go f.handle(conn)
	}
}

func (f *fakeSMTP) handle(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	write := func(s string) { conn.Write([]byte(s + "\r\n")) }

	// reads one client line, empty string on a dead connection
	read := func() string {
		line, err := r.ReadString('\n')
		if err != nil {
			return ""
		}
		return strings.TrimRight(line, "\r\n")
	}

	write("220 fake-smtp ready")
	var data strings.Builder
	inData := false

	for {
		raw, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line := strings.TrimRight(raw, "\r\n")

		if inData {
			if line == "." {
				inData = false
				if f.rejectData {
					data.Reset()
					write("550 5.7.1 message rejected by policy")
					continue
				}
				f.mu.Lock()
				f.messages = append(f.messages, data.String())
				f.mu.Unlock()
				data.Reset()
				write("250 ok")
				continue
			}
			data.WriteString(line + "\n")
			continue
		}

		f.mu.Lock()
		f.commands = append(f.commands, line)
		f.mu.Unlock()

		upper := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
			if f.authMechs == "" {
				write("250 ok")
				continue
			}
			write("250-fake-smtp")
			write("250 AUTH " + f.authMechs)
		case strings.HasPrefix(upper, "AUTH "):
			f.auth(strings.TrimSpace(line[len("AUTH "):]), read, write)
		case strings.HasPrefix(upper, "DATA"):
			inData = true
			write("354 go ahead")
		case strings.HasPrefix(upper, "QUIT"):
			write("221 bye")
			return
		default:
			write("250 ok")
		}
	}
}

// auth answers an AUTH command the way the advertised mechanisms allow. A
// mechanism the sink did not advertise gets the same 504 the server in #31
// returns for AUTH PLAIN.
func (f *fakeSMTP) auth(arg string, read func() string, write func(string)) {
	mech, initial, _ := strings.Cut(arg, " ")
	mech = strings.ToUpper(mech)

	if !strings.Contains(strings.ToUpper(f.authMechs), mech) {
		write("504 5.7.4 Unrecognized authentication type")
		return
	}

	decode := func(s string) string {
		b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
		if err != nil {
			return ""
		}
		return string(b)
	}

	switch mech {
	case "PLAIN":
		if initial == "" {
			write("334 ")
			initial = read()
		}
		parts := strings.Split(decode(initial), "\x00")
		if len(parts) == 3 {
			f.mu.Lock()
			f.authUser, f.authPass = parts[1], parts[2]
			f.mu.Unlock()
		}
	case "LOGIN":
		write("334 " + base64.StdEncoding.EncodeToString([]byte("Username:")))
		user := decode(read())
		write("334 " + base64.StdEncoding.EncodeToString([]byte("Password:")))
		pass := decode(read())
		f.mu.Lock()
		f.authUser, f.authPass = user, pass
		f.mu.Unlock()
	default:
		write("535 5.7.8 authentication failed")
		return
	}

	write("235 2.7.0 authentication succeeded")
}

func (f *fakeSMTP) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.messages)
}

func (f *fakeSMTP) all() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.messages...)
}

// credentials returns the username and password the sink accepted
func (f *fakeSMTP) credentials() (string, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.authUser, f.authPass
}

// sawCommand reports whether any command line started with prefix
func (f *fakeSMTP) sawCommand(prefix string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.commands {
		if strings.HasPrefix(strings.ToUpper(c), strings.ToUpper(prefix)) {
			return true
		}
	}
	return false
}
