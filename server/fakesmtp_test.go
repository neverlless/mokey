package server

// Minimal SMTP sink for tests: accepts any mail and records the DATA
// payloads so tests can assert on delivered emails.

import (
	"bufio"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/spf13/viper"
)

type fakeSMTP struct {
	ln net.Listener

	mu       sync.Mutex
	messages []string // raw DATA payloads
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

	write("220 fake-smtp ready")
	var data strings.Builder
	inData := false

	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")

		if inData {
			if line == "." {
				inData = false
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

		switch {
		case strings.HasPrefix(strings.ToUpper(line), "DATA"):
			inData = true
			write("354 go ahead")
		case strings.HasPrefix(strings.ToUpper(line), "QUIT"):
			write("221 bye")
			return
		default:
			write("250 ok")
		}
	}
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
