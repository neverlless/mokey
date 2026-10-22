package server

import (
	"net"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
)

func TestServeListensOnIPv6(t *testing.T) {
	probe, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %s", err)
	}
	probe.Close()

	app, _, _ := newTestApp(t)
	s := &Server{ListenAddress: "[::1]:0", app: app}

	listening := make(chan string, 1)
	app.Hooks().OnListen(func(ld fiber.ListenData) error {
		listening <- ld.Host + ":" + ld.Port
		return nil
	})

	served := make(chan error, 1)
	go func() { served <- s.Serve() }()

	select {
	case addr := <-listening:
		conn, err := net.DialTimeout("tcp6", addr, time.Second)
		if err != nil {
			t.Fatalf("dial %s: %s", addr, err)
		}
		conn.Close()
		if err := s.Shutdown(t.Context()); err != nil {
			t.Fatalf("shutdown: %s", err)
		}
		<-served
	case err := <-served:
		t.Fatalf("Serve on [::1]:0 failed: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not start listening")
	}
}
