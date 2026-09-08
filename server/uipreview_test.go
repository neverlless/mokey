package server

import (
	"os"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

// TestUIPreviewServe boots the real app against the fake FreeIPA on a
// local port for visual work (screenshots, theme checks). Skipped unless
// MOKEY_UI_PREVIEW is set:
//
//	MOKEY_UI_PREVIEW=127.0.0.1:8899 go test ./server/ -run TestUIPreviewServe -count=1
//
// Log in as walter / Secret123!
func TestUIPreviewServe(t *testing.T) {
	addr := os.Getenv("MOKEY_UI_PREVIEW")
	if addr == "" {
		t.Skip("set MOKEY_UI_PREVIEW=host:port to serve the UI preview")
	}

	app, router, fake := newTestAppWith(t, func() {
		viper.Set("accounts.enable_subid", true)
		viper.Set("admin.enabled", true)
	})

	fake.addUser("walter", &fakeUser{
		Password: "Secret123!",
		First:    "Walter", Last: "White",
		Email:  "wwhite@acme.local",
		Groups: []string{"ipausers", "chemists", "lab-admins", "admins"},
	})
	fake.addUser("jesse", &fakeUser{Password: "Secret123!"})
	fake.addGroup("chemists", &fakeGroup{Description: "Lab crew", ManagerUsers: []string{"walter"}, Members: []string{"walter"}})
	fake.addGroup("glee-club", &fakeGroup{Description: "After-hours choir", ManagerUsers: []string{"jesse"}})
	fake.subids["walter"] = &fakeSubid{SubUID: 2147483648, SubGID: 2147483648}
	fake.addHBACRule("lab-access", &fakeHBACRule{
		Enabled: true, Description: "Lab SSH",
		MemberGroups: []string{"chemists"}, MemberHosts: []string{"lab.acme.local"}, MemberServices: []string{"sshd"},
	})
	fake.addSudoRule("lab-sudo", &fakeSudoRule{
		Enabled: true, MemberGroups: []string{"chemists"},
		HostCategory: "all", AllowCommands: []string{"/usr/bin/systemctl"},
	})
	router.addGroupRequest("chemists", "jesse", groupRequestJoin)

	t.Logf("UI preview on http://%s (walter / Secret123!)", addr)
	if err := app.Listen(addr); err != nil {
		t.Fatal(err)
	}
}


// #24: the toggle used to sit in the top bar next to the logo, where users
// found it distracting; it belongs with the help icon in the footer
func TestThemeToggleLivesInTheFooter(t *testing.T) {
	header, err := os.ReadFile("templates/header.html")
	if err != nil {
		t.Fatalf("read header: %s", err)
	}
	footer, err := os.ReadFile("templates/footer.html")
	if err != nil {
		t.Fatalf("read footer: %s", err)
	}

	if strings.Contains(string(header), `id="theme-toggle"`) {
		t.Error("theme toggle is back in the top bar")
	}
	if !strings.Contains(string(footer), `id="theme-toggle"`) {
		t.Error("theme toggle is missing from the footer")
	}
}
