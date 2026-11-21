package testflight

import "testing"

func TestParsePublicLink(t *testing.T) {
	for _, input := range []string{
		"FAKE1234",
		" https://testflight.apple.com/join/FAKE1234 ",
		"itms-beta://testflight.apple.com/join/FAKE1234",
	} {
		code, err := ParsePublicLink(input)
		if err != nil || code != "FAKE1234" {
			t.Errorf("ParsePublicLink(%q) = %q, %v", input, code, err)
		}
	}
}

func TestParsePublicLinkRejectsUntrustedInput(t *testing.T) {
	for _, input := range []string{
		"",
		"not-a-code",
		"https://example.com/join/FAKE1234",
		"https://testflight.apple.com.evil.example/join/FAKE1234",
		"https://testflight.apple.com/join/FAKE1234/extra",
		"https://testflight.apple.com/join/FAKE1234?accept=true",
	} {
		if _, err := ParsePublicLink(input); err == nil {
			t.Errorf("ParsePublicLink(%q) succeeded", input)
		}
	}
}

func TestPublicLinkPathIsAccountScoped(t *testing.T) {
	client := Client{session: Session{AccountID: "account/id"}}
	got := client.publicLinkPath("FAKE1234")
	want := "/v3/accounts/account%2Fid/ru/FAKE1234"

	if got != want {
		t.Fatalf("path = %q, want %q", got, want)
	}
}

func TestPublicLinkAvailability(t *testing.T) {
	if err := (PublicLink{Status: PublicLinkOpen}).AvailabilityError(); err != nil {
		t.Fatal(err)
	}

	for _, status := range []string{PublicLinkFull, PublicLinkDisabled, PublicLinkNoBuilds} {
		if err := (PublicLink{Status: status}).AvailabilityError(); err == nil {
			t.Errorf("status %q is available", status)
		}
	}
}

func TestNormalizePublicLinkUsesBuildProvider(t *testing.T) {
	link, err := normalizePublicLink(PublicLink{
		Status: PublicLinkOpen,
		App: PublicLinkApp{
			ID:   1_000_000_000,
			Name: "Example App",
			Platforms: []PublicLinkPlatform{{
				Build: PublicLinkBuild{ProviderName: "Example Developer"},
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if link.App.ProviderName != "Example Developer" {
		t.Fatalf("provider = %q", link.App.ProviderName)
	}
}

func TestNormalizePublicLinkRejectsTerminalControlCharacters(t *testing.T) {
	_, err := normalizePublicLink(PublicLink{
		Status: PublicLinkOpen,
		App: PublicLinkApp{
			ID:           1_000_000_000,
			Name:         "Example\x1b[31m",
			ProviderName: "Example Developer",
		},
	})
	if err == nil {
		t.Fatal("accepted terminal control characters")
	}
}

func TestPublicLinkCompatibilityWarning(t *testing.T) {
	link := PublicLink{App: PublicLinkApp{Platforms: []PublicLinkPlatform{
		{Build: PublicLinkBuild{CompatibilityMessage: "Requires iOS 17.0 or later."}},
	}}}
	if got := link.CompatibilityWarning(); got != "Requires iOS 17.0 or later." {
		t.Fatalf("warning = %q", got)
	}

	link.App.Platforms = append(link.App.Platforms, PublicLinkPlatform{Build: PublicLinkBuild{Compatible: true}})
	if got := link.CompatibilityWarning(); got != "" {
		t.Fatalf("warning with compatible platform = %q", got)
	}
}
