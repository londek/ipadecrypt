package testflight

import "testing"

func TestSelectVersion(t *testing.T) {
	versions := []Version{{Name: "1.0.1"}, {Name: "1.0.0"}}

	latest, err := selectVersion(versions, "")
	if err != nil || latest != "1.0.1" {
		t.Fatalf("latest = %q, %v", latest, err)
	}

	selected, err := selectVersion(versions, " 1.0.0 ")
	if err != nil || selected != "1.0.0" {
		t.Fatalf("selected = %q, %v", selected, err)
	}

	if _, err := selectVersion(versions, "1.2.0"); err == nil {
		t.Fatal("selected an unavailable version")
	}
}

func TestNewestBuildPrefersLatestThenKnownUploadDate(t *testing.T) {
	builds := []build{
		{ID: 10, UploadDate: "2026-11-18T12:00:00Z"},
		{ID: 30, UploadDate: "2026-11-19T12:00:00Z"},
		{ID: 20, UploadDate: "2026-11-17T12:00:00Z", Latest: true},
	}

	if got := newestBuild(builds, "1.0.0"); got.ID != 20 {
		t.Fatalf("build = %d, want 20", got.ID)
	}

	builds[2].Latest = false

	builds = append(builds, build{ID: 40, UploadDate: "invalid"})
	if got := newestBuild(builds, "1.0.0"); got.ID != 30 {
		t.Fatalf("build = %d, want 30", got.ID)
	}
}
