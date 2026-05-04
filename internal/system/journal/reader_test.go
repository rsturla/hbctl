package journal

import (
	"testing"
)

func TestBuildArgs_Defaults(t *testing.T) {
	t.Parallel()

	args := buildArgs(StreamOpts{})

	assertContains(t, args, "--output=json")
	assertContains(t, args, "--no-pager")
	assertContains(t, args, "--lines=100")
	assertNotContains(t, args, "--follow")
}

func TestBuildArgs_Follow(t *testing.T) {
	t.Parallel()

	args := buildArgs(StreamOpts{Follow: true})

	assertContains(t, args, "--follow")
	assertNotContains(t, args, "--lines=100")
}

func TestBuildArgs_Unit(t *testing.T) {
	t.Parallel()

	args := buildArgs(StreamOpts{Unit: "kubelet.service"})
	assertContains(t, args, "--unit=kubelet.service")
}

func TestBuildArgs_Lines(t *testing.T) {
	t.Parallel()

	args := buildArgs(StreamOpts{Lines: 50})
	assertContains(t, args, "--lines=50")
	assertNotContains(t, args, "--lines=100")
}

func TestBuildArgs_FollowWithLines(t *testing.T) {
	t.Parallel()

	args := buildArgs(StreamOpts{Follow: true, Lines: 10})
	assertContains(t, args, "--follow")
	assertContains(t, args, "--lines=10")
}

func TestBuildArgs_AllOpts(t *testing.T) {
	t.Parallel()

	args := buildArgs(StreamOpts{Follow: true, Unit: "crio.service", Lines: 25})
	assertContains(t, args, "--follow")
	assertContains(t, args, "--unit=crio.service")
	assertContains(t, args, "--lines=25")
}

func TestBuildArgs_Dmesg(t *testing.T) {
	t.Parallel()

	args := buildArgs(StreamOpts{Dmesg: true, Lines: 10})
	assertContains(t, args, "--dmesg")
	assertContains(t, args, "--lines=10")
	assertNotContains(t, args, "--unit=")
}

func TestBuildArgs_DmesgOverridesUnit(t *testing.T) {
	t.Parallel()

	args := buildArgs(StreamOpts{Dmesg: true, Unit: "something.service"})
	assertContains(t, args, "--dmesg")
	assertNotContains(t, args, "--unit=something.service")
}

func TestParseJournalJSON(t *testing.T) {
	t.Parallel()

	input := `{
		"__REALTIME_TIMESTAMP": "1714838400000000",
		"_SYSTEMD_UNIT": "kubelet.service",
		"MESSAGE": "Starting kubelet...",
		"PRIORITY": "6"
	}`

	entry, err := parseJournalJSON([]byte(input))
	if err != nil {
		t.Fatalf("parseJournalJSON: %v", err)
	}

	if entry.Timestamp != "1714838400000000" {
		t.Errorf("Timestamp = %q", entry.Timestamp)
	}
	if entry.Unit != "kubelet.service" {
		t.Errorf("Unit = %q", entry.Unit)
	}
	if entry.Message != "Starting kubelet..." {
		t.Errorf("Message = %q", entry.Message)
	}
	if entry.Priority != "6" {
		t.Errorf("Priority = %q", entry.Priority)
	}
}

func TestParseJournalJSON_MissingFields(t *testing.T) {
	t.Parallel()

	entry, err := parseJournalJSON([]byte(`{"MESSAGE": "hello"}`))
	if err != nil {
		t.Fatalf("parseJournalJSON: %v", err)
	}

	if entry.Message != "hello" {
		t.Errorf("Message = %q", entry.Message)
	}
	if entry.Unit != "" {
		t.Errorf("Unit should be empty, got %q", entry.Unit)
	}
	if entry.Timestamp != "" {
		t.Errorf("Timestamp should be empty, got %q", entry.Timestamp)
	}
}

func TestParseJournalJSON_NumericPriority(t *testing.T) {
	t.Parallel()

	entry, err := parseJournalJSON([]byte(`{"PRIORITY": 3, "MESSAGE": "error"}`))
	if err != nil {
		t.Fatalf("parseJournalJSON: %v", err)
	}

	if entry.Priority != "3" {
		t.Errorf("Priority = %q, want '3'", entry.Priority)
	}
}

func TestParseJournalJSON_InvalidJSON(t *testing.T) {
	t.Parallel()

	_, err := parseJournalJSON([]byte("not json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestParseJournalJSON_EmptyObject(t *testing.T) {
	t.Parallel()

	entry, err := parseJournalJSON([]byte(`{}`))
	if err != nil {
		t.Fatalf("parseJournalJSON: %v", err)
	}
	if entry.Message != "" || entry.Unit != "" || entry.Timestamp != "" || entry.Priority != "" {
		t.Errorf("all fields should be empty: %+v", entry)
	}
}

func FuzzParseJournalJSON(f *testing.F) {
	f.Add([]byte(`{"MESSAGE":"test","PRIORITY":"6"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`not json`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{"PRIORITY":3}`))
	f.Add([]byte(`{"MESSAGE":["array"]}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		entry, err := parseJournalJSON(data)
		if err != nil {
			return
		}
		_ = entry.Message
		_ = entry.Unit
		_ = entry.Timestamp
		_ = entry.Priority
	})
}

func assertContains(t *testing.T, args []string, want string) {
	t.Helper()
	for _, a := range args {
		if a == want {
			return
		}
	}
	t.Errorf("args %v missing %q", args, want)
}

func assertNotContains(t *testing.T, args []string, notWant string) {
	t.Helper()
	for _, a := range args {
		if a == notWant {
			t.Errorf("args %v should not contain %q", args, notWant)
			return
		}
	}
}
