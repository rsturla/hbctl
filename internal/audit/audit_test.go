package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"fmt"
	"testing"
	"time"
)

func newTestCfg(dir string) Config {
	return Config{Dir: dir, MaxSizeMB: 10, MaxAgeDays: 7}
}

func TestFileLogger_BasicLogging(t *testing.T) {
	dir := t.TempDir()
	logger, err := NewFileLogger(newTestCfg(dir))
	if err != nil {
		t.Fatalf("NewFileLogger: %v", err)
	}
	defer func() { _ = logger.Close() }()

	logger.Log(Event{
		Type: "authn.success", Identity: "admin@corp.com",
		Action: "Version", Outcome: "success", PeerAddr: "10.0.0.1:54321",
	})

	data, _ := os.ReadFile(filepath.Join(dir, "audit.log"))
	var event Event
	_ = json.Unmarshal(data[:len(data)-1], &event)

	if event.Type != "authn.success" {
		t.Errorf("Type = %q", event.Type)
	}
	if event.ID == "" {
		t.Error("ID empty")
	}
	if event.Hash == "" {
		t.Error("Hash empty")
	}
	if event.PrevHash != "genesis" {
		t.Errorf("PrevHash = %q", event.PrevHash)
	}
}

func TestFileLogger_IntegrityChain(t *testing.T) {
	dir := t.TempDir()
	logger, _ := NewFileLogger(newTestCfg(dir))
	for i := 0; i < 10; i++ {
		logger.Log(Event{Type: "test", Outcome: "success"})
	}
	_ = logger.Close()

	result, _ := VerifyLog(filepath.Join(dir, "audit.log"), filepath.Join(dir, "hmac.key"))
	if result.ValidEvents != 10 {
		t.Errorf("ValidEvents = %d", result.ValidEvents)
	}
	if result.BrokenChain != 0 {
		t.Errorf("BrokenChain = %d", result.BrokenChain)
	}
}

func TestFileLogger_DetectsTampering(t *testing.T) {
	dir := t.TempDir()
	logger, _ := NewFileLogger(newTestCfg(dir))
	for i := 0; i < 5; i++ {
		logger.Log(Event{Type: "test", Outcome: "success"})
	}
	_ = logger.Close()

	logPath := filepath.Join(dir, "audit.log")
	data, _ := os.ReadFile(logPath)
	lines := splitLines(data)
	var ev Event
	_ = json.Unmarshal(lines[2], &ev)
	ev.Identity = "tampered"
	lines[2], _ = json.Marshal(ev)
	var out []byte
	for _, l := range lines {
		out = append(out, l...)
		out = append(out, '\n')
	}
	_ = os.WriteFile(logPath, out, 0o600)

	result, _ := VerifyLog(logPath, filepath.Join(dir, "hmac.key"))
	if result.InvalidHash == 0 {
		t.Error("should detect tampered event")
	}
}

func TestFileLogger_DetectsDeletion(t *testing.T) {
	dir := t.TempDir()
	logger, _ := NewFileLogger(newTestCfg(dir))
	for i := 0; i < 5; i++ {
		logger.Log(Event{Type: "test", Outcome: "success"})
	}
	_ = logger.Close()

	logPath := filepath.Join(dir, "audit.log")
	data, _ := os.ReadFile(logPath)
	lines := splitLines(data)
	remaining := append(lines[:2], lines[3:]...)
	var out []byte
	for _, l := range remaining {
		out = append(out, l...)
		out = append(out, '\n')
	}
	_ = os.WriteFile(logPath, out, 0o600)

	result, _ := VerifyLog(logPath, filepath.Join(dir, "hmac.key"))
	if result.BrokenChain == 0 {
		t.Error("should detect deleted event")
	}
}

func TestFileLogger_ShouldLog_ExcludeRules(t *testing.T) {
	t.Parallel()
	cfg := Config{Excludes: []ExcludeRule{
		{Identity: "prometheus", Action: "Health"},
		{Identity: "prometheus", Action: "Stats"},
		{Identity: "healthcheck-bot"},
	}}
	logger := &FileLogger{cfg: cfg}

	if logger.ShouldLog("prometheus", "Health", "*", "success") {
		t.Error("prometheus+Health success should be excluded")
	}
	if !logger.ShouldLog("prometheus", "Reboot", "*", "success") {
		t.Error("prometheus+Reboot should be logged — not excluded")
	}
	if logger.ShouldLog("healthcheck-bot", "Version", "*", "success") {
		t.Error("healthcheck-bot success should be excluded")
	}
	if !logger.ShouldLog("prometheus", "Health", "*", "denied") {
		t.Error("denied should always be logged")
	}
	if !logger.ShouldLog("prometheus", "Stats", "*", "error") {
		t.Error("error should always be logged")
	}
	if !logger.ShouldLog("", "Version", "*", "unauthenticated") {
		t.Error("empty identity should always be logged")
	}
	if !logger.ShouldLog("admin@corp.com", "Reboot", "*", "success") {
		t.Error("admin should be logged")
	}
}

func TestFileLogger_FailedRequests_AlwaysLogged(t *testing.T) {
	t.Parallel()
	cfg := Config{Excludes: []ExcludeRule{{Identity: "attacker"}}}
	logger := &FileLogger{cfg: cfg}

	for _, outcome := range []string{"denied", "error", "unauthenticated"} {
		if !logger.ShouldLog("attacker", "Reboot", "*", outcome) {
			t.Errorf("attacker+Reboot+%s should be logged", outcome)
		}
	}
}

func TestFileLogger_Subscribe(t *testing.T) {
	dir := t.TempDir()
	logger, _ := NewFileLogger(newTestCfg(dir))
	defer func() { _ = logger.Close() }()

	ch := logger.Subscribe()
	logger.Log(Event{Type: "test", Outcome: "success"})

	select {
	case ev := <-ch:
		if ev.Type != "test" {
			t.Errorf("Type = %q", ev.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestFileLogger_ChainSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	l1, _ := NewFileLogger(newTestCfg(dir))
	l1.Log(Event{Type: "first", Outcome: "success"})
	_ = l1.Close()

	l2, _ := NewFileLogger(newTestCfg(dir))
	l2.Log(Event{Type: "second", Outcome: "success"})
	_ = l2.Close()

	result, _ := VerifyLog(filepath.Join(dir, "audit.log"), filepath.Join(dir, "hmac.key"))
	if result.ValidEvents != 2 {
		t.Errorf("ValidEvents = %d", result.ValidEvents)
	}
	if result.BrokenChain != 0 {
		t.Errorf("BrokenChain = %d", result.BrokenChain)
	}
}

func TestFileLogger_FilePermissions(t *testing.T) {
	dir := t.TempDir()
	logger, _ := NewFileLogger(newTestCfg(dir))
	logger.Log(Event{Type: "test", Outcome: "success"})
	_ = logger.Close()

	logInfo, _ := os.Stat(filepath.Join(dir, "audit.log"))
	if logInfo.Mode().Perm() != 0o600 {
		t.Errorf("audit.log = %o", logInfo.Mode().Perm())
	}
	keyInfo, _ := os.Stat(filepath.Join(dir, "hmac.key"))
	if keyInfo.Mode().Perm() != 0o600 {
		t.Errorf("hmac.key = %o", keyInfo.Mode().Perm())
	}
}

func TestDefaultConfig(t *testing.T) {
	t.Parallel()
	cfg := DefaultConfig()
	if cfg.MaxSizeMB != 100 {
		t.Errorf("MaxSizeMB = %d", cfg.MaxSizeMB)
	}
	if cfg.MaxAgeDays != 90 {
		t.Errorf("MaxAgeDays = %d", cfg.MaxAgeDays)
	}
}

func TestFileLogger_ShouldLog_ResourceExclude(t *testing.T) {
	t.Parallel()
	cfg := Config{Excludes: []ExcludeRule{
		{Identity: "prometheus", Action: "ServiceStatus", Resource: "crio.service"},
	}}
	logger := &FileLogger{cfg: cfg}

	if logger.ShouldLog("prometheus", "ServiceStatus", "crio.service", "success") {
		t.Error("prometheus+ServiceStatus+crio.service should be excluded")
	}
	if !logger.ShouldLog("prometheus", "ServiceStatus", "kubelet.service", "success") {
		t.Error("prometheus+ServiceStatus+kubelet.service should be logged — different resource")
	}
	if !logger.ShouldLog("prometheus", "ServiceStatus", "crio.service", "denied") {
		t.Error("denied should always be logged even with resource match")
	}
}

func TestFileLogger_ConcurrentLogging(t *testing.T) {
	dir := t.TempDir()
	logger, err := NewFileLogger(newTestCfg(dir))
	if err != nil {
		t.Fatalf("NewFileLogger: %v", err)
	}

	const goroutines = 10
	const eventsPerGoroutine = 50

	done := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer func() { done <- struct{}{} }()
			for j := 0; j < eventsPerGoroutine; j++ {
				logger.Log(Event{
					Type:     "concurrent",
					Identity: fmt.Sprintf("worker-%d", id),
					Outcome:  "success",
				})
			}
		}(i)
	}
	for i := 0; i < goroutines; i++ {
		<-done
	}
	_ = logger.Close()

	result, err := VerifyLog(filepath.Join(dir, "audit.log"), filepath.Join(dir, "hmac.key"))
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	expected := goroutines * eventsPerGoroutine
	if result.TotalEvents != expected {
		t.Errorf("TotalEvents = %d, want %d", result.TotalEvents, expected)
	}
	if result.ValidEvents != expected {
		t.Errorf("ValidEvents = %d, want %d", result.ValidEvents, expected)
	}
	if result.BrokenChain != 0 {
		t.Errorf("BrokenChain = %d", result.BrokenChain)
	}
}

func TestFileLogger_ResourceFieldInHash(t *testing.T) {
	dir := t.TempDir()
	logger, _ := NewFileLogger(newTestCfg(dir))

	logger.Log(Event{
		Type: "test", Outcome: "success",
		ResourceType: "Service", ResourceID: "crio.service",
	})
	_ = logger.Close()

	// Tamper with resource ID
	logPath := filepath.Join(dir, "audit.log")
	data, _ := os.ReadFile(logPath)
	var ev Event
	_ = json.Unmarshal(data[:len(data)-1], &ev)
	ev.ResourceID = "kubelet.service"
	tampered, _ := json.Marshal(ev)
	_ = os.WriteFile(logPath, append(tampered, '\n'), 0o600)

	result, _ := VerifyLog(logPath, filepath.Join(dir, "hmac.key"))
	if result.InvalidHash == 0 {
		t.Error("tampering with resource ID should break hash")
	}
}

func TestFileLogger_MultipleSubscribers(t *testing.T) {
	dir := t.TempDir()
	logger, _ := NewFileLogger(newTestCfg(dir))
	defer func() { _ = logger.Close() }()

	ch1 := logger.Subscribe()
	ch2 := logger.Subscribe()

	logger.Log(Event{Type: "broadcast", Outcome: "success"})

	for _, ch := range []<-chan Event{ch1, ch2} {
		select {
		case ev := <-ch:
			if ev.Type != "broadcast" {
				t.Errorf("Type = %q", ev.Type)
			}
		case <-time.After(time.Second):
			t.Fatal("timeout on subscriber")
		}
	}
}

func TestVerifyLog_EmptyLog(t *testing.T) {
	dir := t.TempDir()
	logger, _ := NewFileLogger(newTestCfg(dir))
	_ = logger.Close()

	result, err := VerifyLog(filepath.Join(dir, "audit.log"), filepath.Join(dir, "hmac.key"))
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	if result.TotalEvents != 0 {
		t.Errorf("TotalEvents = %d", result.TotalEvents)
	}
}

func TestFileLogger_RotationTriggered(t *testing.T) {
	dir := t.TempDir()
	// MaxSizeMB=1, each event ~300 bytes, need ~3500 events to hit 1MB
	logger, err := NewFileLogger(Config{Dir: dir, MaxSizeMB: 1, MaxAgeDays: 90})
	if err != nil {
		t.Fatalf("NewFileLogger: %v", err)
	}

	// Write ~1.2MB of events (each ~350 bytes with padding)
	for i := 0; i < 4000; i++ {
		logger.Log(Event{
			Type: "filler", Outcome: "success",
			Detail: map[string]string{"i": fmt.Sprintf("%d", i)},
		})
	}
	_ = logger.Close()

	// Rotated file should exist
	if _, err := os.Stat(filepath.Join(dir, "audit.log.1")); err != nil {
		t.Error("audit.log.1 should exist after rotation")
	}

	// Current audit.log should exist and be smaller than max
	info, err := os.Stat(filepath.Join(dir, "audit.log"))
	if err != nil {
		t.Fatal("audit.log should exist after rotation")
	}
	if info.Size() > 1024*1024 {
		t.Errorf("audit.log should be < 1MB after rotation, got %d bytes", info.Size())
	}
}

func TestFileLogger_NoRotation_WhenDisabled(t *testing.T) {
	dir := t.TempDir()
	logger, _ := NewFileLogger(Config{Dir: dir, MaxSizeMB: 0, MaxAgeDays: 90})

	for i := 0; i < 100; i++ {
		logger.Log(Event{Type: "test", Outcome: "success"})
	}
	_ = logger.Close()

	if _, err := os.Stat(filepath.Join(dir, "audit.log.1")); !os.IsNotExist(err) {
		t.Error("should not rotate when MaxSizeMB=0")
	}
}

func TestFileLogger_RotationChainContinuity(t *testing.T) {
	dir := t.TempDir()
	logger, _ := NewFileLogger(Config{Dir: dir, MaxSizeMB: 1, MaxAgeDays: 90})

	// Write enough to trigger rotation
	for i := 0; i < 4000; i++ {
		logger.Log(Event{Type: "chain", Outcome: "success", Detail: map[string]string{"i": fmt.Sprintf("%d", i)}})
	}
	_ = logger.Close()

	// The current audit.log should be verifiable on its own
	// (chain restarts after rotation — prevHash reads from new file)
	result, err := VerifyLog(filepath.Join(dir, "audit.log"), filepath.Join(dir, "hmac.key"))
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	if result.InvalidHash != 0 {
		t.Errorf("InvalidHash = %d — current log should be valid", result.InvalidHash)
	}
}

func FuzzComputeHash(f *testing.F) {
	f.Add("authn.success", "admin", "Version", "Service", "crio.service", "success", "10.0.0.1:1234")
	f.Add("", "", "", "", "", "", "")
	f.Add("rpc.Reboot", "attacker\ninjection", "Reboot", "Node", "*", "denied", "0.0.0.0:0")

	dir := f.TempDir()
	logger, err := NewFileLogger(Config{Dir: dir, MaxSizeMB: 1, MaxAgeDays: 1})
	if err != nil {
		f.Fatalf("NewFileLogger: %v", err)
	}
	defer func() { _ = logger.Close() }()

	f.Fuzz(func(t *testing.T, typ, identity, action, resType, resID, outcome, peer string) {
		event := Event{
			Type: typ, Identity: identity, Action: action,
			ResourceType: resType, ResourceID: resID,
			Outcome: outcome, PeerAddr: peer,
			PrevHash: "genesis",
		}
		hash := logger.computeHash(event)
		if hash == "" {
			t.Error("empty hash")
		}
		hash2 := logger.computeHash(event)
		if hash != hash2 {
			t.Error("hash not deterministic")
		}
	})
}
