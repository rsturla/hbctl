package audit

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Event struct {
	Timestamp    time.Time         `json:"ts"`
	ID           string            `json:"id"`
	Type         string            `json:"type"`
	Identity     string            `json:"identity,omitempty"`
	Action       string            `json:"action,omitempty"`
	ResourceType string            `json:"resource_type,omitempty"`
	ResourceID   string            `json:"resource_id,omitempty"`
	Outcome      string            `json:"outcome"`
	PeerAddr     string            `json:"peer,omitempty"`
	Detail       map[string]string `json:"detail,omitempty"`
	PrevHash     string            `json:"prev_hash"`
	Hash         string            `json:"hash"`
}

// ExcludeRule suppresses audit for a specific identity+action+resource combination.
// Empty fields match anything. For example:
//   {identity: "prometheus", action: "Health"} — excludes prometheus Health on any resource
//   {identity: "prometheus", action: "ServiceStatus", resource: "crio.service"} — only crio status
//   {identity: "healthcheck-bot"} — excludes all actions on all resources
// Exclusions NEVER apply to failures — denied/error outcomes are always logged.
type ExcludeRule struct {
	Identity string `json:"identity"`
	Action   string `json:"action,omitempty"`
	Resource string `json:"resource,omitempty"`
}

type Config struct {
	Dir        string        `json:"dir"`
	Excludes   []ExcludeRule `json:"excludes"`
	MaxSizeMB  int           `json:"max_size_mb"`
	MaxAgeDays int           `json:"max_age_days"`
}

func DefaultConfig() Config {
	return Config{
		Dir:        "/var/log/hummingbird/audit",
		MaxSizeMB:  100,
		MaxAgeDays: 90,
	}
}

type Logger interface {
	Log(event Event)
	ShouldLog(identity, action, resource, outcome string) bool
	Subscribe() <-chan Event
	Close() error
}

type FileLogger struct {
	mu          sync.Mutex
	file        *os.File
	cfg         Config
	hmacKey     []byte
	prevHash    string
	subscribers []chan Event
	subMu       sync.RWMutex
}

func NewFileLogger(cfg Config) (*FileLogger, error) {
	if err := os.MkdirAll(cfg.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("create audit dir: %w", err)
	}

	path := filepath.Join(cfg.Dir, "audit.log")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}

	hmacKey := make([]byte, 32)
	keyPath := filepath.Join(cfg.Dir, "hmac.key")
	existing, err := os.ReadFile(keyPath)
	if err == nil && len(existing) == 32 {
		copy(hmacKey, existing)
	} else {
		if _, err := rand.Read(hmacKey); err != nil {
			return nil, fmt.Errorf("generate HMAC key: %w", err)
		}
		if err := os.WriteFile(keyPath, hmacKey, 0o600); err != nil {
			return nil, fmt.Errorf("write HMAC key: %w", err)
		}
	}

	prevHash := readLastHash(path)

	slog.Info("audit logger initialized", "dir", cfg.Dir)

	return &FileLogger{
		file:     f,
		cfg:      cfg,
		hmacKey:  hmacKey,
		prevHash: prevHash,
	}, nil
}

// ShouldLog returns true if this event should be audit-logged.
// Failed requests (denied, error, unauthenticated) are ALWAYS logged.
// Only successful requests from excluded identity+action pairs are suppressed.
func (l *FileLogger) ShouldLog(identity, action, resource, outcome string) bool {
	if outcome != "success" {
		return true
	}
	if identity == "" {
		return true
	}
	for _, rule := range l.cfg.Excludes {
		if rule.Identity != identity {
			continue
		}
		if rule.Action != "" && rule.Action != action {
			continue
		}
		if rule.Resource != "" && rule.Resource != resource {
			continue
		}
		return false
	}
	return true
}

func (l *FileLogger) Log(event Event) {
	l.mu.Lock()
	defer l.mu.Unlock()

	event.Timestamp = time.Now().UTC()
	event.ID = generateID()
	event.PrevHash = l.prevHash
	event.Hash = l.computeHash(event)
	l.prevHash = event.Hash

	data, err := json.Marshal(event)
	if err != nil {
		return
	}

	l.maybeRotate()

	if _, err := l.file.Write(append(data, '\n')); err != nil {
		slog.Error("audit write failed", "error", err, "event_id", event.ID)
	}

	l.subMu.RLock()
	for _, ch := range l.subscribers {
		select {
		case ch <- event:
		default:
			slog.Warn("audit subscriber dropped event", "event_id", event.ID)
		}
	}
	l.subMu.RUnlock()
}

func (l *FileLogger) Subscribe() <-chan Event {
	ch := make(chan Event, 256)
	l.subMu.Lock()
	l.subscribers = append(l.subscribers, ch)
	l.subMu.Unlock()
	return ch
}

func (l *FileLogger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	clear(l.hmacKey)

	l.subMu.Lock()
	for _, ch := range l.subscribers {
		close(ch)
	}
	l.subscribers = nil
	l.subMu.Unlock()

	return l.file.Close()
}

func (l *FileLogger) maybeRotate() {
	if l.cfg.MaxSizeMB <= 0 {
		return
	}

	info, err := l.file.Stat()
	if err != nil {
		return
	}

	maxBytes := int64(l.cfg.MaxSizeMB) * 1024 * 1024
	if info.Size() < maxBytes {
		return
	}

	_ = l.file.Close()

	logPath := filepath.Join(l.cfg.Dir, "audit.log")

	// Shift existing rotated files: .3 → .4, .2 → .3, .1 → .2
	for i := 4; i >= 1; i-- {
		from := fmt.Sprintf("%s.%d", logPath, i)
		to := fmt.Sprintf("%s.%d", logPath, i+1)
		_ = os.Rename(from, to)
	}
	_ = os.Rename(logPath, logPath+".1")

	// Delete old rotated files beyond retention
	if l.cfg.MaxAgeDays > 0 {
		cutoff := time.Now().AddDate(0, 0, -l.cfg.MaxAgeDays)
		entries, _ := os.ReadDir(l.cfg.Dir)
		for _, entry := range entries {
			if entry.IsDir() || entry.Name() == "hmac.key" {
				continue
			}
			info, err := entry.Info()
			if err != nil {
				continue
			}
			if info.ModTime().Before(cutoff) {
				_ = os.Remove(filepath.Join(l.cfg.Dir, entry.Name()))
				slog.Info("removed old audit log", "file", entry.Name())
			}
		}
	}

	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		slog.Error("failed to create new audit log after rotation", "error", err)
		return
	}
	l.file = f

	slog.Info("audit log rotated", "max_mb", l.cfg.MaxSizeMB)
}

func (l *FileLogger) computeHash(event Event) string {
	mac := hmac.New(sha256.New, l.hmacKey)
	_, _ = fmt.Fprintf(mac, "%s|%s|%s|%s|%s|%s|%s|%s|%s|%s",
		event.Timestamp.Format(time.RFC3339Nano),
		event.ID,
		event.Type,
		event.Identity,
		event.Action,
		event.ResourceType,
		event.ResourceID,
		event.Outcome,
		event.PeerAddr,
		event.PrevHash,
	)
	return hex.EncodeToString(mac.Sum(nil))
}

func generateID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func readLastHash(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return "genesis"
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil || info.Size() == 0 {
		return "genesis"
	}

	// Read last 8KB — enough for several audit lines
	readSize := int64(8192)
	offset := info.Size() - readSize
	if offset < 0 {
		offset = 0
		readSize = info.Size()
	}

	buf := make([]byte, readSize)
	if _, err := f.ReadAt(buf, offset); err != nil {
		return "genesis"
	}

	lines := splitLines(buf)
	for i := len(lines) - 1; i >= 0; i-- {
		if len(lines[i]) == 0 {
			continue
		}
		var event Event
		if err := json.Unmarshal(lines[i], &event); err == nil {
			return event.Hash
		}
	}
	return "genesis"
}

func splitLines(data []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i, b := range data {
		if b == '\n' {
			lines = append(lines, data[start:i])
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, data[start:])
	}
	return lines
}
