package kargs

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	defaultDir = "/etc/bootc/kargs.d"
	filename   = "50-hb-config.toml"
)

type Manager interface {
	Write(dir string, args []string) error
	Read(dir string) ([]string, error)
}

type FileManager struct{}

func NewManager() *FileManager {
	return &FileManager{}
}

func (m *FileManager) Write(dir string, args []string) error {
	if dir == "" {
		dir = defaultDir
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create kargs dir: %w", err)
	}

	path := filepath.Join(dir, filename)

	if len(args) == 0 {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove kargs file: %w", err)
		}
		return nil
	}

	content := renderTOML(args)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return fmt.Errorf("write kargs: %w", err)
	}

	return nil
}

func (m *FileManager) Read(dir string) ([]string, error) {
	if dir == "" {
		dir = defaultDir
	}

	path := filepath.Join(dir, filename)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read kargs: %w", err)
	}

	return parseTOML(string(data)), nil
}

func renderTOML(args []string) string {
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = fmt.Sprintf("%q", a)
	}
	return fmt.Sprintf("kargs = [%s]\n", strings.Join(quoted, ", "))
}

func parseTOML(content string) []string {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "kargs") {
			continue
		}

		_, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}

		value = strings.TrimSpace(value)
		value = strings.TrimPrefix(value, "[")
		value = strings.TrimSuffix(value, "]")
		value = strings.TrimSpace(value)

		if value == "" {
			return nil
		}

		return parseQuotedList(value)
	}

	return nil
}

func parseQuotedList(s string) []string {
	var args []string
	for len(s) > 0 {
		s = strings.TrimSpace(s)
		if s == "" {
			break
		}
		if s[0] == '"' {
			end := strings.Index(s[1:], "\"")
			if end < 0 {
				break
			}
			args = append(args, s[1:end+1])
			s = s[end+2:]
			s = strings.TrimLeft(s, ", ")
		} else {
			var token string
			token, s, _ = strings.Cut(s, ",")
			token = strings.TrimSpace(token)
			if token != "" {
				args = append(args, token)
			}
		}
	}
	return args
}
