package journal

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
)

type Entry struct {
	Timestamp string
	Unit      string
	Message   string
	Priority  string
}

type StreamOpts struct {
	Follow bool
	Unit   string
	Lines  int
	Dmesg  bool
}

type Reader interface {
	Stream(ctx context.Context, opts StreamOpts) (<-chan Entry, <-chan error)
}

type JournalctlReader struct{}

func NewReader() *JournalctlReader {
	return &JournalctlReader{}
}

func (r *JournalctlReader) Stream(ctx context.Context, opts StreamOpts) (<-chan Entry, <-chan error) {
	entries := make(chan Entry, 64)
	errc := make(chan error, 1)

	args := buildArgs(opts)

	go func() {
		defer close(entries)
		defer close(errc)

		cmd := exec.CommandContext(ctx, "journalctl", args...)
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			errc <- fmt.Errorf("journalctl stdout pipe: %w", err)
			return
		}

		if err := cmd.Start(); err != nil {
			errc <- fmt.Errorf("start journalctl: %w", err)
			return
		}

		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 256*1024), 256*1024)

		for scanner.Scan() {
			entry, err := parseJournalJSON(scanner.Bytes())
			if err != nil {
				continue
			}
			select {
			case entries <- entry:
			case <-ctx.Done():
				return
			}
		}

		if err := cmd.Wait(); err != nil {
			if ctx.Err() != nil {
				return
			}
			errc <- fmt.Errorf("journalctl exit: %w", err)
		}
	}()

	return entries, errc
}

func buildArgs(opts StreamOpts) []string {
	args := []string{"--output=json", "--no-pager"}

	if opts.Follow {
		args = append(args, "--follow")
	}
	if opts.Dmesg {
		args = append(args, "--dmesg")
	} else if opts.Unit != "" {
		args = append(args, "--unit="+opts.Unit)
	}
	if opts.Lines > 0 {
		args = append(args, "--lines="+strconv.Itoa(opts.Lines))
	} else if !opts.Follow {
		args = append(args, "--lines=100")
	}

	return args
}

func parseJournalJSON(data []byte) (Entry, error) {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return Entry{}, err
	}

	return Entry{
		Timestamp: getString(raw, "__REALTIME_TIMESTAMP"),
		Unit:      getString(raw, "_SYSTEMD_UNIT"),
		Message:   getString(raw, "MESSAGE"),
		Priority:  getString(raw, "PRIORITY"),
	}, nil
}

func getString(m map[string]any, key string) string {
	v, ok := m[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return fmt.Sprintf("%v", v)
	}
	return s
}
