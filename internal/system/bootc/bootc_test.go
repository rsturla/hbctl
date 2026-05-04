package bootc

import (
	"context"
	"testing"
)

func TestParseStatus_Basic(t *testing.T) {
	t.Parallel()

	input := `{
		"status": {
			"booted": {
				"image": {
					"image": {
						"image": "registry.example.com/os:latest"
					},
					"version": "1.0.0"
				}
			},
			"staged": null
		}
	}`

	s, err := parseStatus([]byte(input))
	if err != nil {
		t.Fatalf("parseStatus: %v", err)
	}

	if s.Image != "registry.example.com/os:latest" {
		t.Errorf("Image = %q, want registry.example.com/os:latest", s.Image)
	}
	if s.Version != "1.0.0" {
		t.Errorf("Version = %q, want 1.0.0", s.Version)
	}
	if s.Staged != "" {
		t.Errorf("Staged = %q, want empty", s.Staged)
	}
}

func TestParseStatus_WithStaged(t *testing.T) {
	t.Parallel()

	input := `{
		"status": {
			"booted": {
				"image": {
					"image": {
						"image": "registry.example.com/os:v1.0.0"
					},
					"version": "1.0.0"
				}
			},
			"staged": {
				"image": {
					"image": {
						"image": "registry.example.com/os:v1.1.0"
					},
					"version": "1.1.0"
				}
			}
		}
	}`

	s, err := parseStatus([]byte(input))
	if err != nil {
		t.Fatalf("parseStatus: %v", err)
	}

	if s.Staged != "registry.example.com/os:v1.1.0" {
		t.Errorf("Staged = %q, want registry.example.com/os:v1.1.0", s.Staged)
	}
}

func TestParseStatus_InvalidJSON(t *testing.T) {
	t.Parallel()

	_, err := parseStatus([]byte("not json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestParseStatus_EmptyObject(t *testing.T) {
	t.Parallel()

	s, err := parseStatus([]byte(`{}`))
	if err != nil {
		t.Fatalf("parseStatus: %v", err)
	}
	if s.Image != "" {
		t.Errorf("Image = %q, want empty", s.Image)
	}
	if s.Version != "" {
		t.Errorf("Version = %q, want empty", s.Version)
	}
	if s.Staged != "" {
		t.Errorf("Staged = %q, want empty", s.Staged)
	}
}

func TestParseStatus_EmptyFields(t *testing.T) {
	t.Parallel()

	input := `{
		"status": {
			"booted": {
				"image": {
					"image": {
						"image": ""
					},
					"version": ""
				}
			},
			"staged": null
		}
	}`

	s, err := parseStatus([]byte(input))
	if err != nil {
		t.Fatalf("parseStatus: %v", err)
	}
	if s.Image != "" {
		t.Errorf("Image = %q, want empty", s.Image)
	}
	if s.Version != "" {
		t.Errorf("Version = %q, want empty", s.Version)
	}
}

func TestParseStatus_ExtraFields(t *testing.T) {
	t.Parallel()

	input := `{
		"apiVersion": "org.containers.bootc/v1alpha1",
		"kind": "BootcHost",
		"status": {
			"booted": {
				"image": {
					"image": {
						"image": "registry.example.com/os:v2.0.0",
						"transport": "registry"
					},
					"version": "2.0.0",
					"timestamp": "2026-01-01T00:00:00Z"
				},
				"incompatible": false,
				"pinned": false
			},
			"staged": null,
			"rollback": null,
			"type": "bootcHost"
		}
	}`

	s, err := parseStatus([]byte(input))
	if err != nil {
		t.Fatalf("parseStatus: %v", err)
	}
	if s.Image != "registry.example.com/os:v2.0.0" {
		t.Errorf("Image = %q", s.Image)
	}
	if s.Version != "2.0.0" {
		t.Errorf("Version = %q", s.Version)
	}
}

func TestParseStatus_LongImageRef(t *testing.T) {
	t.Parallel()

	ref := "us-east-1.ecr.aws/123456789012/very-long-repository-name/with/nested/paths/myimage@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	input := `{
		"status": {
			"booted": {
				"image": {
					"image": {
						"image": "` + ref + `"
					},
					"version": "v1.35.3-hb1"
				}
			},
			"staged": null
		}
	}`

	s, err := parseStatus([]byte(input))
	if err != nil {
		t.Fatalf("parseStatus: %v", err)
	}
	if s.Image != ref {
		t.Errorf("Image = %q, want %q", s.Image, ref)
	}
}

func TestStatusReaderInterface(t *testing.T) {
	t.Parallel()

	fake := &fakeStatusReader{
		status: &Status{Image: "test:latest", Version: "1.0.0"},
	}

	var sr StatusReader = fake
	s, err := sr.Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if s.Image != "test:latest" {
		t.Errorf("Image = %q", s.Image)
	}
}

type fakeStatusReader struct {
	status *Status
	err    error
}

func (f *fakeStatusReader) Status(_ context.Context) (*Status, error) {
	return f.status, f.err
}

func (f *fakeStatusReader) Switch(_ context.Context, _ string) error { return nil }
func (f *fakeStatusReader) Rollback(_ context.Context) error         { return nil }

func FuzzParseStatus(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"status":{}}`))
	f.Add([]byte(`{"status":{"booted":{"image":{"image":{"image":"test"},"version":"1.0"}}}}`))
	f.Add([]byte(`{"status":{"booted":{"image":{"image":{"image":"img"},"version":"v"}},"staged":{"image":{"image":{"image":"stg"}}}}}`))
	f.Add([]byte(`not json`))
	f.Add([]byte(``))
	f.Add([]byte(`null`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`{"status":{"booted":null}}`))
	f.Add([]byte(`{"status":{"booted":{"image":null}}}`))
	f.Add([]byte(`{"status":{"booted":{"image":{"image":null}}}}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		s, err := parseStatus(data)
		if err != nil {
			return
		}
		// If parsing succeeds, result must be non-nil and fields must be safe to read.
		if s == nil {
			t.Fatal("parseStatus returned nil Status without error")
		}
		_ = s.Image
		_ = s.Version
		_ = s.Staged
	})
}

func BenchmarkParseStatus(b *testing.B) {
	input := []byte(`{
		"status": {
			"booted": {
				"image": {
					"image": {
						"image": "registry.example.com/os:latest"
					},
					"version": "1.0.0"
				}
			},
			"staged": null
		}
	}`)

	for b.Loop() {
		_, err := parseStatus(input)
		if err != nil {
			b.Fatal(err)
		}
	}
}
