package proc

import (
	"runtime"
	"testing"
)

func TestParseMemInfo(t *testing.T) {
	t.Parallel()

	data := `MemTotal:       16384000 kB
MemFree:         2000000 kB
MemAvailable:    8192000 kB
Buffers:          500000 kB
Cached:          4000000 kB
`
	mem := ParseMemInfo(data)

	if mem.TotalBytes != 16384000*1024 {
		t.Errorf("TotalBytes = %d, want %d", mem.TotalBytes, 16384000*1024)
	}
	if mem.AvailableBytes != 8192000*1024 {
		t.Errorf("AvailableBytes = %d, want %d", mem.AvailableBytes, 8192000*1024)
	}
	if mem.UsedBytes != (16384000-8192000)*1024 {
		t.Errorf("UsedBytes = %d, want %d", mem.UsedBytes, (16384000-8192000)*1024)
	}
}

func TestParseMemInfo_Empty(t *testing.T) {
	t.Parallel()

	mem := ParseMemInfo("")
	if mem.TotalBytes != 0 || mem.AvailableBytes != 0 || mem.UsedBytes != 0 {
		t.Errorf("empty input should give zeros: %+v", mem)
	}
}

func TestParseMemInfo_MissingAvailable(t *testing.T) {
	t.Parallel()

	data := `MemTotal:       16384000 kB
MemFree:         2000000 kB
`
	mem := ParseMemInfo(data)
	if mem.TotalBytes != 16384000*1024 {
		t.Errorf("TotalBytes = %d", mem.TotalBytes)
	}
	if mem.UsedBytes != 16384000*1024 {
		t.Errorf("UsedBytes should equal Total when Available=0, got %d", mem.UsedBytes)
	}
}

func TestParseLoadAvg(t *testing.T) {
	t.Parallel()

	load, err := ParseLoadAvg("1.50 2.30 3.10 2/450 12345")
	if err != nil {
		t.Fatalf("ParseLoadAvg: %v", err)
	}

	if load.Load1 != 1.50 {
		t.Errorf("Load1 = %f, want 1.50", load.Load1)
	}
	if load.Load5 != 2.30 {
		t.Errorf("Load5 = %f, want 2.30", load.Load5)
	}
	if load.Load15 != 3.10 {
		t.Errorf("Load15 = %f, want 3.10", load.Load15)
	}
}

func TestParseLoadAvg_ZeroLoad(t *testing.T) {
	t.Parallel()

	load, err := ParseLoadAvg("0.00 0.00 0.00 1/100 1")
	if err != nil {
		t.Fatalf("ParseLoadAvg: %v", err)
	}
	if load.Load1 != 0 || load.Load5 != 0 || load.Load15 != 0 {
		t.Errorf("expected all zeros: %+v", load)
	}
}

func TestParseLoadAvg_TooFewFields(t *testing.T) {
	t.Parallel()

	_, err := ParseLoadAvg("1.0 2.0")
	if err == nil {
		t.Error("expected error for too few fields")
	}
}

func TestParseLoadAvg_Empty(t *testing.T) {
	t.Parallel()

	_, err := ParseLoadAvg("")
	if err == nil {
		t.Error("expected error for empty input")
	}
}

func TestParseMemLine(t *testing.T) {
	t.Parallel()

	cases := []struct {
		line string
		want uint64
	}{
		{"MemTotal:       16384000 kB", 16384000},
		{"MemAvailable:    8192000 kB", 8192000},
		{"MemTotal:", 0},
		{"", 0},
	}

	for _, tc := range cases {
		got := parseMemLine(tc.line)
		if got != tc.want {
			t.Errorf("parseMemLine(%q) = %d, want %d", tc.line, got, tc.want)
		}
	}
}

func TestProcReader_Read(t *testing.T) {
	r := NewReader([]string{"/"})
	stats, err := r.Read()
	if err != nil {
		t.Fatalf("Read: %v", err)
	}

	if stats.Memory.TotalBytes == 0 {
		t.Error("TotalBytes should be > 0")
	}
	if stats.Memory.AvailableBytes == 0 {
		t.Error("AvailableBytes should be > 0")
	}
	if stats.CPU.Count != uint32(runtime.NumCPU()) {
		t.Errorf("CPU.Count = %d, want %d", stats.CPU.Count, runtime.NumCPU())
	}
	if stats.Load.Load1 < 0 {
		t.Errorf("Load1 = %f, should be >= 0", stats.Load.Load1)
	}
	if len(stats.Disks) != 1 {
		t.Errorf("Disks count = %d, want 1", len(stats.Disks))
	}
	if stats.Disks[0].MountPoint != "/" {
		t.Errorf("Disks[0].MountPoint = %q", stats.Disks[0].MountPoint)
	}
	if stats.Disks[0].TotalBytes == 0 {
		t.Error("disk TotalBytes should be > 0")
	}
}

func TestProcReader_InvalidMountPoint(t *testing.T) {
	r := NewReader([]string{"/nonexistent-mount-12345"})
	stats, err := r.Read()
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(stats.Disks) != 0 {
		t.Errorf("bad mount point should be skipped, got %d disks", len(stats.Disks))
	}
}

func TestNewReader(t *testing.T) {
	t.Parallel()

	r := NewReader([]string{"/", "/var"})
	if len(r.mountPoints) != 2 {
		t.Errorf("mountPoints = %d, want 2", len(r.mountPoints))
	}
}

func TestReaderInterface(t *testing.T) {
	t.Parallel()

	var r Reader = &fakeReader{
		stats: &Stats{
			Memory: MemoryStats{TotalBytes: 1024},
			CPU:    CPUStats{Count: 4},
		},
	}

	stats, err := r.Read()
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if stats.Memory.TotalBytes != 1024 {
		t.Errorf("TotalBytes = %d", stats.Memory.TotalBytes)
	}
}

type fakeReader struct {
	stats *Stats
	err   error
}

func (f *fakeReader) Read() (*Stats, error) {
	return f.stats, f.err
}
