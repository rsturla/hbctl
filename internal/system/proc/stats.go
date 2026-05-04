package proc

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

type MemoryStats struct {
	TotalBytes     uint64
	AvailableBytes uint64
	UsedBytes      uint64
}

type LoadStats struct {
	Load1  float64
	Load5  float64
	Load15 float64
}

type DiskStats struct {
	MountPoint     string
	Filesystem     string
	TotalBytes     uint64
	AvailableBytes uint64
	UsedBytes      uint64
}

type CPUStats struct {
	Count        uint32
	UsagePercent float64
}

type Stats struct {
	Memory MemoryStats
	CPU    CPUStats
	Load   LoadStats
	Disks  []DiskStats
}

type Reader interface {
	Read() (*Stats, error)
}

type ProcReader struct {
	mountPoints []string
}

func NewReader(mountPoints []string) *ProcReader {
	return &ProcReader{mountPoints: mountPoints}
}

func (r *ProcReader) Read() (*Stats, error) {
	mem, err := readMemInfo()
	if err != nil {
		return nil, fmt.Errorf("read meminfo: %w", err)
	}

	load, err := readLoadAvg()
	if err != nil {
		return nil, fmt.Errorf("read loadavg: %w", err)
	}

	cpu, err := readCPUStats()
	if err != nil {
		return nil, fmt.Errorf("read cpu stats: %w", err)
	}

	var disks []DiskStats
	for _, mp := range r.mountPoints {
		ds, err := readDiskStats(mp)
		if err != nil {
			continue
		}
		disks = append(disks, *ds)
	}

	return &Stats{
		Memory: *mem,
		CPU:    *cpu,
		Load:   *load,
		Disks:  disks,
	}, nil
}

func readMemInfo() (*MemoryStats, error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var totalKB, availableKB uint64
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "MemTotal:"):
			totalKB = parseMemLine(line)
		case strings.HasPrefix(line, "MemAvailable:"):
			availableKB = parseMemLine(line)
		}
	}

	total := totalKB * 1024
	available := availableKB * 1024
	used := total - available

	return &MemoryStats{
		TotalBytes:     total,
		AvailableBytes: available,
		UsedBytes:      used,
	}, nil
}

func parseMemLine(line string) uint64 {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0
	}
	v, _ := strconv.ParseUint(fields[1], 10, 64)
	return v
}

func readLoadAvg() (*LoadStats, error) {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return nil, err
	}

	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return nil, fmt.Errorf("unexpected loadavg format: %q", string(data))
	}

	load1, _ := strconv.ParseFloat(fields[0], 64)
	load5, _ := strconv.ParseFloat(fields[1], 64)
	load15, _ := strconv.ParseFloat(fields[2], 64)

	return &LoadStats{
		Load1:  load1,
		Load5:  load5,
		Load15: load15,
	}, nil
}

func readCPUStats() (*CPUStats, error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 5 {
			break
		}

		user, _ := strconv.ParseUint(fields[1], 10, 64)
		nice, _ := strconv.ParseUint(fields[2], 10, 64)
		system, _ := strconv.ParseUint(fields[3], 10, 64)
		idle, _ := strconv.ParseUint(fields[4], 10, 64)

		total := user + nice + system + idle
		if total == 0 {
			break
		}

		usage := float64(user+nice+system) / float64(total) * 100.0

		return &CPUStats{
			Count:        uint32(runtime.NumCPU()),
			UsagePercent: usage,
		}, nil
	}

	return &CPUStats{Count: uint32(runtime.NumCPU())}, nil
}

func readDiskStats(mountPoint string) (*DiskStats, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(mountPoint, &stat); err != nil {
		return nil, fmt.Errorf("statfs %s: %w", mountPoint, err)
	}

	total := stat.Blocks * uint64(stat.Bsize)
	available := stat.Bavail * uint64(stat.Bsize)
	used := total - (stat.Bfree * uint64(stat.Bsize))

	return &DiskStats{
		MountPoint:     mountPoint,
		TotalBytes:     total,
		AvailableBytes: available,
		UsedBytes:      used,
	}, nil
}

func ParseMemInfo(data string) *MemoryStats {
	var totalKB, availableKB uint64
	scanner := bufio.NewScanner(strings.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "MemTotal:"):
			totalKB = parseMemLine(line)
		case strings.HasPrefix(line, "MemAvailable:"):
			availableKB = parseMemLine(line)
		}
	}
	total := totalKB * 1024
	available := availableKB * 1024
	return &MemoryStats{
		TotalBytes:     total,
		AvailableBytes: available,
		UsedBytes:      total - available,
	}
}

func ParseLoadAvg(data string) (*LoadStats, error) {
	fields := strings.Fields(data)
	if len(fields) < 3 {
		return nil, fmt.Errorf("unexpected loadavg format: %q", data)
	}
	load1, _ := strconv.ParseFloat(fields[0], 64)
	load5, _ := strconv.ParseFloat(fields[1], 64)
	load15, _ := strconv.ParseFloat(fields[2], 64)
	return &LoadStats{Load1: load1, Load5: load5, Load15: load15}, nil
}
