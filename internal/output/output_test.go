package output

import "testing"

func TestHumanBytes(t *testing.T) {
	t.Parallel()

	cases := []struct {
		input uint64
		want  string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1023, "1023 B"},
		{1024, "1.0 KiB"},
		{1536, "1.5 KiB"},
		{1048576, "1.0 MiB"},
		{1073741824, "1.0 GiB"},
		{10737418240, "10.0 GiB"},
		{33357516800, "31.1 GiB"},
	}

	for _, tc := range cases {
		got := HumanBytes(tc.input)
		if got != tc.want {
			t.Errorf("HumanBytes(%d) = %q, want %q", tc.input, got, tc.want)
		}
	}
}
