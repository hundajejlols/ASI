package nmap

import "testing"

func TestValidateNmapFlags(t *testing.T) {
	okCases := []string{
		"-sT -sV --version-light -T4 --max-retries 1",
		"-sS -Pn --host-timeout 45s --max-rate=250 -6",
		"",
	}
	for _, tc := range okCases {
		if _, err := ValidateNmapFlags(tc); err != nil {
			t.Fatalf("expected flags %q to pass, got error: %v", tc, err)
		}
	}

	badCases := []string{
		"-sT --script=vuln",
		"-sT --script exploit",
		"-sT -oN /tmp/pwn",
		"-sT -iL /etc/passwd",
		"--datadir /tmp",
		"-T5",
		"--max-retries 99",
	}
	for _, tc := range badCases {
		if _, err := ValidateNmapFlags(tc); err == nil {
			t.Fatalf("expected dangerous flags %q to be rejected, but passed", tc)
		}
	}
}

func TestValidateTarget(t *testing.T) {
	okTargets := []string{
		"172.28.0.10",
		"172.28.0.8/29",
		"10.0.0.0/16",
		"web.agh.edu.pl",
		"2001:db8::1",
	}
	for _, tgt := range okTargets {
		if err := ValidateTarget(tgt); err != nil {
			t.Fatalf("expected target %q to be valid, got: %v", tgt, err)
		}
	}

	badTargets := []string{
		"127.0.0.1",
		"127.0.0.0/8",
		"169.254.169.254",
		"::1",
		"localhost",
		"postgres",
		"redis",
		"backend",
		"--script=http-title",
		"10.0.0.1;id",
	}
	for _, tgt := range badTargets {
		if err := ValidateTarget(tgt); err == nil {
			t.Fatalf("expected unsafe target %q to be rejected, but passed", tgt)
		}
	}
}
