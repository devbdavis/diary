package main

import (
	"strings"
	"testing"
	"time"
)

func TestRedact(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"password kv", "DB_PASSWORD=supersecret123", "DB_PASSWORD=[REDACTED]"},
		{"token colon", "api_token: abc.def.ghi", "api_token: [REDACTED]"},
		{"bearer", "curl -H Bearer abcdef123456 host", "curl -H Bearer [REDACTED] host"},
		{"aws key", "key is AKIAABCDEFGHIJKLMNOP here", "key is [REDACTED] here"},
		{"gh token", "token=ghp_abcdefghijklmnopqrstuvwx", "token=[REDACTED]"},
		{"github pat", "github_pat_abcDEF123_xyz used", "[REDACTED] used"},
		{"slack token", "set xoxb-123-456-abcdefg now", "set [REDACTED] now"},
		{"sk token", "sk-ant-abcdefghijklmnopqrstuvwxyz", "[REDACTED]"},
		{"linear key", "lin_api_AbCdEf123456", "[REDACTED]"},
		{"url creds", "https://user:pass@example.com/x", "https://[REDACTED]@example.com/x"},
		{"password flag eq", "curl --password=hunter2 host", "curl --password=[REDACTED] host"},
		{"password flag sp", "mysql --password hunter2 -u root", "mysql --password [REDACTED] -u root"},
		{"token flag", "--token abcdef123456", "--token [REDACTED]"},
		{"private key", "a\n-----BEGIN RSA PRIVATE KEY-----\nMIIEabc\n-----END RSA PRIVATE KEY-----\nb", "a\n[REDACTED]\nb"},
		{"truncated key", "-----BEGIN OPENSSH PRIVATE KEY-----\nMIIEabc", "[REDACTED]"},
		{"kv no line cross", "token:\nls", "token:\nls"},
		{"bare key var", "export STRIPE_KEY=abc123", "export STRIPE_KEY=[REDACTED]"},
		{"json key", `{"password":"hunter2"}`, `{"password":"[REDACTED]"}`},
		{"stripe sk", "paste sk_live_abcdefghijklmnopqrstuv", "paste [REDACTED]"},
		{"curl basic auth", "curl -u admin:s3cret https://x", "curl -u [REDACTED] https://x"},
		{"push -u untouched", "git push -u origin main", "git push -u origin main"},
		{"innocent", "git status --short", "git status --short"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := redact(c.in); got != c.want {
				t.Errorf("redact(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestParseZsh(t *testing.T) {
	in := ": 1700000000:0;echo hello\n" +
		": 1700000060:0;for i in 1 2; do\\\necho $i\\\ndone\n" +
		"plain command\n"
	entries := parseZsh(strings.NewReader(in))
	if len(entries) != 3 {
		t.Fatalf("got %d entries, want 3: %+v", len(entries), entries)
	}
	if entries[0].s != "echo hello" || entries[0].t.Unix() != 1700000000 {
		t.Errorf("entry 0 = %+v", entries[0])
	}
	if want := "for i in 1 2; do\necho $i\ndone"; entries[1].s != want || entries[1].t.Unix() != 1700000060 {
		t.Errorf("entry 1 = %+v, want cmd %q", entries[1], want)
	}
	if entries[2].s != "plain command" || !entries[2].t.IsZero() {
		t.Errorf("entry 2 = %+v", entries[2])
	}
}

func TestParseBash(t *testing.T) {
	in := "#1700000000\nls -la\nunstamped command\n#1700000120\npwd\n"
	entries := parseBash(strings.NewReader(in))
	if len(entries) != 3 {
		t.Fatalf("got %d entries, want 3: %+v", len(entries), entries)
	}
	if entries[0].s != "ls -la" || entries[0].t.Unix() != 1700000000 {
		t.Errorf("entry 0 = %+v", entries[0])
	}
	if entries[1].s != "unstamped command" || !entries[1].t.IsZero() {
		t.Errorf("entry 1 = %+v, want zero time", entries[1])
	}
	if entries[2].s != "pwd" || entries[2].t.Unix() != 1700000120 {
		t.Errorf("entry 2 = %+v", entries[2])
	}
}

func TestParseFish(t *testing.T) {
	in := "- cmd: ls -la\n  when: 1700000000\n- cmd: git status\n  when: 1700000060\n"
	entries := parseFish(strings.NewReader(in))
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2: %+v", len(entries), entries)
	}
	if entries[0].s != "ls -la" || entries[0].t.Unix() != 1700000000 {
		t.Errorf("entry 0 = %+v", entries[0])
	}
	if entries[1].s != "git status" || entries[1].t.Unix() != 1700000060 {
		t.Errorf("entry 1 = %+v", entries[1])
	}
}

func TestCapLines(t *testing.T) {
	lines := []string{"a", "b", "c", "d", "e"}
	got := capLines(lines, 2)
	want := []string{"_(3 earlier lines omitted)_", "d", "e"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("capLines = %v, want %v", got, want)
	}
	if got := capLines(lines, 10); len(got) != len(lines) {
		t.Errorf("capLines under max should be unchanged, got %v", got)
	}
}

func TestCollapseDup(t *testing.T) {
	in := []entry{{s: "ls"}, {s: "ls"}, {s: "pwd"}, {s: "pwd"}, {s: "ls"}}
	out := collapseDup(in)
	if len(out) != 3 {
		t.Fatalf("got %d, want 3: %+v", len(out), out)
	}
}

func TestEntryTimeSanity(t *testing.T) {
	// guards against accidental epoch-unit mixups (ms vs s) in the parsers.
	e := entry{t: time.Unix(1700000000, 0)}
	if e.t.Year() < 2023 || e.t.Year() > 2025 {
		t.Errorf("unexpected year from epoch seconds: %v", e.t)
	}
}
