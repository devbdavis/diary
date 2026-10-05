// diary prints one markdown digest of recent activity to stdout. It never
// writes files; an LLM agent downstream turns the digest into vault entries.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ---------- redaction ----------

var (
	rePrivateKey = regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY[A-Z ]*-----.*?(?:-----END [A-Z ]*PRIVATE KEY[A-Z ]*-----|\z)`)
	reAWS        = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	reGH         = regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{20,}|github_pat_\w+`)
	reSlackTok   = regexp.MustCompile(`xox[abprs]-[\w-]+`)
	reSlackHook  = regexp.MustCompile(`hooks\.slack\.com/(?:services|workflows|triggers)/\S+`)
	reSK         = regexp.MustCompile(`\bsk[_-][\w-]{20,}`)
	reLinear     = regexp.MustCompile(`lin_api_\w+`)
	reURLCreds   = regexp.MustCompile(`://[^/\s:@]+:[^/\s]+@`)
	reUserPass   = regexp.MustCompile(`(--user|\s-u)(=|\s+)[^\s:]+:\S+`)
	reBearer     = regexp.MustCompile(`(?i)\b(Bearer|Basic)\s+[\w.~+/=-]{8,}`)
	rePassToken  = regexp.MustCompile(`(?i)(--password|--token)(=|\s+)\S+`)
	reKey        = regexp.MustCompile(`(?i)\b(\w*(?:token|secret|password|passwd|pwd|key|auth|credential)\w*)(['"]?[ \t]*[:=][ \t]*['"]?)([^\s'"]+)`)

	ansiStripRe = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(\x07|\x1b\\)|\x1b[@-Z\\-_]|\r`)
)

// redact scrubs secrets from the whole digest; runs on the full text so multi-line PEM blocks are caught.
func redact(s string) string {
	s = rePrivateKey.ReplaceAllString(s, "[REDACTED]")
	s = reAWS.ReplaceAllString(s, "[REDACTED]")
	s = reGH.ReplaceAllString(s, "[REDACTED]")
	s = reSlackTok.ReplaceAllString(s, "[REDACTED]")
	s = reSlackHook.ReplaceAllString(s, "hooks.slack.com/[REDACTED]")
	s = reSK.ReplaceAllString(s, "[REDACTED]")
	s = reLinear.ReplaceAllString(s, "[REDACTED]")
	s = reURLCreds.ReplaceAllString(s, "://[REDACTED]@")
	s = reBearer.ReplaceAllString(s, "$1 [REDACTED]")
	s = reUserPass.ReplaceAllString(s, "$1$2[REDACTED]")
	s = rePassToken.ReplaceAllString(s, "$1$2[REDACTED]")
	s = reKey.ReplaceAllString(s, "$1$2[REDACTED]")
	return s
}

// ---------- shell history parsers ----------

type entry struct {
	t time.Time
	s string
}

// parseZsh handles zsh history, extended (": <epoch>:<dur>;<cmd>") or plain.
// zsh stores multi-line commands with a trailing backslash on every line but the last.
func parseZsh(r io.Reader) []entry {
	var out []entry
	cont := false
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		wasCont := cont
		cont = strings.HasSuffix(line, `\`)
		line = strings.TrimSuffix(line, `\`)
		if wasCont && len(out) > 0 {
			out[len(out)-1].s += "\n" + line
			continue
		}
		e := entry{s: line}
		if meta, cmd, ok := strings.Cut(strings.TrimPrefix(line, ": "), ";"); ok && strings.HasPrefix(line, ": ") {
			e.s = cmd
			if sec, _, ok := strings.Cut(meta, ":"); ok {
				if n, err := strconv.ParseInt(strings.TrimSpace(sec), 10, 64); err == nil {
					e.t = time.Unix(n, 0)
				}
			}
		}
		out = append(out, e)
	}
	return out
}

// parseBash handles a "#<epoch>" line (HISTTIMEFORMAT) stamping the command
// that immediately follows it. Commands without a preceding stamp get zero time.
func parseBash(r io.Reader) []entry {
	var out []entry
	var pending time.Time
	have := false
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") {
			if sec, err := strconv.ParseInt(strings.TrimSpace(line[1:]), 10, 64); err == nil {
				pending, have = time.Unix(sec, 0), true
				continue
			}
		}
		var t time.Time
		if have {
			t = pending
		}
		out = append(out, entry{t: t, s: line})
		have = false
	}
	return out
}

// parseFish handles fish's YAML-ish history: "- cmd: X" then "  when: <epoch>".
func parseFish(r io.Reader) []entry {
	var out []entry
	var cur *entry
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "- cmd: "):
			if cur != nil {
				out = append(out, *cur)
			}
			c := strings.TrimPrefix(line, "- cmd: ")
			cur = &entry{s: c}
		case strings.HasPrefix(line, "  when: "):
			if cur != nil {
				v := strings.TrimSpace(strings.TrimPrefix(line, "  when: "))
				if sec, err := strconv.ParseInt(v, 10, 64); err == nil {
					cur.t = time.Unix(sec, 0)
				}
			}
		}
	}
	if cur != nil {
		out = append(out, *cur)
	}
	return out
}

func collapseDup(in []entry) []entry {
	var out []entry
	for _, e := range in {
		if len(out) > 0 && out[len(out)-1].s == e.s {
			continue
		}
		out = append(out, e)
	}
	return out
}

func displayCmd(e entry) string {
	cmd := strings.ReplaceAll(e.s, "\n", " ⏎ ")
	if e.t.IsZero() {
		return cmd
	}
	return e.t.Local().Format("01-02 15:04") + " " + cmd
}

func countShape(m map[string]int, cmd string) {
	if i := strings.IndexByte(cmd, '\n'); i >= 0 {
		cmd = cmd[:i]
	}
	fields := strings.Fields(cmd)
	if len(fields) == 0 {
		return
	}
	shape := fields[0]
	if len(fields) > 1 && !strings.HasPrefix(fields[1], "-") {
		shape += " " + fields[1]
	}
	m[shape]++
}

func topShapes(m map[string]int, topN int) []string {
	type kv struct {
		k string
		v int
	}
	var arr []kv
	for k, v := range m {
		if v >= 2 {
			arr = append(arr, kv{k, v})
		}
	}
	sort.Slice(arr, func(i, j int) bool {
		if arr[i].v != arr[j].v {
			return arr[i].v > arr[j].v
		}
		return arr[i].k < arr[j].k
	})
	if len(arr) > topN {
		arr = arr[:topN]
	}
	out := make([]string, len(arr))
	for i, e := range arr {
		out[i] = fmt.Sprintf("- %d× %s", e.v, e.k)
	}
	return out
}

// ---------- small helpers ----------

func runCmd(ctx context.Context, name string, args ...string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, name, args...).CombinedOutput()
	return string(out), err
}

// readTail returns at most the last 8MB of a file; logs can grow to GBs and only the newest lines are kept anyway.
func readTail(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	const limit = 8 << 20
	if fi, err := f.Stat(); err == nil && fi.Size() > limit {
		if _, err := f.Seek(fi.Size()-limit, io.SeekStart); err != nil {
			return nil, err
		}
	}
	return io.ReadAll(f)
}

func onPath(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}

func errLine(out string, err error) string {
	msg := strings.TrimSpace(out)
	if msg == "" {
		msg = err.Error()
	}
	msg = strings.Join(strings.Fields(msg), " ")
	return "_error: " + msg + "_\n"
}

func truncRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

func capLines(lines []string, max int) []string {
	if max <= 0 || len(lines) <= max {
		return lines
	}
	omitted := len(lines) - max
	out := make([]string, 0, max+1)
	out = append(out, fmt.Sprintf("_(%d earlier lines omitted)_", omitted))
	out = append(out, lines[len(lines)-max:]...)
	return out
}

func splitComma(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func yn(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func inContainer() bool {
	for _, p := range []string{"/.dockerenv", "/run/.containerenv"} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

func osName(ctx context.Context) string {
	switch runtime.GOOS {
	case "darwin":
		if out, err := runCmd(ctx, "sw_vers", "-productVersion"); err == nil {
			return "macOS " + strings.TrimSpace(out)
		}
	case "linux":
		data, err := os.ReadFile("/etc/os-release")
		if err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				if strings.HasPrefix(line, "PRETTY_NAME=") {
					return strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"`)
				}
			}
		}
	}
	return ""
}

// ---------- sections ----------

func sectionEnvironment(ctx context.Context) string {
	var b strings.Builder
	host, _ := os.Hostname()
	fmt.Fprintf(&b, "- hostname: %s\n", host)
	fmt.Fprintf(&b, "- platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	if name := osName(ctx); name != "" {
		fmt.Fprintf(&b, "- os: %s\n", name)
	}
	if out, err := runCmd(ctx, "uname", "-r"); err == nil {
		fmt.Fprintf(&b, "- kernel: %s\n", strings.TrimSpace(out))
	}
	fmt.Fprintf(&b, "- container: %s\n", yn(inContainer()))
	fmt.Fprintf(&b, "- shell: %s\n", os.Getenv("SHELL"))

	for _, t := range [][]string{
		{"git", "--version"}, {"go", "version"}, {"node", "--version"},
		{"docker", "--version"}, {"kubectl", "version", "--client"}, {"gh", "--version"},
	} {
		if !onPath(t[0]) {
			continue
		}
		out, err := runCmd(ctx, t[0], t[1:]...)
		if err != nil {
			fmt.Fprintf(&b, "- %s: %s", t[0], errLine(out, err))
			continue
		}
		fmt.Fprintf(&b, "- %s: %s\n", t[0], firstLine(out))
	}

	if onPath("docker") {
		out, err := runCmd(ctx, "docker", "ps", "--format", "{{.Names}}\t{{.Image}}\t{{.Status}}")
		if err != nil {
			b.WriteString(errLine(out, err))
		} else if out = strings.TrimSpace(out); out != "" {
			b.WriteString(out)
			b.WriteString("\n")
		}
	}
	return b.String()
}

type histFile struct {
	path   string
	parser func(io.Reader) []entry
}

func pickParser(path string) func(io.Reader) []entry {
	base := filepath.Base(path)
	switch {
	case strings.Contains(base, "zsh"):
		return parseZsh
	case strings.Contains(base, "fish"):
		return parseFish
	default:
		return parseBash
	}
}

func sectionShellHistory(ctx context.Context, sinceTime time.Time, max int) (string, bool) {
	home := os.Getenv("HOME")
	var candidates []string
	if hf := os.Getenv("HISTFILE"); hf != "" {
		candidates = append(candidates, hf)
	}
	candidates = append(candidates,
		filepath.Join(home, ".zsh_history"),
		filepath.Join(home, ".bash_history"),
		filepath.Join(home, ".local/share/fish/fish_history"),
	)

	var files []histFile
	var seen []os.FileInfo
	for _, p := range candidates {
		fi, err := os.Stat(p)
		if err != nil || fi.IsDir() {
			continue
		}
		dup := false
		for _, s := range seen {
			if os.SameFile(s, fi) {
				dup = true
				break
			}
		}
		if dup {
			continue
		}
		seen = append(seen, fi)
		files = append(files, histFile{path: p, parser: pickParser(p)})
	}

	atuinOK := onPath("atuin")
	if len(files) == 0 && !atuinOK {
		return "", false
	}

	var timed []entry
	shapes := map[string]int{}
	var untimedBlocks []string

	for _, f := range files {
		data, err := readTail(f.path)
		if err != nil {
			continue
		}
		fi, err := os.Stat(f.path)
		if err != nil {
			continue
		}
		entries := collapseDup(f.parser(bytes.NewReader(data)))
		var untimed []entry
		for _, e := range entries {
			if e.t.IsZero() {
				untimed = append(untimed, e)
				continue
			}
			if e.t.Before(sinceTime) {
				continue
			}
			timed = append(timed, e)
			countShape(shapes, e.s)
		}
		if len(untimed) > 0 && !fi.ModTime().Before(sinceTime) {
			if len(untimed) > 50 {
				untimed = untimed[len(untimed)-50:]
			}
			var ub strings.Builder
			fmt.Fprintf(&ub, "### %s (untimed, last 50)\n", f.path)
			for _, e := range untimed {
				ub.WriteString(displayCmd(e))
				ub.WriteString("\n")
			}
			untimedBlocks = append(untimedBlocks, ub.String())
		}
	}

	sort.SliceStable(timed, func(i, j int) bool { return timed[i].t.Before(timed[j].t) })
	mainLines := make([]string, 0, len(timed))
	for _, e := range timed {
		mainLines = append(mainLines, displayCmd(e))
	}

	if atuinOK {
		out, err := runCmd(ctx, "atuin", "search", "--after", sinceTime.Format(time.RFC3339),
			"--format", "{time}\t{duration}\t{exit}\t{directory}\t{command}")
		var ab strings.Builder
		ab.WriteString("### atuin\n")
		if err != nil {
			ab.WriteString(errLine(out, err))
		} else if out = strings.TrimSpace(out); out != "" {
			ab.WriteString(out)
			ab.WriteString("\n")
		}
		untimedBlocks = append(untimedBlocks, ab.String())
	}

	var b strings.Builder
	if len(mainLines) > 0 {
		b.WriteString(strings.Join(capLines(mainLines, max), "\n"))
		b.WriteString("\n")
	}
	for _, blk := range untimedBlocks {
		b.WriteString(blk)
	}
	b.WriteString("### Top command shapes\n")
	for _, l := range topShapes(shapes, 15) {
		b.WriteString(l)
		b.WriteString("\n")
	}
	return b.String(), true
}

func sectionTerminalLogs(sinceTime time.Time, max int, dirs []string) (string, bool) {
	if len(dirs) == 0 {
		return "", false
	}
	var b strings.Builder
	for _, dir := range dirs {
		_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			info, err := d.Info()
			if err != nil || info.ModTime().Before(sinceTime) {
				return nil
			}
			data, err := readTail(path)
			if err != nil {
				return nil
			}
			text := ansiStripRe.ReplaceAllString(string(data), "")
			var lines []string
			for _, l := range strings.Split(text, "\n") {
				if strings.TrimSpace(l) != "" {
					lines = append(lines, l)
				}
			}
			if len(lines) == 0 {
				return nil
			}
			rel, err := filepath.Rel(dir, path)
			if err != nil {
				rel = path
			}
			fmt.Fprintf(&b, "### %s\n", rel)
			b.WriteString(strings.Join(capLines(lines, max), "\n"))
			b.WriteString("\n")
			return nil
		})
	}
	return b.String(), true
}

type claudeEntry struct {
	Display   string `json:"display"`
	Project   string `json:"project"`
	Timestamp int64  `json:"timestamp"`
	SessionID string `json:"sessionId"`
}

func sectionClaude(sinceTime time.Time, max int) (string, bool) {
	path := filepath.Join(os.Getenv("HOME"), ".claude", "history.jsonl")
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		var ce claudeEntry
		if err := json.Unmarshal(sc.Bytes(), &ce); err != nil {
			continue
		}
		ts := time.UnixMilli(ce.Timestamp)
		if ts.Before(sinceTime) {
			continue
		}
		disp := truncRunes(strings.Join(strings.Fields(ce.Display), " "), 240)
		lines = append(lines, fmt.Sprintf("%s [%s] %s", ts.Local().Format("01-02 15:04"), filepath.Base(ce.Project), disp))
	}
	return strings.Join(capLines(lines, max), "\n") + "\n", true
}

// findRepos walks root up to maxDepth levels looking for dirs containing
// .git; it does not descend into a repo once found, and skips node_modules,
// vendor, and hidden dirs.
func findRepos(root string, maxDepth int) []string {
	var repos []string
	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			if e.Name() == ".git" {
				repos = append(repos, dir)
				return
			}
		}
		if depth >= maxDepth {
			return
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			name := e.Name()
			if name == "node_modules" || name == "vendor" || strings.HasPrefix(name, ".") {
				continue
			}
			walk(filepath.Join(dir, name), depth+1)
		}
	}
	walk(root, 0)
	return repos
}

func sectionGit(ctx context.Context, sinceTime time.Time, max int, roots []string) (string, bool) {
	var repos []string
	for _, root := range roots {
		repos = append(repos, findRepos(root, 4)...)
	}
	if len(repos) == 0 {
		return "", false
	}

	seen := map[string]bool{}
	var b strings.Builder
	for _, r := range repos {
		idOut, err := runCmd(ctx, "git", "-C", r, "rev-parse", "--path-format=absolute", "--git-common-dir")
		id := strings.TrimSpace(idOut)
		if err != nil || id == "" {
			id = r
		}
		if seen[id] {
			continue
		}
		seen[id] = true

		logArgs := []string{"-C", r, "log", "--all", "--since=" + sinceTime.Format(time.RFC3339),
			"--date=format-local:%m-%d %H:%M", "--format=%h %ad %s"}
		// Per repo, so a repo-local user.email override is honoured.
		emailOut, _ := runCmd(ctx, "git", "-C", r, "config", "user.email")
		email := strings.TrimSpace(emailOut)
		if email != "" {
			logArgs = append(logArgs, "--author="+email)
		}
		logOut, _ := runCmd(ctx, "git", logArgs...)
		logOut = strings.TrimSpace(logOut)

		statusOut, _ := runCmd(ctx, "git", "-C", r, "status", "--porcelain")
		uncommitted := 0
		for _, l := range strings.Split(statusOut, "\n") {
			if strings.TrimSpace(l) != "" {
				uncommitted++
			}
		}

		if logOut == "" && uncommitted == 0 {
			continue
		}
		fmt.Fprintf(&b, "### %s\n", r)
		if logOut != "" {
			b.WriteString(strings.Join(capLines(strings.Split(logOut, "\n"), max), "\n"))
			b.WriteString("\n")
		}
		if uncommitted > 0 {
			fmt.Fprintf(&b, "_uncommitted: %d files_\n", uncommitted)
		}
	}
	return b.String(), true
}

func sectionGH(ctx context.Context, sinceTime time.Time, max int) (string, bool) {
	if !onPath("gh") {
		return "", false
	}
	args := []string{"search", "prs", "--author=@me", "--updated=>=" + sinceTime.Format("2006-01-02"),
		"--limit", "50", "--json", "repository,number,title,state,url",
		"--jq", `.[] | "\(.repository.nameWithOwner)#\(.number) [\(.state)] \(.title) \(.url)"`}
	out, err := runCmd(ctx, "gh", args...)
	if err != nil {
		return errLine(out, err), true
	}
	out = strings.TrimSpace(out)
	if out == "" {
		return "", true
	}
	return strings.Join(capLines(strings.Split(out, "\n"), max), "\n") + "\n", true
}

// sectionForgejo lists PRs updated in the window across every repo tea's default login can see.
func sectionForgejo(ctx context.Context, sinceTime time.Time, max int) (string, bool) {
	if !onPath("tea") {
		return "", false
	}
	out, err := runCmd(ctx, "tea", "api", "/repos/issues/search?type=pulls&state=all&limit=50&since="+
		url.QueryEscape(sinceTime.Format(time.RFC3339)))
	if err != nil {
		return errLine(out, err), true
	}
	var prs []struct {
		Number     int    `json:"number"`
		Title      string `json:"title"`
		State      string `json:"state"`
		HTMLURL    string `json:"html_url"`
		Repository struct {
			FullName string `json:"full_name"`
		} `json:"repository"`
	}
	if err := json.Unmarshal([]byte(out), &prs); err != nil {
		return errLine(out, err), true
	}
	var lines []string
	for _, p := range prs {
		lines = append(lines, fmt.Sprintf("%s#%d [%s] %s %s", p.Repository.FullName, p.Number, p.State, p.Title, p.HTMLURL))
	}
	return strings.Join(capLines(lines, max), "\n") + "\n", true
}

type slackResp struct {
	OK       bool   `json:"ok"`
	Error    string `json:"error"`
	Messages struct {
		Matches []struct {
			TS      string `json:"ts"`
			Text    string `json:"text"`
			Channel struct {
				Name string `json:"name"`
			} `json:"channel"`
			Permalink string `json:"permalink"`
		} `json:"matches"`
	} `json:"messages"`
}

func sectionSlack(client *http.Client, sinceTime time.Time, max int) (string, bool) {
	token := os.Getenv("SLACK_TOKEN")
	if token == "" {
		return "", false
	}
	req, err := http.NewRequest("GET", "https://slack.com/api/search.messages", nil)
	if err != nil {
		return errLine("", err), true
	}
	req.Header.Set("Authorization", "Bearer "+token)
	q := req.URL.Query()
	q.Set("query", "from:me after:"+sinceTime.AddDate(0, 0, -1).Format("2006-01-02"))
	q.Set("count", "100")
	q.Set("sort", "timestamp")
	req.URL.RawQuery = q.Encode()

	resp, err := client.Do(req)
	if err != nil {
		return errLine("", err), true
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var sr slackResp
	if err := json.Unmarshal(body, &sr); err != nil {
		return errLine(string(body), err), true
	}
	if !sr.OK {
		return "_error: " + sr.Error + "_\n", true
	}
	var lines []string
	for _, m := range sr.Messages.Matches {
		sec, _ := strconv.ParseFloat(m.TS, 64)
		ts := time.Unix(int64(sec), 0)
		if ts.Before(sinceTime) {
			continue
		}
		text := truncRunes(strings.Join(strings.Fields(m.Text), " "), 300)
		lines = append(lines, fmt.Sprintf("%s #%s: %s", ts.Local().Format("01-02 15:04"), m.Channel.Name, text))
	}
	return strings.Join(capLines(lines, max), "\n") + "\n", true
}

type linearResp struct {
	Data struct {
		Viewer struct {
			AssignedIssues struct {
				Nodes []struct {
					Identifier string `json:"identifier"`
					Title      string `json:"title"`
					URL        string `json:"url"`
					State      struct {
						Name string `json:"name"`
					} `json:"state"`
				} `json:"nodes"`
			} `json:"assignedIssues"`
		} `json:"viewer"`
	} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

func sectionLinear(client *http.Client, sinceTime time.Time, max int) (string, bool) {
	key := os.Getenv("LINEAR_API_KEY")
	if key == "" {
		return "", false
	}
	query := `query($since: DateTimeOrDuration!){ viewer { assignedIssues(filter:{updatedAt:{gt:$since}}, first:50){ nodes { identifier title url state { name } } } } }`
	reqBody, _ := json.Marshal(map[string]any{
		"query":     query,
		"variables": map[string]string{"since": sinceTime.Format(time.RFC3339)},
	})
	req, err := http.NewRequest("POST", "https://api.linear.app/graphql", bytes.NewReader(reqBody))
	if err != nil {
		return errLine("", err), true
	}
	req.Header.Set("Authorization", key)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return errLine("", err), true
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var lr linearResp
	if err := json.Unmarshal(body, &lr); err != nil {
		return errLine(string(body), err), true
	}
	if len(lr.Errors) > 0 {
		return "_error: " + lr.Errors[0].Message + "_\n", true
	}
	var lines []string
	for _, n := range lr.Data.Viewer.AssignedIssues.Nodes {
		lines = append(lines, fmt.Sprintf("%s [%s] %s %s", n.Identifier, n.State.Name, n.Title, n.URL))
	}
	return strings.Join(capLines(lines, max), "\n") + "\n", true
}

// ---------- main ----------

func main() {
	defaultRepos := os.Getenv("DIARY_REPOS")
	if defaultRepos == "" {
		defaultRepos = os.Getenv("HOME")
	}
	defaultLogs := os.Getenv("DIARY_TERM_LOGS")

	since := flag.Duration("since", 24*time.Hour, "how far back to look")
	max := flag.Int("max", 300, "per-section line cap (keeps newest)")
	reposFlag := flag.String("repos", defaultRepos, "comma-separated roots to scan for git repos")
	logsFlag := flag.String("logs", defaultLogs, "comma-separated dirs of terminal session logs")
	flag.Parse()

	now := time.Now()
	sinceTime := now.Add(-*since)
	ctx := context.Background()
	client := &http.Client{Timeout: 15 * time.Second}
	host, _ := os.Hostname()

	type section struct {
		name    string
		present bool
		body    string
	}
	var sections []section
	add := func(name string, body string, present bool) {
		sections = append(sections, section{name, present, body})
	}

	add("Environment", sectionEnvironment(ctx), true)
	var body string
	var ok bool
	body, ok = sectionShellHistory(ctx, sinceTime, *max)
	add("Shell history", body, ok)
	body, ok = sectionTerminalLogs(sinceTime, *max, splitComma(*logsFlag))
	add("Terminal logs", body, ok)
	body, ok = sectionClaude(sinceTime, *max)
	add("Claude Code prompts", body, ok)
	body, ok = sectionGit(ctx, sinceTime, *max, splitComma(*reposFlag))
	add("Git commits", body, ok)
	body, ok = sectionGH(ctx, sinceTime, *max)
	add("GitHub PRs", body, ok)
	body, ok = sectionForgejo(ctx, sinceTime, *max)
	add("Forgejo PRs", body, ok)
	body, ok = sectionSlack(client, sinceTime, *max)
	add("Slack", body, ok)
	body, ok = sectionLinear(client, sinceTime, *max)
	add("Linear", body, ok)

	var out strings.Builder
	fmt.Fprintf(&out, "# Diary digest %s %s → %s\n\n", host, sinceTime.Format(time.RFC3339), now.Format(time.RFC3339))

	var unavailable []string
	for _, s := range sections {
		if !s.present {
			unavailable = append(unavailable, s.name)
			continue
		}
		out.WriteString("## " + s.name + "\n")
		if body := strings.TrimRight(s.body, "\n"); body != "" {
			out.WriteString(body)
			out.WriteString("\n")
		}
		out.WriteString("\n")
	}
	out.WriteString("## Coverage\n")
	if len(unavailable) > 0 {
		out.WriteString("Unavailable: " + strings.Join(unavailable, ", ") + "\n")
	} else {
		out.WriteString("Unavailable: none\n")
	}

	fmt.Print(redact(out.String()))
}
