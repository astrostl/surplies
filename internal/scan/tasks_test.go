package scan

import (
	"path/filepath"
	"testing"
)

func TestFakeFontTasksWithoutPayloadSignature(t *testing.T) {
	cases := []struct {
		name, data string
		want       bool
	}{
		{"dune", `{"tasks":[{"command":"(command -v node >/dev/null 2>&1 && node ./public/fonts/fa-solid-400.woff2) || (where node >nul 2>&1 && node ./public/fonts/fa-solid-400.woff2) || echo ''","runOptions":{"runOn":"folderOpen"}}]}`, true},
		{"jsonc", `{// comment
"tasks":[{"command":"node './fonts/my font.woff2'", "runOptions":{"runOn":"folderOpen",},},],}`, true},
		{"process", `{"tasks":[{"command":"C:\\Program Files\\nodejs\\node.exe","args":["fonts/payload.woff2"],"runOptions":{"runOn":"folderOpen"}}]}`, true},
		{"override", `{"tasks":[{"command":"echo ok","windows":{"command":"node.exe","args":["payload.woff2"]},"runOptions":{"runOn":"folderOpen"}}]}`, true},
		{"quoted command", `{"tasks":[{"command":{"value":"node","quoting":"strong"},"args":["payload.woff"],"runOptions":{"runOn":"folderOpen"}}]}`, true},
		{"quoted argument", `{"tasks":[{"command":"node","args":[{"value":"fonts/my font.woff2","quoting":"strong"}],"runOptions":{"runOn":"folderOpen"}}]}`, true},
		{"benign watch", `{"tasks":[{"command":"node watch.js","runOptions":{"runOn":"folderOpen"}}]}`, false},
		{"echo", `{"tasks":[{"command":"echo node foo.woff2","runOptions":{"runOn":"folderOpen"}}]}`, false},
		{"argument only", `{"tasks":[{"command":"node convert.js font.woff2","runOptions":{"runOn":"folderOpen"}}]}`, false},
		{"option only", `{"tasks":[{"command":"node --output=font.woff2","runOptions":{"runOn":"folderOpen"}}]}`, false},
		{"not automatic", `{"tasks":[{"command":"node font.woff2"}]}`, false},
		{"comment only", `{"tasks":[] /* node foo.woff2 folderOpen */}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "repo", ".vscode", "tasks.json")
			writeFixture(t, path, tc.data)
			s := New(dir, false)
			s.scanProjectDirs()
			got := len(findingsFor(s, "font-execution-task")) > 0
			if got != tc.want {
				t.Fatalf("got %v want %v: %+v", got, tc.want, s.Findings)
			}
		})
	}
}
