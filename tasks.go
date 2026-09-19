package main

import (
	"encoding/json"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// This checks the published interpreter-to-fake-font execution pattern, not
// folderOpen alone (watch/build tasks legitimately use automatic execution).
// https://github.com/OpenSourceMalware/PolinRider
// https://github.com/n0m4dz/ByteGuard/blob/ac0f609ecdfeab88d731ed7b47ffdf38deb8256d/src/scanner.ts
type vscodeTask struct {
	Command    json.RawMessage   `json:"command"`
	Args       []json.RawMessage `json:"args"`
	RunOptions struct {
		RunOn string `json:"runOn"`
	} `json:"runOptions"`
	Windows *vscodeTask `json:"windows"`
	Linux   *vscodeTask `json:"linux"`
	OSX     *vscodeTask `json:"osx"`
}

func (s *Scanner) checkFontTask(path string, data []byte) {
	var config struct {
		Tasks []vscodeTask `json:"tasks"`
	}
	if json.Unmarshal(stripJSONComments(data), &config) != nil {
		return
	}
	for _, task := range config.Tasks {
		for _, override := range []*vscodeTask{nil, task.Windows, task.Linux, task.OSX} {
			candidate := task
			if override != nil {
				if override.Command != nil {
					candidate.Command = override.Command
				}
				if override.Args != nil {
					candidate.Args = override.Args
				}
			}
			if candidate.RunOptions.RunOn != "folderOpen" || !taskRunsFont(candidate) {
				continue
			}
			s.addFinding(Finding{Check: "font-execution-task", Severity: SevCritical, Path: path,
				Detail: "Automatic folder-open task executes a font-extension file with Node.js (attack: polinrider (DPRK))"})
			return
		}
	}
}

func taskCommand(raw json.RawMessage) string {
	var value string
	if json.Unmarshal(raw, &value) == nil {
		return value
	}
	var quoted struct {
		Value string `json:"value"`
	}
	_ = json.Unmarshal(raw, &quoted)
	return quoted.Value
}

var shellTokens = regexp.MustCompile(`"[^"\r\n]*"|'[^'\r\n]*'|&&|\|\||[;&|()\n]|[^\s;&|()]+`)

func taskRunsFont(task vscodeTask) bool {
	command := taskCommand(task.Command)
	args := make([]string, 0, len(task.Args))
	for _, arg := range task.Args {
		args = append(args, taskCommand(arg))
	}
	// A process task may supply an unquoted executable path containing spaces.
	if nodeExecutable(command) && len(task.Args) > 0 {
		return nodeFontArgument(args)
	}
	tokens := shellTokens.FindAllString(command, -1)
	tokens = append(tokens, args...)
	for i, token := range tokens {
		if i > 0 && !slices.Contains([]string{"&&", "||", ";", "|", "(", "\n"}, tokens[i-1]) {
			continue
		}
		if nodeExecutable(token) && nodeFontArgument(tokens[i+1:]) {
			return true
		}
	}
	return false
}

func nodeExecutable(token string) bool {
	token = strings.ReplaceAll(strings.Trim(token, `"'`), `\`, "/")
	base := token[strings.LastIndex(token, "/")+1:]
	return strings.EqualFold(base, "node") || strings.EqualFold(base, "node.exe")
}

func nodeFontArgument(args []string) bool {
	for _, arg := range args {
		arg = strings.Trim(arg, `"'`)
		if arg == "--" || arg == "--no-warnings" {
			continue
		}
		if strings.HasPrefix(arg, "-") {
			return false
		}
		return slices.Contains(fontExtensions, strings.ToLower(filepath.Ext(arg)))
	}
	return false
}

// VS Code accepts JSON with comments and trailing commas. Preserve quoted
// strings byte-for-byte; comment-like text inside commands must not be removed.
var jsoncTokens = regexp.MustCompile(`"(?:\\.|[^"\\])*"|//[^\r\n]*|/\*[\s\S]*?\*/`)
var jsonTrailingComma = regexp.MustCompile(`,\s*([}\]])`)

func stripJSONComments(data []byte) []byte {
	clean := jsoncTokens.ReplaceAllFunc(data, func(token []byte) []byte {
		if token[0] == '"' {
			return token
		}
		return []byte(" ")
	})
	// Handle trailing commas only outside strings, using the same lexer.
	var out []byte
	start := 0
	for _, loc := range jsoncTokens.FindAllIndex(clean, -1) {
		out = append(out, jsonTrailingComma.ReplaceAll(clean[start:loc[0]], []byte("$1"))...)
		out = append(out, clean[loc[0]:loc[1]]...)
		start = loc[1]
	}
	return append(out, jsonTrailingComma.ReplaceAll(clean[start:], []byte("$1"))...)
}
