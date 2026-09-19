package scan

import (
	"bytes"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Community matching forms, evaluated as contextual warnings rather than
// inheriting upstream severity. No incident-only DUNE constants are added.
// https://github.com/n0m4dz/ByteGuard/blob/ac0f609ecdfeab88d731ed7b47ffdf38deb8256d/rules/default.rules.json
var victimAssignment = regexp.MustCompile(`global\s*\[\s*['"](?:_V|!)['"]\s*\]\s*=`)
var inlineLoader = regexp.MustCompile(`import\s*\.\s*meta\s*\.\s*url\s*\)\s*\(\s*['"]\.[^'"\r\n]*\.cjs['"]`)
var buildMarker = regexp.MustCompile(`/\*(?:M[0-9]{6}[A-Z]?|RS[0-9]{6})\*/`)

// Separate literal prefixes let Go's regexp engine skip directly to candidate
// calls instead of running the alternation machine over every source byte.
var decodeEval = regexp.MustCompile(`eval\s*\(\s*(?:Buffer\s*\.\s*from|atob|unescape|decodeURIComponent)\s*\(`)
var decodeFunction = regexp.MustCompile(`Function\s*\(\s*(?:Buffer\s*\.\s*from|atob|unescape|decodeURIComponent)\s*\(`)

func matchesDecodeExecute(data []byte) bool {
	return decodeEval.Match(data) || decodeFunction.Match(data)
}

var downloadShell = regexp.MustCompile(`\b(?:curl|wget)\b[^\r\n|]{0,200}\|\s*(?:ba|z)?sh\b`)
var escapedASCII = regexp.MustCompile(`(?:\\u00[2-7][0-9a-fA-F]){8,}`)
var escapeLiteral = regexp.MustCompile(`\\(?:u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2})`)
var hiddenSpawn = regexp.MustCompile(`(?s)spawn\s*\(.{0,500}(?:detached\s*:\s*true.{0,200}windowsHide\s*:\s*true|windowsHide\s*:\s*true.{0,200}detached\s*:\s*true)`)

// Decode fixed-width ASCII escapes only; never evaluate code or unpack payloads.
// Escaped identifiers are documented in https://osv.dev/vulnerability/MAL-2026-11132.
func normalizeASCII(data []byte) []byte {
	if bytes.IndexByte(data, '\\') < 0 {
		return data
	}
	return escapeLiteral.ReplaceAllFunc(data, func(token []byte) []byte {
		value := 0
		for _, b := range token[2:] {
			value *= 16
			switch {
			case b >= '0' && b <= '9':
				value += int(b - '0')
			case b >= 'a' && b <= 'f':
				value += int(b - 'a' + 10)
			default:
				value += int(b - 'A' + 10)
			}
		}
		if value >= 32 && value < 127 {
			return []byte{byte(value)}
		}
		return token
	})
}
func researchText(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".md" || ext == ".txt" {
		return true
	}
	for part := range strings.SplitSeq(filepath.ToSlash(path), "/") {
		switch strings.ToLower(part) {
		case "testdata", "fixtures", "__fixtures__", "tests", "__tests__", "docs":
			return true
		}
	}
	name := strings.ToLower(filepath.Base(path))
	return strings.Contains(name, ".test.") || strings.Contains(name, ".spec.") || strings.HasSuffix(name, "_test.go")
}
func (s *Scanner) inspectGeneralContent(path string, data []byte) {
	if filepath.Base(path) == "settings.json" && filepath.Base(filepath.Dir(path)) == ".vscode" {
		s.checkWorkspaceSettings(path, data)
	}
	if assetExtension(strings.ToLower(filepath.Ext(path))) {
		data = trimAssetPadding(data)
	}
	if bytes.IndexByte(data, 0) >= 0 || !utf8.Valid(data) {
		return
	}
	normalized := normalizeASCII(data)
	if sig, ok := payloadSignature(normalized); ok {
		severity := SevCritical
		detail := fmt.Sprintf("%s (attack: %s)", sig.Desc, sig.Attack)
		if researchText(path) {
			severity = SevWarn
			detail += "; documentation/test context: may be an inert example, not evidence of execution"
		}
		s.addFinding(Finding{Check: "payload-signature", Severity: severity, Path: path, Detail: detail})
		return
	} else if victimAssignment.Match(normalized) {
		s.addFinding(Finding{Check: "loader-variant", Severity: SevWarn, Path: path, Detail: "Global injection assignment matches a published loader form; review surrounding code"})
	}
	s.inspectLoaderPatterns(path, data, normalized)
	s.checkUnicode(path, data)

}

// GlassWorm variation-selector payloads: both Unicode ranges are covered;
// ordinary emoji selectors, balanced RTL text and non-ASCII joiners are allowed.
// https://www.endorlabs.com/reports/invisible-threats-glassworm-unicode-vscode
// https://www.aikido.dev/blog/glassworm-returns-unicode-attack-github-npm-vscode
func (s *Scanner) checkUnicode(path string, data []byte) {
	if !hasUnicodeControlPrefix(data) {
		return
	}
	suspicious := false
	for line := range bytes.Lines(data) {
		stack := []rune{}
		run := 0
		var previous rune
		for i, r := range string(line) {
			switch r {
			case '\u202a', '\u202b', '\u202d', '\u202e':
				stack = append(stack, '\u202c')
			case '\u2066', '\u2067', '\u2068':
				stack = append(stack, '\u2069')
			case '\u202c', '\u2069':
				if len(stack) == 0 || stack[len(stack)-1] != r {
					suspicious = true
				} else {
					stack = stack[:len(stack)-1]
				}
			}
			if variationSelector(r) {
				run++
				if run >= 8 {
					suspicious = true
				}
			} else {
				run = 0
			}
			if asciiJoiner(line, i, r, previous) {
				suspicious = true
			}
			previous = r
		}
		if len(stack) > 0 {
			suspicious = true
		}
	}
	if suspicious {
		s.addFinding(Finding{Check: "unicode-concealment", Severity: SevWarn, Path: path, Detail: "Unbalanced bidi controls, a long variation-selector run, or a joiner inside an ASCII identifier; review for source concealment"})
	}
}
func asciiIdentifier(r rune) bool {
	return r == '_' || r == '$' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
}

func (s *Scanner) inspectLoaderPatterns(path string, data, normalized []byte) {
	structural := bytes.Contains(normalized, []byte("import")) && inlineLoader.Match(normalized)
	if structural {
		s.addFinding(Finding{Check: "loader-structure", Severity: SevWarn, Path: path, Detail: "Immediate import.meta.url loader invokes a local CJS sidecar; legitimate loaders are possible, inspect the referenced module"})
	}
	content := string(normalized)
	decodedExecution := hasDecodeExecute(normalized, content)
	if hasCommunityMarker(normalized, content) && (structural || victimAssignment.Match(normalized) || decodedExecution) {
		s.addFinding(Finding{Check: "correlated-loader-markers", Severity: SevWarn, Path: path, Detail: "Community loader marker occurs alongside loader or decode/execute structure"})
	}
	if decodedExecution || suspiciousShellOrSpawn(normalized, content) {
		s.addFinding(Finding{Check: "suspicious-source-execution", Severity: SevWarn, Path: path, Detail: "Decode-and-execute, download-to-shell, or hidden detached spawn pattern; static review required, execution is not established"})
	}
	if bytes.Contains(data, []byte(`\u00`)) && escapedASCII.Match(data) && (strings.Contains(content, "eval(") || strings.Contains(content, "Function(") || structural) {
		s.addFinding(Finding{Check: "escaped-execution", Severity: SevWarn, Path: path, Detail: "Long ASCII escape run alongside dynamic execution or loader structure"})
	}
}

func hasCommunityMarker(data []byte, text string) bool {
	return buildMarker.Match(data) || strings.Contains(text, "__inzV") || strings.Contains(text, "app-vscode-eval")
}
func suspiciousShellOrSpawn(data []byte, text string) bool {
	return ((strings.Contains(text, "curl") || strings.Contains(text, "wget")) && downloadShell.Match(data)) || (strings.Contains(text, "spawn") && strings.Contains(text, "detached") && strings.Contains(text, "windowsHide") && hiddenSpawn.Match(data))
}
func variationSelector(r rune) bool {
	return (r >= 0xfe00 && r <= 0xfe0f) || (r >= 0xe0100 && r <= 0xe01ef)
}
func asciiJoiner(line []byte, i int, r, previous rune) bool {
	if r != '\u200c' && r != '\u200d' {
		return false
	}
	next, _ := utf8.DecodeRune(line[i+utf8.RuneLen(r):])
	return asciiIdentifier(previous) && asciiIdentifier(next)
}

func hasUnicodeControlPrefix(data []byte) bool {
	return bytes.IndexByte(data, 0xe2) >= 0 || bytes.IndexByte(data, 0xef) >= 0 || bytes.IndexByte(data, 0xf3) >= 0
}
func hasDecodeExecute(data []byte, text string) bool {
	return (strings.Contains(text, "eval") || strings.Contains(text, "Function")) && matchesDecodeExecute(data)
}
