package scan

import (
	"math/rand"
	"regexp"
	"strings"
	"testing"
)

func TestDecodeExecuteOptimizationEquivalent(t *testing.T) {
	old := regexp.MustCompile(`(?:eval|Function)\s*\(\s*(?:Buffer\s*\.\s*from|atob|unescape|decodeURIComponent)\s*\(`)
	rng := rand.New(rand.NewSource(7))
	tokens := []string{"eval", "Function", "Buffer", "from", "atob", "unescape", "decodeURIComponent", "(", ")", ".", " ", "\t", "\n", "x", "\\n"}
	cases := []string{"eval(atob(", "Function ( Buffer . from (", "prefixeval\n(\tdecodeURIComponent (", "Function(unescape(", "Function(Buffer.from)", "evaluation(atob("}
	for range 3000 {
		var s strings.Builder
		for range 30 {
			s.WriteString(tokens[rng.Intn(len(tokens))])
		}
		cases = append(cases, s.String())
	}
	for _, s := range cases {
		if got, want := matchesDecodeExecute([]byte(s)), old.MatchString(s); got != want {
			t.Fatalf("%q: got %v want %v", s, got, want)
		}
	}
}
