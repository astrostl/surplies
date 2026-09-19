package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Inspect execution entrypoints, not type exports, wildcard export trees, or
// transitive imports. Candidate selection is driven by the installed manifest.
func (s *Scanner) inspectPackageEntrypoints(dir string, pkg *packageJSON) {
	targets := map[string]bool{}
	add := func(value string) {
		if value != "" {
			targets[value] = true
		}
	}
	var main, module string
	_ = json.Unmarshal(pkg.Main, &main)
	_ = json.Unmarshal(pkg.Module, &module)
	if main != "" {
		add(main)
	} else {
		add("index.js")
	}
	add(module)
	var bin any
	if json.Unmarshal(pkg.Bin, &bin) == nil {
		switch b := bin.(type) {
		case string:
			add(b)
		case map[string]any:
			for _, v := range b {
				if p, ok := v.(string); ok {
					add(p)
				}
			}
		}
	}
	packageRootExports(pkg.Exports, add)
	names := make([]string, 0, len(targets))
	for p := range targets {
		names = append(names, p)
	}
	sort.Strings(names)
	for _, p := range names {
		s.inspectDependencyTarget(dir, p)
	}
}
func (s *Scanner) inspectDependencyTarget(dir, target string) {
	if strings.ContainsAny(target, "*\x00") || filepath.IsAbs(target) {
		return
	}
	path := filepath.Join(dir, filepath.FromSlash(target))
	rel, err := filepath.Rel(dir, path)
	if !insideDependencyPath(rel, err) {
		return
	}
	// Node main may omit the extension or name a directory. Do not execute its resolver.
	candidates := []string{path}
	if filepath.Ext(path) == "" {
		candidates = append(candidates, path+".js", path+".cjs", filepath.Join(path, "index.js"))
	}
	for _, candidate := range candidates {
		info, err := os.Stat(candidate)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			s.scanError(candidate, err)
			return
		}
		if !info.Mode().IsRegular() {
			continue
		}
		if s.scriptChecked == nil {
			s.scriptChecked = make(map[string]bool)
		}
		if s.scriptChecked[candidate] || s.persistenceChecked[candidate] {
			return
		}
		s.scriptChecked[candidate] = true
		s.log("checking dependency entrypoint: %s", candidate)
		s.debug.event("selected-dependency-entrypoint", candidate, 0, 0)
		if s.processSourceFile(candidate, func(local *Scanner, data []byte) {
			if !local.checkRepoPayloadHash(candidate, filepath.Base(candidate), data) {
				local.checkDisguisedAsset(candidate, strings.ToLower(filepath.Ext(candidate)), data)
				local.inspectGeneralContent(candidate, data)
			}
		}) != nil {
			s.stats.FilesChecked++
		}
		return
	}
}

func (s *Scanner) inspectPythonEntrypoints(spDir, distDir string) {
	path := filepath.Join(spDir, distDir, "entry_points.txt")
	s.processFileMode(path, ReadTimeout, func(local *Scanner, data []byte) {
		section := ""
		for line := range strings.SplitSeq(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "[") {
				section = line
				continue
			}
			if section != "[console_scripts]" && section != "[gui_scripts]" {
				continue
			}
			_, value, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			module, _, _ := strings.Cut(strings.TrimSpace(value), ":")
			valid := validPythonModule(module)
			if !valid {
				continue
			}
			base := strings.ReplaceAll(module, ".", string(filepath.Separator))
			local.inspectDependencyTarget(spDir, base+".py")
			local.inspectDependencyTarget(spDir, filepath.Join(base, "__init__.py"))
		}
	}, true)
}

func packageRootExports(raw json.RawMessage, add func(string)) {
	var exports any
	if json.Unmarshal(raw, &exports) == nil {
		var root func(any)
		root = func(v any) {
			switch e := v.(type) {
			case string:
				add(e)
			case []any:
				for _, v := range e {
					root(v)
				}
			case map[string]any:
				if v, ok := e["."]; ok {
					root(v)
					return
				}
				for _, key := range []string{"default", "node", "import", "require", "browser", "development", "production"} {
					if v, ok := e[key]; ok {
						root(v)
					}
				}
			}
		}
		root(exports)
	}

}

func validPythonModule(module string) bool {
	valid := module != ""
	for part := range strings.SplitSeq(module, ".") {
		if part == "" {
			valid = false
		}
		for _, r := range part {
			if !(r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
				valid = false
			}
		}
	}

	return valid
}

func insideDependencyPath(rel string, err error) bool {
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
