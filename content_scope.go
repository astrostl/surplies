package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Discovery still walks ordinary directories for packages, source files and
// project roots. Only identified browser storage is pruned before enumeration.
func (s *Scanner) skipBrowserStorage(path string) bool {
	if s.BrowserCache || !s.browserStoragePath(path) {
		return false
	}
	s.noteContentScope(path)
	return true
}

func (s *Scanner) browserStoragePath(path string) bool {
	rel, err := filepath.Rel(s.HomeDir, path)
	if err != nil {
		return false
	}
	rel = filepath.ToSlash(rel)
	for _, root := range []string{
		"Library/Caches/Google/Chrome", "Library/Caches/Chromium", "Library/Caches/Microsoft Edge",
		"Library/Caches/Firefox", "Library/Caches/com.apple.Safari",
		"Library/Caches/BraveSoftware/Brave-Browser",
		".cache/google-chrome", ".cache/chromium", ".cache/microsoft-edge", ".cache/mozilla/firefox", ".cache/BraveSoftware/Brave-Browser",
	} {
		if rel == root || strings.HasPrefix(rel, root+"/") {
			return true
		}
	}
	// Chromium profile caches live beside executable extensions. Skip only the
	// cache subdirectories, preserving profile extension/package discovery.
	lower := strings.ToLower(rel)
	for _, root := range []string{
		"library/application support/google/chrome/", "library/application support/chromium/",
		"library/application support/microsoft edge/", "library/application support/bravesoftware/brave-browser/",
		".config/google-chrome/", ".config/chromium/", ".config/microsoft-edge/", ".config/bravesoftware/brave-browser/",
		"appdata/local/google/chrome/user data/", "appdata/local/chromium/user data/",
		"appdata/local/microsoft/edge/user data/", "appdata/local/bravesoftware/brave-browser/user data/",
	} {
		if after, ok := strings.CutPrefix(lower, root); ok {
			parts := strings.Split(after, "/")
			for _, part := range parts[:min(2, len(parts))] {
				if slices.Contains([]string{"cache", "code cache", "gpucache", "shadercache", "grshadercache"}, part) {
					return true
				}
			}
			break
		}
	}

	return false
}
func (s *Scanner) noteContentScope(path string) {
	s.log("skipping browser cache storage: %s (use -browser-cache to include)", path)
	s.addFinding(Finding{Check: "scan-limited", Severity: SevInfo, Path: path, Detail: "Browser cache storage excluded from traversal; use -browser-cache to include"})
}

// Classify from the directory entries already being read by the root walker;
// no per-file manifest stats or second directory enumeration are needed.
func (s *Scanner) classifyContentDir(path string, entries []os.DirEntry) {
	if s.contentDirs == nil {
		s.contentDirs = make(map[string]bool)
	}
	if s.dependencyDirs == nil {
		s.dependencyDirs = make(map[string]bool)
	}
	dependency := s.isDependencyDir(path, entries)
	s.dependencyDirs[path] = dependency
	parent := filepath.Dir(path)
	project := s.contentDirs[parent]
	// A manifest or dotfiles repository in home must not classify Documents,
	// Library, caches and every other child as application source. An explicit
	// -root home remains an intentional expansion of scope.
	if parent == filepath.Clean(s.HomeDir) && !s.explicitContentRoot(parent) {
		project = false
	}
	if slices.Contains([]string{"node_modules", "site-packages"}, filepath.Base(path)) {
		project = true
	}
	for _, e := range entries {
		if e.Name() == ".git" || (!e.IsDir() && slices.Contains([]string{"package.json", "pyproject.toml", "setup.py", "setup.cfg", "composer.json", "go.mod", "Cargo.toml", "Gemfile", "pom.xml", "build.gradle", "build.gradle.kts"}, e.Name())) {
			project = true
			break
		}
	}
	if s.explicitContentRoot(path) {
		project = true
	}
	s.contentDirs[path] = project
}
func (s *Scanner) routineContentFile(path, name string) bool {

	if targetedContentFile(path, name) {
		return true
	}
	dir := filepath.Dir(path)
	if s.dependencyDirs[dir] {
		// Metadata/lifecycle and declared entrypoints are read by their checks.
		// Unreferenced dependency source, type declarations, datasets and docs are not.
		return (filepath.Base(dir) == ".vscode" || filepath.Base(dir) == ".claude") && (name == "settings.json" || slices.Contains(injectableSourceNames, name))
	}
	if s.Broad || s.BrowserCache && s.browserStoragePath(path) || s.NpmCache && strings.Contains(filepath.ToSlash(path), "/_cacache/") {
		return true
	}
	return s.injectionContentFile(path, name)
}

func (s *Scanner) explicitContentRoot(path string) bool {
	for _, root := range s.ExtraRoots {
		abs, err := filepath.Abs(root)
		if err == nil && abs == path {
			return true
		}
	}
	return false
}

func (s *Scanner) isDependencyDir(path string, entries []os.DirEntry) bool {
	dependency := s.dependencyDirs[filepath.Dir(path)]
	base := filepath.Base(path)
	if base == "node_modules" || base == "site-packages" || strings.HasSuffix(base, ".app") || base == "archive-v0" && filepath.Base(filepath.Dir(path)) == "uv" {
		dependency = true
	}
	if base == "vendor" {
		for _, e := range entries {
			if e.IsDir() && e.Name() == "composer" {
				dependency = true
			}
		}
	}

	return dependency
}

func targetedContentFile(path, name string) bool {
	// Targeted entrypoints/metadata/name indicators are checked regardless of the
	// general-content policy; these methods also preserve lifecycle target reads.
	if name == "package.json" || name == ".gitignore" || startupPath(path) || extraToolchainPath(path) || persistenceEntrypointName(name) && discoveredPersistenceEntrypoint(path) {
		return true
	}
	if slices.ContainsFunc(KnownRepoArtifacts, func(a ProjectArtifact) bool { return a.Filename == name }) {
		return true
	}
	if slices.ContainsFunc(KnownRepoPayloadHashes, func(h RepoPayloadHash) bool { return h.Filename == name }) {
		return true
	}
	if strings.HasSuffix(name, ".inz.cjs") || strings.HasSuffix(name, ".inz.orig") {
		return true
	}
	return false
}

func (s *Scanner) injectionContentFile(path, name string) bool {
	dir := filepath.Dir(path)
	// A project marker is context, never permission to read every file below it.
	// These candidates correspond to the documented injected-source/font checks.
	ext := strings.ToLower(filepath.Ext(name))
	if slices.Contains(injectableSourceNames, name) {
		return true
	}
	if strings.Contains(name, ".config.") && isJSFamily(ext) {
		return true
	}
	if slices.Contains(fontExtensions, ext) && s.contentDirs[dir] {
		return true
	}
	if (filepath.Base(dir) == ".vscode" || filepath.Base(dir) == ".claude") && name == "settings.json" {
		return true
	}

	return false
}
