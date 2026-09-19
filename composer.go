package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
)

// composerInstalledPackage is one entry from a Composer vendor/composer/installed.json.
type composerInstalledPackage struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Autoload struct {
		Files []string `json:"files"`
	} `json:"autoload"`
}

// composerInstalledV2 matches the Composer 2.x installed.json envelope.
// 1.x installed.json is a flat top-level array.
type composerInstalledV2 struct {
	Packages []composerInstalledPackage `json:"packages"`
}

// checkComposerVendor inspects a project's vendor/ directory by reading its
// vendor/composer/installed.json manifest and comparing each installed package
// against KnownBadComposerVersions. Supports both Composer 1.x (flat array)
// and 2.x ({packages: [...]}) installed.json formats.
func (s *Scanner) checkComposerVendor(vendorDir string) {
	installedJSON := filepath.Join(vendorDir, "composer", "installed.json")
	if s.processFile(installedJSON, ReadTimeout, func(local *Scanner, data []byte) { local.inspectComposer(installedJSON, data) }) != nil {
		s.stats.FilesChecked++
	}
}
func (s *Scanner) inspectComposer(installedJSON string, data []byte) {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		s.scanError(installedJSON, fmt.Errorf("invalid Composer manifest: expected array or object"))
		return
	}
	var packages []composerInstalledPackage
	var v2 composerInstalledV2
	if err := json.Unmarshal(data, &v2); err == nil && v2.Packages != nil {
		packages = v2.Packages
	} else if err := json.Unmarshal(data, &packages); err != nil {
		s.scanError(installedJSON, fmt.Errorf("invalid Composer manifest: %w", err))
		return
	}

	for _, p := range packages {
		s.stats.ComposerPackagesScanned++
		if s.Deep && !strings.Contains(p.Name, "..") && !filepath.IsAbs(p.Name) {
			dir := filepath.Join(filepath.Dir(filepath.Dir(installedJSON)), filepath.FromSlash(p.Name))
			for _, file := range p.Autoload.Files {
				s.inspectDependencyTarget(dir, file)
			}
		}
		bad, ok := KnownBadComposerVersions[p.Name]
		if !ok {
			continue
		}
		got := strings.TrimPrefix(p.Version, "v")
		for _, badVer := range bad {
			if got == strings.TrimPrefix(badVer, "v") {
				s.addFinding(Finding{
					Check:    "compromised-composer-version",
					Severity: SevCritical,
					Path:     installedJSON,
					Detail:   fmt.Sprintf("Known compromised version %s==%s", p.Name, p.Version),
				})
				break
			}
		}
	}
}
