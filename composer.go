package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// composerInstalledPackage is one entry from a Composer vendor/composer/installed.json.
type composerInstalledPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
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
	data, err := os.ReadFile(installedJSON)
	if err != nil {
		return
	}

	var packages []composerInstalledPackage
	var v2 composerInstalledV2
	if err := json.Unmarshal(data, &v2); err == nil && v2.Packages != nil {
		packages = v2.Packages
	} else if err := json.Unmarshal(data, &packages); err != nil {
		return
	}

	for _, p := range packages {
		s.stats.ComposerPackagesScanned++
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
