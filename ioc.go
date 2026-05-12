package main

import (
	"os"
	"path/filepath"
)

// --- npm ---

// KnownPhantomPackages are npm packages that exist solely as malware carriers
// and have no legitimate use. Their presence in node_modules is always suspicious.
var KnownPhantomPackages = []string{
	"plain-crypto-js",
}

// KnownBadNpmVersions maps legitimate npm package names to known-compromised versions.
var KnownBadNpmVersions = map[string][]string{
	// axios (March 2026)
	// https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan
	"axios": {"1.14.1", "0.30.4"},

	// Mini Shai-Hulud self-spreading worm (May 2026)
	// https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem
	"@opensearch-project/opensearch": {"3.6.2"},

	// @uipath
	"@uipath/access-policy-sdk":                      {"0.3.1"},
	"@uipath/access-policy-tool":                     {"0.3.1"},
	"@uipath/admin-tool":                             {"0.1.1"},
	"@uipath/agent-sdk":                              {"1.0.2"},
	"@uipath/agent-tool":                             {"1.0.1"},
	"@uipath/agent.sdk":                              {"0.0.18"},
	"@uipath/aops-policy-tool":                       {"0.3.1"},
	"@uipath/ap-chat":                                {"1.5.7"},
	"@uipath/api-workflow-tool":                      {"1.0.1"},
	"@uipath/apollo-core":                            {"5.9.2"},
	"@uipath/apollo-react":                           {"4.24.5"},
	"@uipath/apollo-wind":                            {"2.16.2"},
	"@uipath/auth":                                   {"1.0.1"},
	"@uipath/case-tool":                              {"1.0.1"},
	"@uipath/cli":                                    {"1.0.1"},
	"@uipath/codedagent-tool":                        {"1.0.1"},
	"@uipath/codedagents-tool":                       {"0.1.12"},
	"@uipath/codedapp-tool":                          {"1.0.1"},
	"@uipath/common":                                 {"1.0.1"},
	"@uipath/context-grounding-tool":                 {"0.1.1"},
	"@uipath/data-fabric-tool":                       {"1.0.2"},
	"@uipath/docsai-tool":                            {"1.0.1"},
	"@uipath/filesystem":                             {"1.0.1"},
	"@uipath/flow-tool":                              {"1.0.2"},
	"@uipath/functions-tool":                         {"1.0.1"},
	"@uipath/gov-tool":                               {"0.3.1"},
	"@uipath/identity-tool":                          {"0.1.1"},
	"@uipath/insights-sdk":                           {"1.0.1"},
	"@uipath/insights-tool":                          {"1.0.1"},
	"@uipath/integrationservice-sdk":                 {"1.0.2"},
	"@uipath/integrationservice-tool":                {"1.0.2"},
	"@uipath/llmgw-tool":                             {"1.0.1"},
	"@uipath/maestro-sdk":                            {"1.0.1"},
	"@uipath/maestro-tool":                           {"1.0.1"},
	"@uipath/orchestrator-tool":                      {"1.0.1"},
	"@uipath/packager-tool-apiworkflow":              {"0.0.19"},
	"@uipath/packager-tool-bpmn":                     {"0.0.9"},
	"@uipath/packager-tool-case":                     {"0.0.9"},
	"@uipath/packager-tool-connector":                {"0.0.19"},
	"@uipath/packager-tool-flow":                     {"0.0.19"},
	"@uipath/packager-tool-functions":                {"0.1.1"},
	"@uipath/packager-tool-webapp":                   {"1.0.6"},
	"@uipath/packager-tool-workflowcompiler":         {"0.0.16"},
	"@uipath/packager-tool-workflowcompiler-browser": {"0.0.34"},
	"@uipath/platform-tool":                          {"1.0.1"},
	"@uipath/project-packager":                       {"1.1.16"},
	"@uipath/resource-tool":                          {"1.0.1"},
	"@uipath/resourcecatalog-tool":                   {"0.1.1"},
	"@uipath/resources-tool":                         {"0.1.11"},
	"@uipath/robot":                                  {"1.3.4"},
	"@uipath/rpa-legacy-tool":                        {"1.0.1"},
	"@uipath/rpa-tool":                               {"0.9.5"},
	"@uipath/solution-packager":                      {"0.0.35"},
	"@uipath/solution-tool":                          {"1.0.1"},
	"@uipath/solutionpackager-sdk":                   {"1.0.11"},
	"@uipath/solutionpackager-tool-core":             {"0.0.34"},
	"@uipath/tasks-tool":                             {"1.0.1"},
	"@uipath/telemetry":                              {"0.0.7"},
	"@uipath/test-manager-tool":                      {"1.0.2"},
	"@uipath/tool-workflowcompiler":                  {"0.0.12"},
	"@uipath/traces-tool":                            {"1.0.1"},
	"@uipath/ui-widgets-multi-file-upload":           {"1.0.1"},
	"@uipath/uipath-python-bridge":                   {"1.0.1"},
	"@uipath/vertical-solutions-tool":                {"1.0.1"},
	"@uipath/vss":                                    {"0.1.6"},
	"@uipath/widget.sdk":                             {"1.2.3"},

	// @tanstack
	"@tanstack/arktype-adapter":               {"1.166.12", "1.166.15"},
	"@tanstack/eslint-plugin-router":          {"1.161.9", "1.161.12"},
	"@tanstack/eslint-plugin-start":           {"0.0.4", "0.0.7"},
	"@tanstack/history":                       {"1.161.9", "1.161.12"},
	"@tanstack/nitro-v2-vite-plugin":          {"1.154.12", "1.154.15"},
	"@tanstack/react-router":                  {"1.169.5", "1.169.8"},
	"@tanstack/react-router-devtools":         {"1.166.16", "1.166.19"},
	"@tanstack/react-router-ssr-query":        {"1.166.15", "1.166.18"},
	"@tanstack/react-start":                   {"1.167.68", "1.167.71"},
	"@tanstack/react-start-client":            {"1.166.51", "1.166.54"},
	"@tanstack/react-start-rsc":               {"0.0.47", "0.0.50"},
	"@tanstack/react-start-server":            {"1.166.55", "1.166.58"},
	"@tanstack/router-cli":                    {"1.166.46", "1.166.49"},
	"@tanstack/router-core":                   {"1.169.5", "1.169.8"},
	"@tanstack/router-devtools":               {"1.166.16", "1.166.19"},
	"@tanstack/router-devtools-core":          {"1.167.6", "1.167.9"},
	"@tanstack/router-generator":              {"1.166.45", "1.166.48"},
	"@tanstack/router-plugin":                 {"1.167.38", "1.167.41"},
	"@tanstack/router-ssr-query-core":         {"1.168.3", "1.168.6"},
	"@tanstack/router-utils":                  {"1.161.11", "1.161.14"},
	"@tanstack/router-vite-plugin":            {"1.166.53", "1.166.56"},
	"@tanstack/solid-router":                  {"1.169.5", "1.169.8"},
	"@tanstack/solid-router-devtools":         {"1.166.16", "1.166.19"},
	"@tanstack/solid-router-ssr-query":        {"1.166.15", "1.166.18"},
	"@tanstack/solid-start":                   {"1.167.65", "1.167.68"},
	"@tanstack/solid-start-client":            {"1.166.50", "1.166.53"},
	"@tanstack/solid-start-server":            {"1.166.54", "1.166.57"},
	"@tanstack/start-client-core":             {"1.168.5", "1.168.8"},
	"@tanstack/start-fn-stubs":                {"1.161.9", "1.161.12"},
	"@tanstack/start-plugin-core":             {"1.169.23", "1.169.26"},
	"@tanstack/start-server-core":             {"1.167.33", "1.167.36"},
	"@tanstack/start-static-server-functions": {"1.166.44", "1.166.47"},
	"@tanstack/start-storage-context":         {"1.166.38", "1.166.41"},
	"@tanstack/valibot-adapter":               {"1.166.12", "1.166.15"},
	"@tanstack/virtual-file-routes":           {"1.161.10", "1.161.13"},
	"@tanstack/vue-router":                    {"1.169.5", "1.169.8"},
	"@tanstack/vue-router-devtools":           {"1.166.16", "1.166.19"},
	"@tanstack/vue-router-ssr-query":          {"1.166.15", "1.166.18"},
	"@tanstack/vue-start":                     {"1.167.61", "1.167.64"},
	"@tanstack/vue-start-client":              {"1.166.46", "1.166.49"},
	"@tanstack/vue-start-server":              {"1.166.50", "1.166.53"},
	"@tanstack/zod-adapter":                   {"1.166.12", "1.166.15"},

	// @draftauth / @draftlab
	"@draftauth/client":     {"0.2.1", "0.2.2"},
	"@draftauth/core":       {"0.13.1", "0.13.2"},
	"@draftlab/auth":        {"0.24.1", "0.24.2"},
	"@draftlab/auth-router": {"0.5.1", "0.5.2"},
	"@draftlab/db":          {"0.16.1", "0.16.2"},

	// @taskflow-corp
	"@taskflow-corp/cli": {"0.1.24", "0.1.25", "0.1.26", "0.1.27", "0.1.28", "0.1.29"},

	// @tolka
	"@tolka/cli": {"1.0.2", "1.0.3", "1.0.4", "1.0.6"},

	// @supersurkhet
	"@supersurkhet/cli": {"0.0.2", "0.0.3", "0.0.4", "0.0.5", "0.0.6", "0.0.7"},
	"@supersurkhet/sdk": {"0.0.2", "0.0.3", "0.0.4", "0.0.5", "0.0.6", "0.0.7"},

	// @beproduct
	"@beproduct/nestjs-auth": {"0.1.2", "0.1.3", "0.1.4", "0.1.5", "0.1.6", "0.1.7", "0.1.8", "0.1.9", "0.1.10", "0.1.11", "0.1.12", "0.1.13", "0.1.14", "0.1.15", "0.1.16", "0.1.17", "0.1.19"},

	// @dirigible-ai
	"@dirigible-ai/sdk": {"0.6.2", "0.6.3"},

	// @ml-toolkit-ts
	"@ml-toolkit-ts/preprocessing": {"1.0.2", "1.0.3"},
	"@ml-toolkit-ts/xgboost":       {"1.0.3", "1.0.4"},
	"ml-toolkit-ts":                {"1.0.4", "1.0.5"},

	// @squawk
	"@squawk/airport-data":       {"0.7.4", "0.7.5", "0.7.7"},
	"@squawk/airports":           {"0.6.2", "0.6.3", "0.6.5"},
	"@squawk/airspace":           {"0.8.1", "0.8.2", "0.8.4"},
	"@squawk/airspace-data":      {"0.5.3", "0.5.4", "0.5.6"},
	"@squawk/airway-data":        {"0.5.4", "0.5.5", "0.5.7"},
	"@squawk/airways":            {"0.4.2", "0.4.3", "0.4.5"},
	"@squawk/fix-data":           {"0.6.4", "0.6.5", "0.6.7"},
	"@squawk/fixes":              {"0.3.2", "0.3.3", "0.3.5"},
	"@squawk/flight-math":        {"0.5.4", "0.5.5", "0.5.7"},
	"@squawk/flightplan":         {"0.5.2", "0.5.3", "0.5.5"},
	"@squawk/geo":                {"0.4.4", "0.4.5", "0.4.7"},
	"@squawk/icao-registry":      {"0.5.2", "0.5.3", "0.5.5"},
	"@squawk/icao-registry-data": {"0.8.4", "0.8.5", "0.8.7"},
	"@squawk/mcp":                {"0.9.1", "0.9.2", "0.9.4"},
	"@squawk/navaid-data":        {"0.6.4", "0.6.5", "0.6.7"},
	"@squawk/navaids":            {"0.4.2", "0.4.3", "0.4.5"},
	"@squawk/notams":             {"0.3.6", "0.3.7", "0.3.9"},
	"@squawk/procedure-data":     {"0.7.3", "0.7.4", "0.7.6"},
	"@squawk/procedures":         {"0.5.2", "0.5.3", "0.5.5"},
	"@squawk/types":              {"0.8.1", "0.8.2", "0.8.4"},
	"@squawk/units":              {"0.4.3", "0.4.4", "0.4.6"},
	"@squawk/weather":            {"0.5.6", "0.5.7", "0.5.9"},

	// @tallyui
	"@tallyui/components":            {"1.0.1", "1.0.2", "1.0.3"},
	"@tallyui/connector-medusa":      {"1.0.1", "1.0.2", "1.0.3"},
	"@tallyui/connector-shopify":     {"1.0.1", "1.0.2", "1.0.3"},
	"@tallyui/connector-vendure":     {"1.0.1", "1.0.2", "1.0.3"},
	"@tallyui/connector-woocommerce": {"1.0.1", "1.0.2", "1.0.3"},
	"@tallyui/core":                  {"0.2.1", "0.2.2", "0.2.3"},
	"@tallyui/database":              {"1.0.1", "1.0.2", "1.0.3"},
	"@tallyui/pos":                   {"0.1.1", "0.1.2", "0.1.3"},
	"@tallyui/storage-sqlite":        {"0.2.1", "0.2.2", "0.2.3"},
	"@tallyui/theme":                 {"0.2.1", "0.2.2", "0.2.3"},

	// @mesadev
	"@mesadev/rest":    {"0.28.3"},
	"@mesadev/saguaro": {"0.4.22"},
	"@mesadev/sdk":     {"0.28.3"},

	// @mistralai
	"@mistralai/mistralai":       {"2.2.3", "2.2.4"},
	"@mistralai/mistralai-azure": {"1.7.2", "1.7.3"},
	"@mistralai/mistralai-gcp":   {"1.7.2", "1.7.3"},

	// unscoped
	"agentwork-cli":       {"0.1.4", "0.1.5"},
	"cmux-agent-mcp":      {"0.1.3", "0.1.4", "0.1.5", "0.1.6", "0.1.7", "0.1.8"},
	"cross-stitch":        {"1.1.3", "1.1.4", "1.1.6"},
	"git-branch-selector": {"1.3.3", "1.3.4", "1.3.5", "1.3.7"},
	"git-git-git":         {"1.0.8", "1.0.9", "1.0.10", "1.0.12"},
	"nextmove-mcp":        {"0.1.3", "0.1.4", "0.1.5", "0.1.7"},
	"safe-action":         {"0.8.3", "0.8.4"},
	"ts-dna":              {"3.0.1", "3.0.2", "3.0.4"},
	"wot-api":             {"0.8.1", "0.8.2", "0.8.4"},
}

// --- Python/PyPI ---

// KnownBadPythonVersions maps legitimate PyPI package names to known-compromised versions.
// Package names are normalized (lowercase, hyphens) to match dist-info directory conventions.
var KnownBadPythonVersions = map[string][]string{
	"litellm": {"1.82.7", "1.82.8"},
}

// KnownMaliciousPthFiles are .pth filenames that are known malware delivery mechanisms.
var KnownMaliciousPthFiles = []string{
	"litellm_init.pth",
}

// --- Network IOCs ---

// KnownC2Domains are command-and-control domains from documented supply chain attacks.
// Each entry is sourced from a specific incident writeup.
var KnownC2Domains = []string{
	"sfrclak.com",           // axios — primary C2 domain (port 8000)
	"models.litellm.cloud",  // litellm — credential exfiltration endpoint
	"checkmarx.zone",        // litellm — C2 polling endpoint (/raw)
	"api.masscan.cloud",     // mini-shai-hulud — direct C2 POST exfiltration
	"git-tanstack.com",      // mini-shai-hulud — marker/staging domain
	"filev2.getsession.org", // mini-shai-hulud — Session Protocol CDN abused for exfil
	"seed1.getsession.org",  // mini-shai-hulud — Session seed used for TLS pinning
}

// KnownC2IPs are command-and-control IP addresses from documented supply chain attacks.
var KnownC2IPs = []string{
	"142.11.206.73", // axios
}

// --- Filesystem artifacts ---

// ArtifactsDarwin are known malicious file paths on macOS (relative to home or absolute).
var ArtifactsDarwin = []ArtifactCheck{
	{Path: "/Library/Caches/com.apple.act.mond", Absolute: true, Desc: "axios RAT payload (macOS)", Attack: "axios 1.14.1/0.30.4"},
	{Path: "/tmp/6202033", Absolute: true, Desc: "axios AppleScript dropper (macOS)", Attack: "axios 1.14.1/0.30.4"},
	{Path: "Library/LaunchAgents/com.user.gh-token-monitor.plist", Absolute: false, Desc: "mini-shai-hulud LaunchAgent persistence", Attack: "mini-shai-hulud (May 2026)"},
}

// ArtifactsWindows returns known malicious file paths on Windows.
// Computed at runtime because ProgramData requires resolving %SystemDrive%.
func ArtifactsWindows() []ArtifactCheck {
	programData := os.Getenv("PROGRAMDATA")
	if programData == "" {
		drive := os.Getenv("SystemDrive")
		if drive == "" {
			drive = "C:"
		}
		programData = filepath.Join(drive, "ProgramData")
	}
	return []ArtifactCheck{
		{Path: filepath.Join(programData, `wt.exe`), Absolute: true, Desc: "PowerShell masquerading as Windows Terminal", Attack: "axios 1.14.1/0.30.4"},
	}
}

// ArtifactsLinux are known malicious file paths on Linux.
var ArtifactsLinux = []ArtifactCheck{
	{Path: "/tmp/ld.py", Absolute: true, Desc: "axios Python RAT payload (Linux)", Attack: "axios 1.14.1/0.30.4"},
	{Path: ".config/systemd/user/gh-token-monitor.service", Absolute: false, Desc: "mini-shai-hulud systemd persistence unit", Attack: "mini-shai-hulud (May 2026)"},
}

// ArtifactsCrossPlatform are checked on all platforms (paths relative to home dir).
var ArtifactsCrossPlatform = []ArtifactCheck{
	// litellm C2 backdoor and persistence
	{Path: ".config/sysmon/sysmon.py", Absolute: false, Desc: "litellm C2 backdoor script", Attack: "litellm 1.82.7/1.82.8"},
	{Path: ".config/systemd/user/sysmon.service", Absolute: false, Desc: "litellm systemd persistence unit", Attack: "litellm 1.82.7/1.82.8"},
	// mini-shai-hulud token-monitor persistence script
	{Path: ".local/bin/gh-token-monitor.sh", Absolute: false, Desc: "mini-shai-hulud token-monitor persistence script", Attack: "mini-shai-hulud (May 2026)"},
}

// ArtifactsTmp are checked in temp directories on all platforms.
var ArtifactsTmp = []struct {
	Glob string
	Desc string
}{
	// axios
	{"*.vbs", "axios VBScript dropper (Windows, %TEMP%\\{campaignID}.vbs)"},
	{"*.ps1", "axios PowerShell payload (Windows, %TEMP%\\{campaignID}.ps1)"},
	// litellm
	{".pg_state", "litellm C2 state tracking file"},
	{"pglog", "litellm downloaded payload staging"},
	{"tpcp.tar.gz", "litellm credential exfiltration archive"},
}
