package scan

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
)

// IOCs in this file come from public incident analyses — primarily
// StepSecurity's writeups (https://www.stepsecurity.io/blog), with
// additional indicators from victim postmortems. Each block cites the
// specific source it was derived from. surplies is a mechanization layer
// on top of others' research — the original reverse engineering, payload
// extraction, and attribution work is theirs.

// --- npm ---

// KnownPhantomPackages are npm packages that exist solely as malware carriers
// and have no legitimate use. Their presence in node_modules is always suspicious.
var KnownPhantomPackages = []string{
	// axios (March 2026)
	// https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan
	"plain-crypto-js",

	// Mini Shai-Hulud — TanStack sub-incident (May 11, 2026). Fabricated
	// package pulled from a GitHub fork via an injected optionalDependencies
	// entry. Not a real published @tanstack package. Distinctive initial-
	// access vector (pwn-request → Actions cache poisoning → OIDC token
	// theft) but same Mini Shai-Hulud campaign per Socket/StepSecurity/Wiz/
	// Snyk attribution; payload (router_init.js) and exfil network
	// (filev2/seed{1,2,3}.getsession.org) match the broader campaign.
	// https://tanstack.com/blog/npm-supply-chain-compromise-postmortem
	// https://socket.dev/blog/tanstack-npm-packages-compromised-mini-shai-hulud-supply-chain-attack
	"@tanstack/setup",

	// Mini Shai-Hulud — @antv/AntV wave (May 19, 2026). Same fabricated-
	// phantom pattern as @tanstack/setup, this time pulled from
	// `github:antvis/G2#<orphan-commit-sha>` via an injected
	// optionalDependencies entry. Not a real published @antv package;
	// exists solely to load the 498 KB Bun bundle (index.js, SHA-256
	// a68dd1e6a6e35ec3771e1f94fe796f55dfe65a2b94560516ff4ac189390dfa1c)
	// that drops the kitty-monitor persistence and beacons to
	// t.m-kosche.com. Three imposter orphan commits in antvis/G2
	// (1916faa3…, 7cb42f57…, dc3d62a2…) backed the dependency reference.
	// https://safedep.io/mini-shai-hulud-strikes-again-314-npm-packages-compromised/
	"@antv/setup",

	// TrapDoor crypto stealer (May 2026). Distinct from Shai-Hulud /
	// Mini Shai-Hulud — different actor (GitHub account `ddjidd564`),
	// different campaign marker (`P-2024-001`), different toolkit. All 21
	// npm packages below are purpose-built phantoms impersonating crypto /
	// DeFi / AI tooling, with no legitimate version. Each drops
	// trap-core.js (48,485 bytes, XOR key `cargo-build-helper-2026`) via
	// postinstall; the payload writes `.cursorrules` and `CLAUDE.md` into
	// the project directory for AI-assistant-driven persistence and pulls
	// runtime config from `ddjidd564.github.io/defi-security-best-practices/`.
	// Same campaign also published 7 PyPI and 6 Crates.io phantoms;
	// surplies tracks the npm and PyPI ones (Crates.io has no scanner).
	// https://socket.dev/blog/trapdoor-crypto-stealer-npm-pypi-crates
	"async-pipeline-builder",
	"build-scripts-utils",
	"chain-key-validator",
	"crypto-credential-scanner",
	"defi-env-auditor",
	"defi-threat-scanner",
	"deployment-key-auditor",
	"dev-env-bootstrapper",
	"eth-wallet-sentinel",
	"llm-context-compressor",
	"mnemonic-safety-check",
	"model-switch-router",
	"node-setup-helpers",
	"project-init-tools",
	"prompt-engineering-toolkit",
	"solidity-deploy-guard",
	"token-usage-tracker",
	"wallet-backup-verifier",
	"wallet-security-checker",
	"web3-secrets-detector",
	"workspace-config-loader",

	// PolinRider (DPRK / Contagious Interview cluster). Attacker-published
	// typosquats impersonating Tailwind / PostCSS plugins, used as the
	// direct-install vector alongside the repo-poisoning worm. Published by
	// the now-deleted npm accounts `allavin` and `blackedward`; installing one
	// injects the PolinRider JS loader into the project's build configs. npm
	// has scrubbed some of these, but victim repos still carry the dependency
	// reference and the injected payload. Only the packages OSM's dossier
	// names as attacker-published are listed as phantoms — compromised
	// legitimate packages from the same campaign are version-pinned in
	// KnownBadNpmVersions instead.
	// https://github.com/OpenSourceMalware/PolinRider
	"tailwind-animationbased",
	"tailwind-autoanimation",
	"tailwind-mainanimation",
	"tailwindcss-animate-style",
	"tailwindcss-style-animate",
	"tailwindcss-style-modify",
	"tailwindcss-typography-style",
}

// KnownBadNpmVersions maps legitimate npm package names to known-compromised versions.
var KnownBadNpmVersions = map[string][]string{
	// axios (March 2026)
	// https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan
	"axios": {"1.14.1", "0.30.4"},

	// Mini Shai-Hulud self-spreading worm (May 2026)
	// https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem
	// Broader package list tracked at:
	// https://socket.dev/supply-chain-attacks/mini-shai-hulud
	"@opensearch-project/opensearch": {"3.5.3", "3.6.2", "3.7.0", "3.8.0"},

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

	// Mini Shai-Hulud — TanStack sub-incident (May 11, 2026)
	// https://tanstack.com/blog/npm-supply-chain-compromise-postmortem
	// https://socket.dev/blog/tanstack-npm-packages-compromised-mini-shai-hulud-supply-chain-attack
	// 84 malicious versions across 42 @tanstack packages, published via
	// an OIDC token extracted from runner memory after a fork PR poisoned a
	// pnpm cache. Distinct initial-access vector from the rest of the
	// Mini Shai-Hulud campaign (pwn-request → Actions cache poisoning →
	// OIDC token theft, vs. compromised maintainer tokens and double-tap
	// publishing) but same actor (TeamPCP), payload family, and exfil
	// infrastructure per Socket / StepSecurity / Wiz / Snyk.
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
	"@tolka/cli": {"1.0.2", "1.0.3", "1.0.4", "1.0.5", "1.0.6"},

	// @supersurkhet
	"@supersurkhet/cli": {"0.0.2", "0.0.3", "0.0.4", "0.0.5", "0.0.6", "0.0.7"},
	"@supersurkhet/sdk": {"0.0.2", "0.0.3", "0.0.4", "0.0.5", "0.0.6", "0.0.7"},

	// @beproduct
	"@beproduct/nestjs-auth": {"0.1.2", "0.1.3", "0.1.4", "0.1.5", "0.1.6", "0.1.7", "0.1.8", "0.1.9", "0.1.10", "0.1.11", "0.1.12", "0.1.13", "0.1.14", "0.1.15", "0.1.16", "0.1.17", "0.1.18", "0.1.19"},

	// @cap-js
	"@cap-js/db-service": {"2.10.1"},
	"@cap-js/postgres":   {"2.2.2"},
	"@cap-js/sqlite":     {"2.2.2"},

	// @dirigible-ai
	"@dirigible-ai/sdk": {"0.6.2", "0.6.3"},

	// @ml-toolkit-ts
	"@ml-toolkit-ts/preprocessing": {"1.0.2", "1.0.3"},
	"@ml-toolkit-ts/xgboost":       {"1.0.3", "1.0.4"},
	"ml-toolkit-ts":                {"1.0.4", "1.0.5"},

	// @squawk
	"@squawk/airport-data":       {"0.7.4", "0.7.5", "0.7.6", "0.7.7", "0.7.8"},
	"@squawk/airports":           {"0.6.2", "0.6.3", "0.6.4", "0.6.5", "0.6.6"},
	"@squawk/airspace":           {"0.8.1", "0.8.2", "0.8.3", "0.8.4", "0.8.5"},
	"@squawk/airspace-data":      {"0.5.3", "0.5.4", "0.5.5", "0.5.6", "0.5.7"},
	"@squawk/airway-data":        {"0.5.4", "0.5.5", "0.5.6", "0.5.7", "0.5.8"},
	"@squawk/airways":            {"0.4.2", "0.4.3", "0.4.4", "0.4.5", "0.4.6"},
	"@squawk/fix-data":           {"0.6.4", "0.6.5", "0.6.6", "0.6.7", "0.6.8"},
	"@squawk/fixes":              {"0.3.2", "0.3.3", "0.3.4", "0.3.5", "0.3.6"},
	"@squawk/flight-math":        {"0.5.4", "0.5.5", "0.5.6", "0.5.7", "0.5.8"},
	"@squawk/flightplan":         {"0.5.2", "0.5.3", "0.5.4", "0.5.5", "0.5.6"},
	"@squawk/geo":                {"0.4.4", "0.4.5", "0.4.6", "0.4.7", "0.4.8"},
	"@squawk/icao-registry":      {"0.5.2", "0.5.3", "0.5.4", "0.5.5", "0.5.6"},
	"@squawk/icao-registry-data": {"0.8.4", "0.8.5", "0.8.6", "0.8.7", "0.8.8"},
	"@squawk/mcp":                {"0.9.1", "0.9.2", "0.9.3", "0.9.4", "0.9.5"},
	"@squawk/navaid-data":        {"0.6.4", "0.6.5", "0.6.6", "0.6.7", "0.6.8"},
	"@squawk/navaids":            {"0.4.2", "0.4.3", "0.4.4", "0.4.5", "0.4.6"},
	"@squawk/notams":             {"0.3.6", "0.3.7", "0.3.8", "0.3.9", "0.3.10"},
	"@squawk/procedure-data":     {"0.7.3", "0.7.4", "0.7.5", "0.7.6", "0.7.7"},
	"@squawk/procedures":         {"0.5.2", "0.5.3", "0.5.4", "0.5.5", "0.5.6"},
	"@squawk/types":              {"0.8.1", "0.8.2", "0.8.3", "0.8.4", "0.8.5"},
	"@squawk/units":              {"0.4.3", "0.4.4", "0.4.5", "0.4.6", "0.4.7"},
	"@squawk/weather":            {"0.5.6", "0.5.7", "0.5.8", "0.5.9", "0.5.10"},

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
	"@mistralai/mistralai":       {"2.2.2", "2.2.3", "2.2.4"},
	"@mistralai/mistralai-azure": {"1.7.1", "1.7.2", "1.7.3"},
	"@mistralai/mistralai-gcp":   {"1.7.1", "1.7.2", "1.7.3"},

	// unscoped
	"agentwork-cli":       {"0.1.4", "0.1.5"},
	"cmux-agent-mcp":      {"0.1.3", "0.1.4", "0.1.5", "0.1.6", "0.1.7", "0.1.8"},
	"cross-stitch":        {"1.1.3", "1.1.4", "1.1.5", "1.1.6", "1.1.7"},
	"git-branch-selector": {"1.3.3", "1.3.4", "1.3.5", "1.3.6", "1.3.7"},
	"git-git-git":         {"1.0.8", "1.0.9", "1.0.10", "1.0.11", "1.0.12"},
	"intercom-client":     {"7.0.4"},
	"mbt":                 {"1.2.48"},
	"nextmove-mcp":        {"0.1.3", "0.1.4", "0.1.5", "0.1.6", "0.1.7"},
	"safe-action":         {"0.8.3", "0.8.4"},
	"ts-dna":              {"3.0.1", "3.0.2", "3.0.3", "3.0.4", "3.0.5"},
	"wot-api":             {"0.8.1", "0.8.2", "0.8.3", "0.8.4"},

	// Mini Shai-Hulud — @antv/AntV wave (May 19, 2026). 317 packages
	// across @antv/* and @lint-md/* plus 35 unscoped AntV-ecosystem
	// packages, all published in a single "double-tap" wave. Compromised
	// versions carry a preinstall hook (`bun run index.js`) that loads a
	// 498 KB Bun bundle (SHA-256
	// a68dd1e6a6e35ec3771e1f94fe796f55dfe65a2b94560516ff4ac189390dfa1c).
	// Same Mini Shai-Hulud toolkit as the SAP and TanStack sub-incidents
	// per SafeDep (identical Bun runtime, hex obfuscation patterns, 100 KB
	// flush threshold, credential regex set, Dune-themed exfil repo
	// naming, `firedalazer` GitHub dead-drop trigger) but a new C2
	// endpoint (t.m-kosche.com, disguised as OpenTelemetry traces) and a
	// new kitty-monitor persistence variant (~/.local/share/kitty/cat.py
	// + kitty-monitor.{service,plist}). New phantom @antv/setup injected
	// via `github:antvis/G2#<commit-sha>` optionalDependencies.
	// https://safedep.io/mini-shai-hulud-strikes-again-314-npm-packages-compromised/

	// @antv (AntV visualization framework — 279 packages)
	"@antv/a8":                             {"0.1.1", "0.2.1"},
	"@antv/adjust":                         {"0.3.5", "0.4.5"},
	"@antv/algorithm":                      {"0.2.26", "0.3.26"},
	"@antv/async-hook":                     {"2.3.9", "2.4.9"},
	"@antv/attr":                           {"0.4.5", "0.5.5"},
	"@antv/ava":                            {"3.5.1", "3.6.1"},
	"@antv/ava-react":                      {"3.4.2", "3.5.2"},
	"@antv/awards":                         {"0.1.9", "0.2.9"},
	"@antv/calendar-heatmap":               {"1.2.2", "1.3.2"},
	"@antv/chart-linter":                   {"1.2.6", "1.3.6"},
	"@antv/chart-node-g6":                  {"0.1.4", "0.2.4"},
	"@antv/chart-visualization-skills":     {"0.2.3", "0.3.3"},
	"@antv/ckb":                            {"2.1.4", "2.2.4"},
	"@antv/color-schema":                   {"0.3.3", "0.4.3"},
	"@antv/color-util":                     {"2.1.6", "2.2.6"},
	"@antv/component":                      {"2.2.11", "2.3.11"},
	"@antv/coord":                          {"0.5.7", "0.6.7"},
	"@antv/d3-color":                       {"1.1.0", "1.2.0"},
	"@antv/d3-interpolate":                 {"1.1.3", "1.2.3"},
	"@antv/data-samples":                   {"1.1.1", "1.2.1"},
	"@antv/data-set":                       {"0.12.8", "0.13.8"},
	"@antv/data-wizard":                    {"2.1.4", "2.2.4"},
	"@antv/dipper-component":               {"0.1.4", "0.2.4"},
	"@antv/dipper-hooks":                   {"0.3.1", "0.4.1"},
	"@antv/dipper-map":                     {"1.1.10", "1.2.10"},
	"@antv/dom-util":                       {"2.1.4", "2.2.4"},
	"@antv/dumi-theme-antv":                {"0.10.4", "0.9.4"},
	"@antv/dw-analyzer":                    {"1.2.5", "1.3.5"},
	"@antv/dw-random":                      {"1.2.7", "1.3.7"},
	"@antv/dw-transform":                   {"1.2.7", "1.3.7"},
	"@antv/dw-util":                        {"1.2.4", "1.3.4"},
	"@antv/event-emitter":                  {"0.2.3", "0.3.3"},
	"@antv/expr":                           {"1.1.2", "1.2.2"},
	"@antv/f-charts":                       {"0.1.0", "0.2.0"},
	"@antv/f-engine":                       {"1.11.0", "1.12.0"},
	"@antv/f-lottie":                       {"1.11.0", "1.12.0"},
	"@antv/f-my":                           {"1.11.0", "1.12.0"},
	"@antv/f-react":                        {"1.11.0", "1.12.0"},
	"@antv/f-test-utils":                   {"1.1.9", "1.2.9"},
	"@antv/f-vue":                          {"1.11.0", "1.12.0"},
	"@antv/f-wx":                           {"1.11.0", "1.12.0"},
	"@antv/f2":                             {"5.15.0", "5.16.0"},
	"@antv/f2-algorithm":                   {"5.8.0", "5.9.0"},
	"@antv/f2-canvas":                      {"1.1.5", "1.2.5"},
	"@antv/f2-context":                     {"0.1.1", "0.2.1"},
	"@antv/f2-graphic":                     {"0.1.16", "0.2.16"},
	"@antv/f2-my":                          {"4.1.52", "4.2.52"},
	"@antv/f2-react":                       {"5.15.0", "5.16.0"},
	"@antv/f2-site":                        {"4.1.42", "4.2.42"},
	"@antv/f2-vue":                         {"4.1.33", "4.2.33"},
	"@antv/f2-wordcloud":                   {"5.15.0", "5.16.0"},
	"@antv/f2-wx":                          {"4.1.51", "4.2.51"},
	"@antv/f6":                             {"0.1.19", "0.2.19"},
	"@antv/f6-alipay":                      {"0.1.7", "0.2.7"},
	"@antv/f6-core":                        {"0.1.2", "0.2.2"},
	"@antv/f6-element":                     {"0.1.1", "0.2.1"},
	"@antv/f6-hammerjs":                    {"0.1.2", "0.2.2"},
	"@antv/f6-plugin":                      {"1.1.6", "1.2.6"},
	"@antv/f6-ui":                          {"1.1.3", "1.2.3"},
	"@antv/f6-wx":                          {"0.1.7", "0.2.7"},
	"@antv/g":                              {"6.4.1", "6.5.1"},
	"@antv/g-base":                         {"0.6.16", "0.7.16"},
	"@antv/g-camera-api":                   {"2.1.45", "2.2.45"},
	"@antv/g-canvas":                       {"2.3.0", "2.4.0"},
	"@antv/g-canvaskit":                    {"1.2.1", "1.3.1"},
	"@antv/g-compat":                       {"1.1.11", "1.2.11"},
	"@antv/g-components":                   {"2.1.42", "2.2.42"},
	"@antv/g-css-layout-api":               {"1.1.38", "1.2.38"},
	"@antv/g-css-typed-om-api":             {"1.1.38", "1.2.38"},
	"@antv/g-device-api":                   {"1.7.13", "1.8.13"},
	"@antv/g-dom-mutation-observer-api":    {"2.1.42", "2.2.42"},
	"@antv/g-gesture":                      {"3.1.42", "3.2.42"},
	"@antv/g-image-exporter":               {"1.1.42", "1.2.42"},
	"@antv/g-layout-blocklike":             {"1.8.49", "1.9.49"},
	"@antv/g-lite":                         {"2.8.0", "2.9.0"},
	"@antv/g-lottie-player":                {"1.2.1", "1.3.1"},
	"@antv/g-math":                         {"3.2.0", "3.3.0"},
	"@antv/g-mobile":                       {"1.2.5", "1.3.5"},
	"@antv/g-mobile-canvas":                {"1.2.1", "1.3.1"},
	"@antv/g-mobile-canvas-element":        {"1.1.42", "1.2.42"},
	"@antv/g-mobile-svg":                   {"1.2.1", "1.3.1"},
	"@antv/g-mobile-webgl":                 {"1.2.1", "1.3.1"},
	"@antv/g-pattern":                      {"2.1.42", "2.2.42"},
	"@antv/g-perf":                         {"1.1.0", "1.2.0"},
	"@antv/g-plugin-3d":                    {"2.2.1", "2.3.1"},
	"@antv/g-plugin-a11y":                  {"1.5.1", "1.6.1"},
	"@antv/g-plugin-annotation":            {"1.3.0", "1.4.0"},
	"@antv/g-plugin-box2d":                 {"2.2.1", "2.3.1"},
	"@antv/g-plugin-canvas-path-generator": {"2.2.26", "2.3.26"},
	"@antv/g-plugin-canvas-picker":         {"2.4.1", "2.5.1"},
	"@antv/g-plugin-canvas-renderer":       {"2.6.1", "2.7.1"},
	"@antv/g-plugin-canvaskit-renderer":    {"2.4.1", "2.5.1"},
	"@antv/g-plugin-control":               {"2.2.1", "2.3.1"},
	"@antv/g-plugin-css-select":            {"2.2.1", "2.3.1"},
	"@antv/g-plugin-device-renderer":       {"2.7.1", "2.8.1"},
	"@antv/g-plugin-dom-interaction":       {"2.2.31", "2.3.31"},
	"@antv/g-plugin-dragndrop":             {"2.2.1", "2.3.1"},
	"@antv/g-plugin-gesture":               {"2.2.1", "2.3.1"},
	"@antv/g-plugin-gpgpu":                 {"1.10.20", "1.11.20"},
	"@antv/g-plugin-html-renderer":         {"2.4.1", "2.5.1"},
	"@antv/g-plugin-image-loader":          {"2.4.1", "2.5.1"},
	"@antv/g-plugin-matterjs":              {"2.2.1", "2.3.1"},
	"@antv/g-plugin-mobile-interaction":    {"1.1.42", "1.2.42"},
	"@antv/g-plugin-physx":                 {"2.2.1", "2.3.1"},
	"@antv/g-plugin-rough-canvas-renderer": {"2.2.1", "2.3.1"},
	"@antv/g-plugin-rough-svg-renderer":    {"2.2.1", "2.3.1"},
	"@antv/g-plugin-svg-picker":            {"2.1.46", "2.2.46"},
	"@antv/g-plugin-svg-renderer":          {"2.5.1", "2.6.1"},
	"@antv/g-plugin-webgl-device":          {"1.10.17", "1.11.17"},
	"@antv/g-plugin-webgl-renderer":        {"1.1.26", "1.2.26"},
	"@antv/g-plugin-webgpu-device":         {"1.10.17", "1.11.17"},
	"@antv/g-plugin-yoga":                  {"2.4.1", "2.5.1"},
	"@antv/g-plugin-zdog-canvas-renderer":  {"2.2.1", "2.3.1"},
	"@antv/g-plugin-zdog-svg-renderer":     {"2.2.1", "2.3.1"},
	"@antv/g-shader-components":            {"2.1.0", "2.2.0"},
	"@antv/g-svg":                          {"2.2.1", "2.3.1"},
	"@antv/g-web-animations-api":           {"2.2.32", "2.3.32"},
	"@antv/g-web-components":               {"2.2.1", "2.3.1"},
	"@antv/g-webgl":                        {"2.2.1", "2.3.1"},
	"@antv/g-webgl-compute":                {"0.1.1", "0.2.1"},
	"@antv/g-webgpu":                       {"2.2.1", "2.3.1"},
	"@antv/g-webgpu-compiler":              {"0.8.2", "0.9.2"},
	"@antv/g-webgpu-core":                  {"0.8.2", "0.9.2"},
	"@antv/g-webgpu-engine":                {"0.8.2", "0.9.2"},
	"@antv/g-webgpu-raytracer":             {"0.6.1", "0.7.1"},
	"@antv/g-webgpu-unitchart":             {"0.6.1", "0.7.1"},
	"@antv/g2":                             {"5.5.8", "5.6.8"},
	"@antv/g2-brush":                       {"0.1.2", "0.2.2"},
	"@antv/g2-extension-3d":                {"0.3.0", "0.4.0"},
	"@antv/g2-extension-ava":               {"0.3.0", "0.4.0"},
	"@antv/g2-extension-plot":              {"0.3.2", "0.4.2"},
	"@antv/g2-plugin-slider":               {"2.2.1", "2.3.1"},
	"@antv/g2-ssr":                         {"0.3.0", "0.4.0"},
	"@antv/g2plot":                         {"2.5.35", "2.6.35"},
	"@antv/g2plot-schemas":                 {"1.3.2", "1.4.2"},
	"@antv/g6":                             {"5.2.1", "5.3.1"},
	"@antv/g6-alipay":                      {"0.1.1", "0.2.1"},
	"@antv/g6-cli":                         {"0.1.4", "0.2.4"},
	"@antv/g6-core":                        {"0.10.24", "0.9.24"},
	"@antv/g6-editor":                      {"1.3.0", "1.4.0"},
	"@antv/g6-element":                     {"0.10.25", "0.9.25"},
	"@antv/g6-extension-3d":                {"0.2.23", "0.3.23"},
	"@antv/g6-extension-react":             {"0.3.7", "0.4.7"},
	"@antv/g6-mobile":                      {"0.2.2", "0.3.2"},
	"@antv/g6-pc":                          {"0.10.25", "0.9.25"},
	"@antv/g6-plugin":                      {"0.10.25", "0.9.25"},
	"@antv/g6-plugin-map-view":             {"0.1.4", "0.2.4"},
	"@antv/g6-plugins":                     {"1.1.9", "1.2.9"},
	"@antv/g6-react-node":                  {"1.5.8", "1.6.8"},
	"@antv/g6-ssr":                         {"0.2.1", "0.3.1"},
	"@antv/g6-wx":                          {"0.1.1", "0.2.1"},
	"@antv/gatsby-theme":                   {"0.2.0", "0.3.0"},
	"@antv/geo-coord":                      {"1.1.8", "1.2.8"},
	"@antv/gi-assets-advance":              {"2.6.22", "2.7.22"},
	"@antv/gi-assets-algorithm":            {"2.4.19", "2.5.19"},
	"@antv/gi-assets-basic":                {"2.5.40", "2.6.40"},
	"@antv/gi-assets-galaxybase":           {"1.3.15", "1.4.15"},
	"@antv/gi-assets-graphscope":           {"2.2.15", "2.3.15"},
	"@antv/gi-assets-hugegraph":            {"1.2.15", "1.3.15"},
	"@antv/gi-assets-janusgraph":           {"1.2.15", "1.3.15"},
	"@antv/gi-assets-neo4j":                {"2.2.15", "2.3.15"},
	"@antv/gi-assets-scene":                {"2.3.21", "2.4.21"},
	"@antv/gi-assets-tugraph":              {"2.2.15", "2.3.15"},
	"@antv/gi-assets-tugraph-analytics":    {"0.3.15", "0.4.15"},
	"@antv/gi-assets-xlab":                 {"0.2.30", "0.3.30"},
	"@antv/gi-cli":                         {"1.3.11", "1.4.11"},
	"@antv/gi-common-components":           {"1.4.16", "1.5.16"},
	"@antv/gi-mock-data":                   {"1.1.5", "1.2.5"},
	"@antv/gi-public-data":                 {"1.1.1", "1.2.1"},
	"@antv/gi-sdk":                         {"3.1.0", "3.2.0"},
	"@antv/gi-sdk-app":                     {"1.3.10", "1.4.10"},
	"@antv/gi-theme-antd":                  {"0.7.11", "0.8.11"},
	"@antv/github-config-cli":              {"0.2.0", "0.3.0"},
	"@antv/gl-matrix":                      {"2.8.1", "2.9.1"},
	"@antv/gpt-vis":                        {"1.1.0", "1.2.0"},
	"@antv/gpt-vis-ssr":                    {"0.4.7", "0.5.7"},
	"@antv/graphin":                        {"3.1.5", "3.2.5"},
	"@antv/graphin-components":             {"2.5.1", "2.6.1"},
	"@antv/graphin-graphscope":             {"1.1.5", "1.2.5"},
	"@antv/graphin-icons":                  {"1.1.0", "1.2.0"},
	"@antv/graphlib":                       {"2.1.4", "2.2.4"},
	"@antv/hierarchy":                      {"0.8.1", "0.9.1"},
	"@antv/infographic":                    {"0.3.19", "0.4.19"},
	"@antv/insight-component":              {"1.1.0", "1.2.0"},
	"@antv/interaction":                    {"0.2.5", "0.3.5"},
	"@antv/istanbul":                       {"0.1.0", "0.2.0"},
	"@antv/knowledge":                      {"1.2.4", "1.3.4"},
	"@antv/l7":                             {"2.26.10", "2.27.10"},
	"@antv/l7-component":                   {"2.26.10", "2.27.10"},
	"@antv/l7-composite-layers":            {"0.18.1", "0.19.1"},
	"@antv/l7-core":                        {"2.26.10", "2.27.10"},
	"@antv/l7-district":                    {"2.4.12", "2.5.12"},
	"@antv/l7-draw":                        {"3.2.5", "3.3.5"},
	"@antv/l7-editor":                      {"1.2.13", "1.3.13"},
	"@antv/l7-extension-g-layer":           {"1.1.0", "1.2.0"},
	"@antv/l7-layers":                      {"2.26.10", "2.27.10"},
	"@antv/l7-leaflet":                     {"1.1.2", "1.2.2"},
	"@antv/l7-map":                         {"2.26.10", "2.27.10"},
	"@antv/l7-mapkit":                      {"0.6.0", "0.7.0"},
	"@antv/l7-maps":                        {"2.26.10", "2.27.10"},
	"@antv/l7-mini":                        {"2.21.8", "2.22.8"},
	"@antv/l7-pass":                        {"1.1.0", "1.2.0"},
	"@antv/l7-react":                       {"2.5.3", "2.6.3"},
	"@antv/l7-renderer":                    {"2.26.10", "2.27.10"},
	"@antv/l7-scene":                       {"2.26.10", "2.27.10"},
	"@antv/l7-source":                      {"2.26.10", "2.27.10"},
	"@antv/l7-three":                       {"2.26.10", "2.27.10"},
	"@antv/l7-utils":                       {"2.26.10", "2.27.10"},
	"@antv/l7plot":                         {"0.6.11", "0.7.11"},
	"@antv/l7plot-component":               {"0.1.11", "0.2.11"},
	"@antv/larkmap":                        {"1.6.1", "1.7.1"},
	"@antv/layout-gpu":                     {"1.2.7", "1.3.7"},
	"@antv/layout-wasm":                    {"1.5.2", "1.6.2"},
	"@antv/li-aiearth-assets":              {"0.5.7", "0.6.7"},
	"@antv/li-analysis-assets":             {"1.10.1", "1.11.1"},
	"@antv/li-core-assets":                 {"1.4.7", "1.5.7"},
	"@antv/li-editor":                      {"1.7.1", "1.8.1"},
	"@antv/li-p2":                          {"1.10.2", "1.9.2"},
	"@antv/li-sam-assets":                  {"0.2.4", "0.3.4"},
	"@antv/li-sdk":                         {"1.6.1", "1.7.1"},
	"@antv/lite-insight":                   {"2.2.1", "2.3.1"},
	"@antv/matrix-util":                    {"3.1.4", "3.2.4"},
	"@antv/mcp-server-antv":                {"0.2.8", "0.3.8"},
	"@antv/mcp-server-chart":               {"0.10.10", "0.11.10"},
	"@antv/my-f2":                          {"2.2.7", "2.3.7"},
	"@antv/my-f2-pc":                       {"0.2.1", "0.3.1"},
	"@antv/narrative-text-editor":          {"0.3.20", "0.4.20"},
	"@antv/narrative-text-schema":          {"0.4.7", "0.5.7"},
	"@antv/narrative-text-vis":             {"0.4.16", "0.5.16"},
	"@antv/path-util":                      {"3.1.1", "3.2.1"},
	"@antv/react-g":                        {"2.2.1", "2.3.1"},
	"@antv/s2":                             {"2.8.1", "2.9.1"},
	"@antv/s2-react":                       {"2.4.1", "2.5.1"},
	"@antv/s2-react-components":            {"2.2.2", "2.3.2"},
	"@antv/s2-ssr":                         {"0.2.1", "0.3.1"},
	"@antv/s2-vue":                         {"2.3.0", "2.4.0"},
	"@antv/sam":                            {"0.3.0", "0.4.0"},
	"@antv/scale":                          {"0.6.2", "0.7.2"},
	"@antv/semantic-release-pnpm":          {"1.1.4", "1.2.4"},
	"@antv/smart-color":                    {"0.3.1", "0.4.1"},
	"@antv/stat":                           {"0.1.2", "0.2.2"},
	"@antv/t8":                             {"0.4.0", "0.5.0"},
	"@antv/thumbnails":                     {"2.1.0", "2.2.0"},
	"@antv/thumbnails-component":           {"2.1.0", "2.2.0"},
	"@antv/torch":                          {"1.1.6", "1.2.6"},
	"@antv/translator":                     {"1.1.1", "1.2.1"},
	"@antv/util":                           {"3.4.11", "3.5.11"},
	"@antv/vendor":                         {"1.1.11", "1.2.11"},
	"@antv/vis-predict-engine":             {"0.2.1", "0.3.1"},
	"@antv/webgpu-graph":                   {"1.1.0", "1.2.0"},
	"@antv/word-scale-chart":               {"0.4.4", "0.5.4"},
	"@antv/wx-f2":                          {"2.2.1", "2.3.1"},
	"@antv/x6":                             {"3.2.7", "3.3.7"},
	"@antv/x6-angular-shape":               {"3.1.1", "3.2.1"},
	"@antv/x6-common":                      {"2.1.17", "2.2.17"},
	"@antv/x6-components":                  {"0.11.7", "0.12.7"},
	"@antv/x6-geometry":                    {"2.1.5", "2.2.5"},
	"@antv/x6-plugin-clipboard":            {"2.2.6", "2.3.6"},
	"@antv/x6-plugin-dnd":                  {"2.2.1", "2.3.1"},
	"@antv/x6-plugin-export":               {"2.2.6", "2.3.6"},
	"@antv/x6-plugin-history":              {"2.3.4", "2.4.4"},
	"@antv/x6-plugin-keyboard":             {"2.3.3", "2.4.3"},
	"@antv/x6-plugin-minimap":              {"2.1.7", "2.2.7"},
	"@antv/x6-plugin-scroller":             {"2.1.10", "2.2.10"},
	"@antv/x6-plugin-selection":            {"2.3.2", "2.4.2"},
	"@antv/x6-plugin-snapline":             {"2.2.7", "2.3.7"},
	"@antv/x6-plugin-stencil":              {"2.2.5", "2.3.5"},
	"@antv/x6-plugin-transform":            {"2.2.8", "2.3.8"},
	"@antv/x6-react":                       {"0.2.26", "0.3.26"},
	"@antv/x6-react-components":            {"2.1.9", "2.2.9"},
	"@antv/x6-react-shape":                 {"3.1.1", "3.2.1"},
	"@antv/x6-vector":                      {"1.5.2", "1.6.2"},
	"@antv/x6-vue-shape":                   {"3.1.2", "3.2.2"},
	"@antv/x6-vue3-shape":                  {"1.1.0", "1.2.0"},
	"@antv/xflow":                          {"2.2.13", "2.3.13"},
	"@antv/xflow-core":                     {"1.1.55", "1.2.55"},
	"@antv/xflow-diff":                     {"1.1.0", "1.2.0"},
	"@antv/xflow-extension":                {"1.1.55", "1.2.55"},
	"@antv/xflow-hook":                     {"1.1.55", "1.2.55"},

	// @lint-md
	"@lint-md/cli":    {"2.1.0", "2.2.0"},
	"@lint-md/core":   {"2.1.0", "2.2.0"},
	"@lint-md/parser": {"0.1.14", "0.2.14"},

	// unscoped (AntV-adjacent packages by the same maintainer)
	"ai-figure":              {"0.5.0", "0.6.0"},
	"amapcn":                 {"0.2.2", "0.3.2"},
	"ast-plugin":             {"0.1.7", "0.2.7"},
	"babel-plugin-version":   {"0.3.3", "0.4.3"},
	"boring-avatars-vanilla": {"1.1.2", "1.2.2"},
	"byte-parser":            {"1.1.0", "1.2.0"},
	"canvas-nest.js":         {"2.1.4", "2.2.4"},
	"echarts-for-react":      {"3.0.7", "3.1.7", "3.2.7"},
	"filesize.js":            {"2.1.0", "2.2.0"},
	"fixed-round":            {"1.1.2", "1.2.2"},
	"gantt-for-react":        {"0.3.0", "0.4.0"},
	"jest-canvas-mock":       {"2.5.3", "2.6.3", "2.7.3"},
	"jest-date-mock":         {"1.0.11", "1.1.11", "1.2.11"},
	"jest-electron":          {"0.2.12", "0.3.12"},
	"jest-expect":            {"0.1.1", "0.2.1"},
	"jest-less-loader":       {"0.3.0", "0.4.0"},
	"jest-random-mock":       {"1.1.0", "1.2.0"},
	"jest-url-loader":        {"0.2.0", "0.3.0"},
	"limit-size":             {"0.2.4", "0.3.4"},
	"lint-md":                {"0.3.0", "0.4.0"},
	"lint-md-cli":            {"0.2.2", "0.3.2"},
	"mcp-echarts":            {"0.8.1", "0.9.1"},
	"mcp-mermaid":            {"0.5.1", "0.6.1"},
	"miz":                    {"1.1.1", "1.2.1"},
	"onfire.js":              {"2.1.1", "2.2.1"},
	"react-adsense":          {"0.2.0", "0.3.0"},
	"relationship.js":        {"1.3.9", "1.4.9"},
	"ribbon.js":              {"1.1.2"},
	"size-sensor":            {"1.0.4", "1.1.4", "1.2.4"},
	"slice.js":               {"1.2.1", "1.3.1"},
	"timeago-react":          {"3.1.7", "3.2.7"},
	"timeago.js":             {"4.1.2", "4.2.2"},
	"uri-parse":              {"1.1.0", "1.2.0"},
	"word-width":             {"1.1.1", "1.2.1"},
	"xmorse":                 {"1.1.0", "1.2.0"},

	// Mini Shai-Hulud — Red Hat Cloud Services wave (June 1, 2026). 31
	// packages across the @redhat-cloud-services scope, published after an
	// attacker minted an npm token from a GitHub Actions OIDC credential
	// stolen from the RedHatInsights/javascript-clients repo. Same campaign
	// payload family: a preinstall hook (`node index.js`) stages an encrypted
	// Bun loader that harvests GitHub Actions secrets, npm tokens, cloud
	// (AWS/GCP/Azure) and Kubernetes/Vault credentials, SSH and Git
	// credentials, then exfiltrates over an encrypted channel with a GitHub
	// API fallback. The exfil abuses a legitimate endpoint (api.anthropic.com,
	// /v1/api) rather than actor-owned infrastructure, so no new C2 domain is
	// added. Compromised package/index.js SHA-256:
	// 21b6409a7b84446310daca5409ad6112ac60a1e4bef97736e53fff5f63bfdef4.
	// Full 31-package version list from StepSecurity; Mini Shai-Hulud
	// attribution, chrome@2.3.1 confirmation, and payload hashes from Socket.
	// https://www.stepsecurity.io/blog/multiple-redhat-cloud-services-npm-packages-compromised
	// https://socket.dev/blog/mini-shai-hulud-campaign-hits-red-hat-cloud-services-npm-packages
	"@redhat-cloud-services/chrome":                                 {"2.3.1"},
	"@redhat-cloud-services/compliance-client":                      {"4.0.3"},
	"@redhat-cloud-services/config-manager-client":                  {"5.0.4"},
	"@redhat-cloud-services/entitlements-client":                    {"4.0.11"},
	"@redhat-cloud-services/eslint-config-redhat-cloud-services":    {"3.2.1"},
	"@redhat-cloud-services/frontend-components":                    {"7.7.2"},
	"@redhat-cloud-services/frontend-components-advisor-components": {"3.8.2"},
	"@redhat-cloud-services/frontend-components-config":             {"6.11.3"},
	"@redhat-cloud-services/frontend-components-config-utilities":   {"4.11.2"},
	"@redhat-cloud-services/frontend-components-notifications":      {"6.9.2"},
	"@redhat-cloud-services/frontend-components-remediations":       {"4.9.2"},
	"@redhat-cloud-services/frontend-components-testing":            {"1.2.1"},
	"@redhat-cloud-services/frontend-components-translations":       {"4.4.1"},
	"@redhat-cloud-services/frontend-components-utilities":          {"7.4.1"},
	"@redhat-cloud-services/hcc-feo-mcp":                            {"0.3.1"},
	"@redhat-cloud-services/hcc-kessel-mcp":                         {"0.3.1"},
	"@redhat-cloud-services/hcc-pf-mcp":                             {"0.6.1"},
	"@redhat-cloud-services/host-inventory-client":                  {"5.0.3"},
	"@redhat-cloud-services/insights-client":                        {"4.0.4"},
	"@redhat-cloud-services/integrations-client":                    {"6.0.4"},
	"@redhat-cloud-services/javascript-clients-shared":              {"2.0.8"},
	"@redhat-cloud-services/notifications-client":                   {"6.1.4"},
	"@redhat-cloud-services/patch-client":                           {"4.0.4"},
	"@redhat-cloud-services/quickstarts-client":                     {"4.0.11"},
	"@redhat-cloud-services/rbac-client":                            {"9.0.3"},
	"@redhat-cloud-services/remediations-client":                    {"4.0.4"},
	"@redhat-cloud-services/rule-components":                        {"4.7.2"},
	"@redhat-cloud-services/sources-client":                         {"3.0.10"},
	"@redhat-cloud-services/topological-inventory-client":           {"3.0.10"},
	"@redhat-cloud-services/tsc-transform-imports":                  {"1.2.2"},
	"@redhat-cloud-services/types":                                  {"3.6.1"},

	// keyv npm compromise (August 4, 2026). Compromised release path for
	// maintainer jaredwray published 11 malicious releases across keyv,
	// cacheable-family packages, and ecto. Each tarball adds a preinstall
	// hook (`node setup.mjs`) plus two payload files (setup.mjs at 29,918
	// bytes; Math_Symbol.js at 727,680 bytes) that are byte-identical across
	// all affected releases. Snyk independently confirmed every package under
	// maintainer jaredwray; other packages under the @keyv scope were not
	// compromised. Three of the eleven releases (flat-cache@6.1.24,
	// cacheable-request@13.0.20, cache-manager@7.2.10) were later removed
	// from the registry, but lockfiles and private mirrors can retain them.
	// A second execution path injected .claude/ and .vscode/ hooks
	// (SessionStart / folderOpen) into the keyv repository. Second-stage
	// analysis (not independently re-executed by Snyk) reports credential
	// theft and gh-token-monitor persistence.
	// Payload hashes (identical across all nine tarballs available at analysis):
	//   setup.mjs     SHA-256 54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668
	//   Math_Symbol.js SHA-256 9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc
	// https://snyk.io/blog/inside-keyv-npm-compromise-preinstall-malware-trusted-provenance-ide-hooks/
	"keyv":                  {"6.0.0"},
	"@cacheable/net":        {"2.1.1"},
	"@cacheable/node-cache": {"3.1.2"},
	"cacheable":             {"2.5.1"},
	"flat-cache":            {"6.1.24"},
	"@cacheable/memory":     {"2.2.1"},
	"cacheable-request":     {"13.0.20"},
	"file-entry-cache":      {"11.1.6"},
	"@cacheable/utils":      {"2.5.1"},
	"cache-manager":         {"7.2.10"},
	"ecto":                  {"5.0.1"},

	// PolinRider (DPRK / Contagious Interview cluster). Compromised legitimate
	// packages — maintainers whose machines were infected and whose npm
	// publishing access the worm then reused. Distinct from the attacker-
	// published typosquats in KnownPhantomPackages above.
	//
	// npm's `0.0.1-security` placeholder versions are deliberately NOT listed:
	// that version is the clean stub npm publishes after a takedown, so
	// flagging it would report the remediation as the compromise.
	// https://socket.dev/supply-chain-attacks/polinrider
	"@bcryptln/becryptjs":               {"3.0.9", "3.0.10", "3.0.11"},
	"@im_ahsan/chatbot-widget":          {"0.0.77", "0.0.78", "0.0.79", "0.0.80", "0.0.81", "0.0.82"},
	"@joyfill/components":               {"4.0.0-rc24-2773-beta.4"},
	"@joyfill/layouts":                  {"0.1.2-2773.beta.0"},
	"@lambda-platform/lambda-vue":       {"3.3.24"},
	"@modhamanish/rn-mm-template":       {"1.1.3"},
	"@muhammadahsan100d/chatbot-widget": {"0.0.82", "0.0.83", "0.0.84", "0.0.85"},
	"@testrelic/appium-analytics":       {"1.1.1-next.88"},
	"@testrelic/playwright-analytics":   {"2.12.1-next.88", "2.13.0"},
	"@usemosaik/template-react-js":      {"1.0.0", "1.0.1"},
	"@uw010010/vite-tree":               {"3.4.2", "3.4.3", "3.6.1"},
	"@vite-ln/build-ts":                 {"5.15.10", "5.17.0"},
	"@vite-mcp/vite-type":               {"6.44.1"},
	"@vite-pro/vite-ui":                 {"2.5.10"},
	"@vite-tab/tab":                     {"3.15.10", "5.7.0"},
	"@vite-ts/vite-ui":                  {"6.44.1"},
	"@vitets/vite-ts":                   {"1.5.10"},
	"html-to-gutenberg":                 {"4.2.11", "4.2.19", "4.2.20", "4.2.21", "4.2.22"},
	"itsa-react-docviewer":              {"16.1.2"},
	"tailwind-animationbasis":           {"2.3.3"},
	"tailwind-container-queries":        {"0.1.1"},
	"tailwind-scrollbar-hider":          {"0.0.1", "5.0.1", "5.0.2"},
	"tailwind-scrollbar-styles":         {"4.0.3"},
	"tailwind-style-typography":         {"0.5.8"},
	"tailwind-stylecss-typography":      {"0.8.3"},
	"tailwind-typography-cssstyle":      {"0.8.3"},
	"tailwind-typography-style":         {"0.5.8"},
	"tailwind-typography-stylecss":      {"0.8.3"},
	"tailwindcss-animate-styles":        {"1.0.9"},
	"tailwindcss-contact-forms":         {"0.5.6"},
	"tailwindcss-fluid-styles":          {"2.0.7"},
	"tailwindcss-style-typography":      {"0.5.6", "0.5.8"},
	"tailwindthml-flips":                {"1.0.3", "1.0.4", "1.0.5"},
	"viteplugiin":                       {"1.0.28"},

	// @common-stack/generate-plugin — the campaign republished the malicious
	// loader across an entire alpha line rather than a single release.
	// https://socket.dev/supply-chain-attacks/polinrider
	"@common-stack/generate-plugin": {
		"9.0.2-alpha.21", "9.0.2-alpha.22", "9.0.2-alpha.23", "9.0.2-alpha.24",
		"9.0.4-alpha.0", "9.0.4-alpha.1",
		"9.0.5-alpha.0", "9.0.5-alpha.1", "9.0.5-alpha.2", "9.0.5-alpha.3",
		"9.0.5-alpha.4", "9.0.5-alpha.5",
		"9.0.6-alpha.0", "9.0.6-alpha.1",
		"10.0.1-alpha.0",
	},

	// PolinRider — fetch-page-assets. Socket's tracker carries 1.2.9 and
	// 1.2.10; OSM's case study documents 1.2.11 through 1.2.14 as still live
	// and unflagged on npm at publication, with 1.2.12 adding a
	// babel.config.cjs payload (marker A8-3292-1) and 1.2.13 refreshing it
	// (A8-3292-2). Only 1.2.9 was ever pulled (GHSA-vxq2-vhm7-7mhq), so the
	// registry's own advisory data under-reports this package by five
	// versions. Pin to <= 1.2.8.
	// https://opensourcemalware.com/blog/polinrider-npm-case-study-dprk-attack
	"fetch-page-assets": {"1.2.9", "1.2.10", "1.2.11", "1.2.12", "1.2.13", "1.2.14"},

	// PolinRider / NullReceiver — trojanized Tailwind-plugin impersonators
	// that resolve their C2 off the Ethereum chain (same publisher wallet
	// 0xa322E5f3D311D3080e6f0121063e9aDC2490Ef1a as the rest of the campaign).
	//
	// fluid-type-ui shipped the payload in TWO versions. OSM's writeup names
	// only 2.0.8, which is the version the analysis was done against; the OSV
	// record references both 2.0.8 and 2.0.9 as affected, so a 2.0.8-only pin
	// misses the later one — and "the fixed version" is a reasonable thing for
	// a victim to have upgraded into. Registry advisory data is the
	// authoritative source for the version RANGE even when a blog is the
	// authoritative source for the behavior.
	//   https://opensourcemalware.com/blog/nullreceiver-dprk-c2-technique
	//   https://osv.dev/vulnerability/MAL-2026-11136  (fluid-type-ui; GHSA-4w4v-pw3v-q85q)
	//   https://osv.dev/vulnerability/MAL-2026-11132  (bianira-ui)
	"bianira-ui":    {"1.27.0"},
	"fluid-type-ui": {"2.0.8", "2.0.9"},
}

// --- Composer/Packagist ---

// KnownBadComposerVersions maps Composer package names ("vendor/pkg") to
// known-compromised versions. Matching strips a leading "v" so "v5.0.2" and
// "5.0.2" both match either form — Composer/Packagist tags carry "v" by
// convention but installed.json normalization varies.
var KnownBadComposerVersions = map[string][]string{
	// Mini Shai-Hulud worm — Composer artifact tracked alongside the npm campaign
	// https://socket.dev/supply-chain-attacks/mini-shai-hulud
	"intercom/intercom-php": {"5.0.2"},

	// PolinRider (DPRK / Contagious Interview cluster). Packagist is hit
	// harder than npm here because the campaign propagates through maintainer
	// machines rather than the registry: the worm finds local git repos,
	// injects its loader into a JS config file, amends the last commit and
	// force-pushes. Packagist then picks the poisoned commit up on every
	// tracked branch, which is why most entries are `dev-*` branch refs
	// rather than tagged releases — the version string in installed.json is
	// literally `dev-main`, so exact matching works without normalization.
	//
	// `olc/olc-php dev-fix/remove-malware` is not a mistake: the branch a
	// maintainer opened to clean up was itself re-poisoned before Packagist
	// indexed it.
	// https://socket.dev/blog/polinrider-github-packagist
	// https://socket.dev/supply-chain-attacks/polinrider
	"adxio/twig-hmvc":                  {"dev-master"},
	"arsl/optima-class":                {"dev-auction-added"},
	"henrique-borba/php-sieve-manager": {"dev-master"},
	"imfaisii/twitter-api-v2-php":      {"dev-master"},
	"lambda-platform/moqup":            {"dev-master"},
	"mahbub/laravel-saas-kit":          {"dev-main"},
	"mahbubur508/api-auth":             {"dev-main"},
	"olc/olc-php":                      {"dev-fix/remove-malware"},
	"thiio/kubernetes-php-sdk":         {"dev-main"},
	"visanduma/laravel-auth-switch":    {"dev-main"},
	"visanduma/laravel-hrm":            {"dev-main"},
	"visanduma/laravel-invoice":        {"dev-main"},
	"visanduma/nova-back-navigation":   {"dev-master"},
	"visanduma/nova-two-factor":        {"dev-main", "dev-nova4support", "dev-nova5", "dev-using-inertia"},
	"plusinfolab/logstation": {
		"dev-master",
		"dev-dependabot/github_actions/actions/checkout-6",
		"dev-dependabot/github_actions/dependabot/fetch-metadata-3.1.0",
		"dev-dependabot/github_actions/ramsey/composer-install-4",
	},
	"roberts/leads": {
		"2.0.0", "2.0.1", "2.0.2", "2.0.3",
		"2.1.0", "2.1.1", "2.1.2", "2.1.3", "2.1.4",
		"dev-main", "dev-drewroberts/feature/test-case",
	},
	"sevenspan/code-generator": {
		"dev-master",
		"dev-feat/livewire-version-update",
		"dev-feat/migration-message",
		"dev-feat/notification-blade-file-support",
		"dev-feat/resource-collection-changes",
		"dev-fix/data-type-mapping",
		"dev-fix/feedback",
		"dev-fix/generator-path-and-migration-table-name",
		"dev-hotfix/vitepress-setup",
		"dev-update/notification-modal",
	},
	"sevenspan/laravel-chat": {
		"1.4.0", "1.4.1", "1.4.2", "1.5.0", "1.5.1", "1.5.2",
		"dev-main",
		"dev-ability-to-encrypt-body",
		"dev-feat/doc",
		"dev-feat/message-variables",
		"dev-feat/php-version-upgrade",
		"dev-imp/message-type",
	},
	"sevenspan/laravel-whatsapp": {
		"dev-master", "dev-dev", "dev-feat/doc",
		"dev-imp-message-template-api",
		"dev-upgrade/laravel-9-to-10",
	},
}

// --- Python/PyPI ---

// KnownBadPythonVersions maps legitimate PyPI package names to known-compromised versions.
// Package names are normalized (lowercase, hyphens) to match dist-info directory conventions.
var KnownBadPythonVersions = map[string][]string{
	// litellm credential stealer
	// https://www.stepsecurity.io/blog/litellm-credential-stealer-hidden-in-pypi-wheel
	"litellm": {"1.82.7", "1.82.8"},

	// Mini Shai-Hulud worm — PyPI artifacts tracked alongside the npm campaign
	// https://socket.dev/supply-chain-attacks/mini-shai-hulud
	"guardrails-ai": {"0.10.1"},
	"lightning":     {"2.6.2", "2.6.3"},
	"mistralai":     {"2.4.6"},

	// PolinRider (DPRK / Contagious Interview cluster). PyPI is the campaign's
	// smallest footprint — the worm reaches it only when an infected
	// maintainer also publishes Python packages.
	// https://socket.dev/supply-chain-attacks/polinrider
	"pybitjs":       {"0.1.0"},
	"pyservercheck": {"0.1.1"},
}

// KnownPhantomPythonPackages are PyPI distribution names that exist solely
// as malware carriers and have no legitimate use. Their presence in any
// site-packages — in any version — is always suspicious. Names are
// normalized (lowercase, hyphens) to match dist-info directory conventions.
var KnownPhantomPythonPackages = []string{
	// TrapDoor crypto stealer (May 2026). Seven purpose-built PyPI phantoms
	// impersonating crypto / DeFi / data-pipeline tooling, published by
	// GitHub actor `ddjidd564` as part of the cross-ecosystem TrapDoor
	// campaign. Earliest observed upload: eth-security-auditor@0.1.0 on
	// May 22, 2026. Same campaign also published 21 npm phantoms (see
	// KnownPhantomPackages above) and 6 Crates.io phantoms (out of scope).
	// https://socket.dev/blog/trapdoor-crypto-stealer-npm-pypi-crates
	"cryptowallet-safety",
	"data-pipeline-check",
	"defi-risk-scanner",
	"env-loader-cli",
	"eth-security-auditor",
	"git-config-sync",
	"solidity-build-guard",
}

// KnownMaliciousPthFiles are .pth filenames that are known malware delivery mechanisms.
// Source: StepSecurity litellm writeup
// https://www.stepsecurity.io/blog/litellm-credential-stealer-hidden-in-pypi-wheel
var KnownMaliciousPthFiles = []string{
	"litellm_init.pth",
}

// --- Project-local artifacts ---

// ProjectArtifact describes a malicious file expected inside a project-local config directory
// (e.g., a repository's .claude/ or .vscode/ folder) rather than at a fixed home-relative path.
type ProjectArtifact struct {
	Filename string
	Desc     string
	Attack   string
}

// KnownProjectArtifacts maps a project-local config directory name to malicious files
// a documented supply chain attack is known to drop inside it. The scanner finds these
// during the home-directory walk and reports any match as a critical finding.
// Sources:
//   - StepSecurity Mini Shai-Hulud writeup
//     https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem
//   - Aikido Mini Shai-Hulud writeup (execution.js — alternate name for the Bun-loaded payload across the campaign)
//     https://www.aikido.dev/blog/mini-shai-hulud-is-back-tanstack-compromised
//   - Socket campaign tracker (confirms execution.js / router_runtime.js are interchangeable payload names)
//     https://socket.dev/supply-chain-attacks/mini-shai-hulud
//   - SafeDep @antv-wave writeup (.claude/index.js as the May 19, 2026 payload-copy name committed into repos)
//     https://safedep.io/mini-shai-hulud-strikes-again-314-npm-packages-compromised/
//   - Snyk keyv writeup (.claude/math_init.js + .claude/.vscode setup.mjs IDE hooks)
//     https://snyk.io/blog/inside-keyv-npm-compromise-preinstall-malware-trusted-provenance-ide-hooks/
var KnownProjectArtifacts = map[string][]ProjectArtifact{
	".claude": {
		{Filename: "router_runtime.js", Desc: "mini-shai-hulud Bun payload dropped via Claude Code SessionStart hook", Attack: "mini-shai-hulud (May 2026)"},
		{Filename: "execution.js", Desc: "mini-shai-hulud Bun payload (alternate filename for the same campaign)", Attack: "mini-shai-hulud (May 2026)"},
		{Filename: "setup.mjs", Desc: "shared setup module (mini-shai-hulud; also keyv npm compromise SessionStart / folderOpen hooks)", Attack: "mini-shai-hulud (May 2026); keyv npm compromise (Aug 2026)"},
		{Filename: "index.js", Desc: "mini-shai-hulud Bun payload copy committed to repos (@antv wave)", Attack: "mini-shai-hulud (@antv wave, May 19 2026)"},
		// keyv npm compromise (Aug 4, 2026) — less-obfuscated second-stage name
		// committed into the keyv repo alongside .claude/setup.mjs. The npm
		// tarballs ship the same stage as Math_Symbol.js (727,680 bytes).
		// https://snyk.io/blog/inside-keyv-npm-compromise-preinstall-malware-trusted-provenance-ide-hooks/
		{Filename: "math_init.js", Desc: "keyv npm compromise second-stage payload dropped via Claude Code SessionStart hook", Attack: "keyv npm compromise (Aug 2026)"},
	},
	".vscode": {
		{Filename: "execution.js", Desc: "mini-shai-hulud Bun payload (alternate filename for the same campaign)", Attack: "mini-shai-hulud (May 2026)"},
		{Filename: "setup.mjs", Desc: "shared setup module dropped via VS Code folderOpen task (mini-shai-hulud; also keyv npm compromise)", Attack: "mini-shai-hulud (May 2026); keyv npm compromise (Aug 2026)"},
	},
}

// KnownNpmPayloadFiles maps an npm scope (e.g., "@tanstack") or an unscoped
// package name (e.g., "keyv") to filenames a documented supply chain attack
// is known to drop inside packages of that key. During the node_modules walk,
// scoped packages are checked under node_modules/<scope>/*, and unscoped
// packages under node_modules/<name>, independent of the version check.
// Sources:
//   - TanStack postmortem (router_init.js)
//     https://tanstack.com/blog/npm-supply-chain-compromise-postmortem
//   - Aikido writeup (tanstack_runner.js + SHA-256)
//     https://www.aikido.dev/blog/mini-shai-hulud-is-back-tanstack-compromised
//   - Snyk keyv writeup (setup.mjs + Math_Symbol.js; identical across all
//     11 malicious releases under maintainer jaredwray)
//     https://snyk.io/blog/inside-keyv-npm-compromise-preinstall-malware-trusted-provenance-ide-hooks/
//
// tanstack_runner.js SHA-256: 2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96
// keyv setup.mjs SHA-256:     54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668
// keyv Math_Symbol.js SHA-256: 9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc
var KnownNpmPayloadFiles = map[string][]ProjectArtifact{
	"@tanstack": {
		{Filename: "router_init.js", Desc: "Mini Shai-Hulud TanStack sub-incident payload (~2.3 MB obfuscated JS)", Attack: "mini-shai-hulud (TanStack sub-incident, May 2026)"},
		{Filename: "tanstack_runner.js", Desc: "Mini Shai-Hulud TanStack sub-incident runner (Bun-loaded via prepare hook)", Attack: "mini-shai-hulud (TanStack sub-incident, May 2026)"},
	},
	// keyv npm compromise (Aug 4, 2026) — scoped @cacheable/* packages. The
	// same two payload files appear in every affected tarball; matching on
	// filename catches leftovers after a version downgrade or partial cleanup.
	"@cacheable": {
		{Filename: "setup.mjs", Desc: "keyv npm compromise preinstall loader (29,918 bytes)", Attack: "keyv npm compromise (Aug 2026)"},
		{Filename: "Math_Symbol.js", Desc: "keyv npm compromise second-stage payload (727,680 bytes)", Attack: "keyv npm compromise (Aug 2026)"},
	},
	// keyv npm compromise — unscoped packages that received the same payloads.
	// Keys are exact package directory names under node_modules/.
	"keyv": {
		{Filename: "setup.mjs", Desc: "keyv npm compromise preinstall loader (29,918 bytes)", Attack: "keyv npm compromise (Aug 2026)"},
		{Filename: "Math_Symbol.js", Desc: "keyv npm compromise second-stage payload (727,680 bytes)", Attack: "keyv npm compromise (Aug 2026)"},
	},
	"cacheable": {
		{Filename: "setup.mjs", Desc: "keyv npm compromise preinstall loader (29,918 bytes)", Attack: "keyv npm compromise (Aug 2026)"},
		{Filename: "Math_Symbol.js", Desc: "keyv npm compromise second-stage payload (727,680 bytes)", Attack: "keyv npm compromise (Aug 2026)"},
	},
	"flat-cache": {
		{Filename: "setup.mjs", Desc: "keyv npm compromise preinstall loader (29,918 bytes)", Attack: "keyv npm compromise (Aug 2026)"},
		{Filename: "Math_Symbol.js", Desc: "keyv npm compromise second-stage payload (727,680 bytes)", Attack: "keyv npm compromise (Aug 2026)"},
	},
	"cacheable-request": {
		{Filename: "setup.mjs", Desc: "keyv npm compromise preinstall loader (29,918 bytes)", Attack: "keyv npm compromise (Aug 2026)"},
		{Filename: "Math_Symbol.js", Desc: "keyv npm compromise second-stage payload (727,680 bytes)", Attack: "keyv npm compromise (Aug 2026)"},
	},
	"file-entry-cache": {
		{Filename: "setup.mjs", Desc: "keyv npm compromise preinstall loader (29,918 bytes)", Attack: "keyv npm compromise (Aug 2026)"},
		{Filename: "Math_Symbol.js", Desc: "keyv npm compromise second-stage payload (727,680 bytes)", Attack: "keyv npm compromise (Aug 2026)"},
	},
	"cache-manager": {
		{Filename: "setup.mjs", Desc: "keyv npm compromise preinstall loader (29,918 bytes)", Attack: "keyv npm compromise (Aug 2026)"},
		{Filename: "Math_Symbol.js", Desc: "keyv npm compromise second-stage payload (727,680 bytes)", Attack: "keyv npm compromise (Aug 2026)"},
	},
	"ecto": {
		{Filename: "setup.mjs", Desc: "keyv npm compromise preinstall loader (29,918 bytes)", Attack: "keyv npm compromise (Aug 2026)"},
		{Filename: "Math_Symbol.js", Desc: "keyv npm compromise second-stage payload (727,680 bytes)", Attack: "keyv npm compromise (Aug 2026)"},
	},
}

// --- Source-file payload signatures ---

// PayloadSignature is a fixed string that appears verbatim inside a file a
// documented supply chain attack has injected code into. Matching is on exact
// bytes, never a regex — these are constants lifted from published analyses,
// not heuristics.
type PayloadSignature struct {
	Signature string
	Desc      string
	Attack    string
	// Requires adds context for short strings that are not distinctive alone.
	Requires string
}

// KnownPayloadSignatures are byte sequences that identify an injected payload
// inside an otherwise-legitimate source or config file.
//
// PolinRider appends its loader to the end of a real build config after ~280
// spaces of padding, so the file still opens, still builds, and still looks
// untouched in a diff unless you scroll right. Filename matching cannot find
// that — the file is `tailwind.config.js` and it is supposed to be there — so
// content matching is the only option.
//
// The campaign has rotated its constants once already (the original March
// `rmcej%otb%` / `_$_1e42` pair became `Cot%3t=shtP` / `MDy` in April, an
// evasion response to OSM's published YARA rule), so every generation's
// markers are listed and a clean result is not proof of anything. The
// `global['!']=` and `global['_V']=` forms are included because assigning to a
// property literally named `!` or `_V` on the global object is not something
// any legitimate build config does, which makes them durable across rotations
// of the surrounding constants.
//
// Sources:
//   - OSM PolinRider dossier (signature constants, both variants, YARA rules)
//     https://github.com/OpenSourceMalware/PolinRider
//   - OSM npm case study (the `global.i="A8-…"` campaign-tag markers)
//     https://opensourcemalware.com/blog/polinrider-npm-case-study-dprk-attack
var KnownPayloadSignatures = []PayloadSignature{
	{Signature: `rmcej%otb%`, Desc: "PolinRider loader signature (original March 2026 variant)", Attack: "polinrider (DPRK)"},
	{Signature: `_$_1e42`, Desc: "PolinRider decoder function (original March 2026 variant)", Attack: "polinrider (DPRK)"},
	{Signature: `Cot%3t=shtP`, Desc: "PolinRider loader signature (rotated April 2026 variant)", Attack: "polinrider (DPRK)"},
	{Signature: `global['!']=`, Desc: "PolinRider global injection marker", Attack: "polinrider (DPRK)"},
	{Signature: `global['_V']=`, Desc: "PolinRider global injection marker (rotated April 2026 variant)", Attack: "polinrider (DPRK)"},
	{Signature: `global.i="A8-`, Desc: "PolinRider campaign-tag marker (fake-font and babel.config.cjs variants)", Attack: "polinrider (DPRK)"},
	{Signature: `global.i="A9-`, Desc: "PolinRider campaign-tag marker (config-append variant; payload appended to the last line of a build config)", Attack: "polinrider (DPRK)"},

	// The NullReceiver loader's own constants, from the OSV records for the two
	// trojanized npm carriers. These are a different class of indicator from the
	// markers above: those identify a generation of the obfuscator, these
	// identify the C2 resolver itself, so they survive a rotation of the
	// obfuscator and hold across carriers the campaign has not published yet.
	//
	// The wallet is the durable one. Every host in KnownC2IPs rotates for the
	// price of one Ethereum transaction, because the loader reads the next
	// address off-chain — but the address it reads FROM is compiled into the
	// payload, and changing that means republishing to every victim rather than
	// sending a transaction. Both spellings are listed because matching is exact
	// bytes: OSV renders the address lowercase, the campaign writeups render it
	// EIP-55 checksummed, and a sample can carry either.
	//
	// Sources — both records independently document the same wallet, the same
	// Ethereum JSON-RPC endpoint set, the same `/0x/cls` + `/0x/ls` fetch paths,
	// the same XOR-then-eval decode, and the same `node -e` spawn:
	//   https://osv.dev/vulnerability/MAL-2026-11136  (fluid-type-ui; GHSA-4w4v-pw3v-q85q)
	//   https://osv.dev/vulnerability/MAL-2026-11132  (bianira-ui)
	//
	// General source inspection normalizes fixed-width ASCII escapes before
	// matching these existing literals; it never evaluates or unpacks code.

	{Signature: `0xa322e5f3d311d3080e6f0121063e9adc2490ef1a`, Desc: "NullReceiver C2-resolver wallet address (lowercase form)", Attack: "polinrider (DPRK)"},
	{Signature: `0xa322E5f3D311D3080e6f0121063e9aDC2490Ef1a`, Desc: "NullReceiver C2-resolver wallet address (EIP-55 checksummed form)", Attack: "polinrider (DPRK)"},
	{Signature: `0x/cls`, Desc: "NullReceiver second-stage fetch path (XOR-encrypted payload, eval'd or spawned via node -e)", Attack: "polinrider (DPRK)"},
	{Signature: `0x/ls`, Desc: "NullReceiver second-stage fetch path (XOR-encrypted payload, eval'd or spawned via node -e)", Attack: "polinrider (DPRK)"},

	// Application persistence markers and additional stage paths recovered in
	// the Joyfill analysis. Match published literals, not arbitrary date tags.
	// https://socket.dev/blog/joyfill-npm-beta-releases-compromised
	// https://www.stepsecurity.io/blog/joyfill-npm-supply-chain-compromise
	{Signature: `/*RS260605*/`, Desc: "PolinRider application persistence marker", Attack: "polinrider (DPRK)"},
	{Signature: `/*C250617A*/`, Desc: "PolinRider application persistence marker", Attack: "polinrider (DPRK)"},
	{Signature: `/*C250618A*/`, Desc: "PolinRider application persistence marker", Attack: "polinrider (DPRK)"},
	{Signature: `/*C250619A*/`, Desc: "PolinRider application persistence marker", Attack: "polinrider (DPRK)"},
	{Signature: `/*C250620A*/`, Desc: "PolinRider application persistence marker", Attack: "polinrider (DPRK)"},
	{Signature: `/*C260511A*/`, Desc: "PolinRider application persistence marker", Attack: "polinrider (DPRK)"},
	{Signature: `/*C260512A*/`, Desc: "PolinRider application persistence marker", Attack: "polinrider (DPRK)"},
	{Signature: `0x/js`, Desc: "PolinRider additional JavaScript fetch path", Attack: "polinrider (DPRK)"},
	{Signature: `ThZG+0jfXE6VAGOJ`, Desc: "DEV#POPPER boot-stage XOR key", Attack: "polinrider (DPRK)"},

	// Community corroboration of the exact markers, including the backup suffix.
	// Do not copy ByteGuard's broad date-marker regex or unrelated family labels.
	// https://github.com/n0m4dz/ByteGuard/blob/ac0f609ecdfeab88d731ed7b47ffdf38deb8256d/rules/default.rules.json
	{Signature: `__inzCR`, Desc: "PolinRider application loader identifier", Attack: "polinrider (DPRK)"},
	{Signature: `/*M260630A*/`, Desc: "PolinRider application build marker", Attack: "polinrider (DPRK)"},

	// Exact XOR keys and payload-header name independently published by Amazon
	// Inspector. The lowercase header is matched case-insensitively below.
	// https://osv.dev/vulnerability/MAL-2026-15636
	// https://osv.dev/vulnerability/MAL-2026-12324
	{Signature: `q4FZkxX{!h,Sr3=@`, Desc: "NullReceiver second-stage loader XOR key (eval'd and spawned stage)", Attack: "polinrider (DPRK)"},
	{Signature: `y-p_>d$0B&@^1aQk`, Desc: "NullReceiver second-stage loader XOR key (spawned stage)", Attack: "polinrider (DPRK)"},
	{Signature: `x-payload-b64`, Desc: "NullReceiver payload response header", Attack: "polinrider (DPRK)"},

	// https://github.com/OsamaCodes62/nullreceiver-ir-kit/blob/main/iocs/iocs.csv
	{Signature: `0x/clb`, Desc: "NullReceiver RAT fetch path", Attack: "polinrider (DPRK)"},
	{Signature: `/$/boot`, Desc: "NullReceiver boot-stage fetch path", Attack: "polinrider (DPRK)"},
	{Signature: `/verify-human/`, Desc: "NullReceiver status beacon path", Attack: "polinrider (DPRK)"},
	{Signature: `helloipbot!!`, Desc: "NullReceiver dead-drop recipient marker", Attack: "polinrider (DPRK)"},
	{Signature: `68656c6c6f6970626f742121`, Desc: "NullReceiver hex-encoded dead-drop recipient marker", Attack: "polinrider (DPRK)"},
	// The upload path alone is too short for a meaningful content finding.
	// Both the endpoint and Socket.IO client are documented in this RAT:
	// https://socket.dev/blog/joyfill-npm-beta-releases-compromised
	{Signature: `/u/f`, Requires: `socket.io-client`, Desc: "PolinRider multipart upload path alongside its Socket.IO client", Attack: "polinrider (DPRK)"},
}

// SignatureScannedExtensions are file extensions worth reading for
// KnownPayloadSignatures during the project walk. Traversal boundaries remain
// separate. Additional contextual rules and their citations live in heuristics.go:
// https://github.com/n0m4dz/ByteGuard/blob/ac0f609ecdfeab88d731ed7b47ffdf38deb8256d/rules/default.rules.json
// Unicode coverage: https://www.endorlabs.com/reports/invisible-threats-glassworm-unicode-vscode
var SignatureScannedExtensions = []string{
	".js", ".mjs", ".cjs", ".ts", ".mts", ".cts",
	".woff2", ".woff", ".dict", ".json", ".jsonc",
	".jsx", ".tsx", ".py", ".sh", ".bash", ".zsh", ".ps1", ".cmd", ".bat", ".yaml", ".yml", ".toml", ".ini", ".conf", ".xml", ".plist", ".service", ".txt", ".md", ".html", ".vue", ".svelte", ".php", ".rb", ".dart",
}

// SignatureScanMaxBytes is the exclusive whole-file content limit (100 MB).
// Reading and inspection together must finish within ReadTimeout.
const SignatureScanMaxBytes = 100_000_000

// ConfigPaddingRunLength is the number of consecutive spaces that marks a
// whitespace-padded injection. PolinRider pads with roughly 280 spaces to push
// the payload off the right edge of an editor viewport. Only runs between
// non-whitespace text on the same line qualify; indentation is ignored.
// https://opensourcemalware.com/blog/developer-guide-getting-over-polinrider
const ConfigPaddingRunLength = 200

// --- Repo-local propagation artifacts ---

// KnownRepoArtifacts are filenames treated as malicious wherever they appear in
// a project tree, matched on basename during the home-directory walk rather
// than at a fixed path.
//
// PolinRider's propagation runs locally: `temp_auto_push.bat` resets the
// machine clock, amends the last commit so the timestamp matches the one it
// replaced, and force-pushes with whatever git credentials are already cached.
// Nothing leaves the machine that GitHub can distinguish from the real
// developer, which is why the artifact left on disk is the evidence. OSM
// found it still present in 101 victim repos whose owners had already cleaned
// the payload out of their config files, making it the single
// highest-confidence indicator of past compromise in the campaign.
//
// Sources:
//   - OSM PolinRider remediation guide (temp_auto_push.bat, config.bat, and
//     the `config.bat` line injected into .gitignore to hide it)
//     https://opensourcemalware.com/blog/developer-guide-getting-over-polinrider
//   - OSM PolinRider dossier (polinrider-scanner.sh checks the same three)
//     https://github.com/OpenSourceMalware/PolinRider
var KnownRepoArtifacts = []ProjectArtifact{
	{Filename: "temp_auto_push.bat", Desc: "PolinRider propagation script (clock reset + commit amend + force-push)", Attack: "polinrider (DPRK)"},
	{Filename: "config.bat", Desc: "PolinRider hidden orchestrator (added to .gitignore to hide it from git status)", Attack: "polinrider (DPRK)"},

	// Mini Shai-Hulud payload filenames are also checked outside known npm
	// scopes to catch additional carriers. Generic names such as setup.mjs
	// remain package-scoped. Math_Symbol.js requires content verification
	// below because regenerate-unicode-properties legitimately ships it.
	//
	// Sources:
	//   - TanStack postmortem (router_init.js)
	//     https://tanstack.com/blog/tanstack-router-compromise-postmortem
	//   - Aikido (tanstack_runner.js + SHA-256)
	//     https://www.aikido.dev/blog/tanstack-npm-supply-chain-attack
	{Filename: "router_init.js", Desc: "mini-shai-hulud payload loader", Attack: "mini-shai-hulud (May 2026)"},
	{Filename: "tanstack_runner.js", Desc: "mini-shai-hulud Bun-loaded payload", Attack: "mini-shai-hulud (May 2026)"},
}

// RepoPayloadHash identifies raw payload bytes. Filesystem checks use Filename;
// Git history inspection ignores filenames and uses Size as an exact-byte candidate optimization.
// GitBlobSHA1 is the Git object identity, not a raw-file SHA-1 or SHA-256.
type RepoPayloadHash struct {
	Filename    string
	SHA256      string
	Size        int64
	GitBlobSHA1 string
	Desc        string
	Attack      string
}

// KnownRepoPayloadHashes disambiguates payload names also used by legitimate
// packages. No directory is exempted: a replaced Unicode file is still checked.
// Source: Snyk's independently computed second-stage hash:
// https://snyk.io/blog/inside-keyv-npm-compromise-preinstall-malware-trusted-provenance-ide-hooks/
// Legitimate filename collision:
// https://github.com/mathiasbynens/regenerate-unicode-properties/blob/v10.2.0/General_Category/Math_Symbol.js
var KnownRepoPayloadHashes = []RepoPayloadHash{
	{
		Filename: "Math_Symbol.js",
		SHA256:   "9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc",
		Size:     727680,
		Desc:     "keyv second-stage payload (SHA-256 verified)",
		Attack:   "keyv npm compromise (August 2026)",
	},
	{
		// Sample bytes verified 2026-09-19.
		// No independent public report of this exact hash was found; do not
		// present it as an IOC supplied by the public campaign writeups.
		Filename:    "fa-solid-400.woff2",
		SHA256:      "11570a86f8a19cd20bc5e1df112f43c52bc939f18b51c37e902d312fd62f6d27",
		Size:        37566,
		GitBlobSHA1: "9b2e3a349e377ba2985c593cb3e619f84a0ea1dc",
		// Desc names the landing a reader can search for, not shorthand.
		Desc:   "Fake Font dropper: JavaScript disguised as a FontAwesome font, run by a .vscode/tasks.json folderOpen task; hash is incident-sourced",
		Attack: "polinrider (DPRK)",
	},
	{
		// Config-append variant of the same campaign: the payload is appended
		// to the last line of a build config the project already loads, so it
		// executes on any lint, dev server or build rather than only on a
		// folder open. Two sizes are published because the attacker's tool
		// writes a constant whitespace run ahead of the payload: 8,626 bytes
		// is the payload blob, 9,133 is that blob behind its 507-space prefix.
		// The prefix is identical across every observed carrier, which makes
		// the segment the more reliable of the two.
		//
		// Plain ASCII, so the hash describes real bytes. No independent
		// public report of these hashes was found.
		SHA256: "85d1294bd225c6fdf938bdc2e2cab392140ac97baccd25442d8c2a0cb015b57d",
		Size:   8626,
		Desc:   "PolinRider config-append payload, appended to the last line of a build config so any lint or build runs it; hash is incident-sourced",
		Attack: "polinrider (DPRK)",
	},
	{
		// The same payload behind the 507-space prefix its injector writes.
		SHA256: "a2bb666327ef2345871e42d6f354123f16bfbdfe16e5a928dd5afd8c144b7138",
		Size:   9133,
		Desc:   "PolinRider config-append injected segment (507-space prefix plus payload), the invariant the injector writes; hash is incident-sourced",
		Attack: "polinrider (DPRK)",
	},
	// PolinRider payload files published by Socket, all delivered under the
	// name tailwind.config.js. Socket does not publish sizes, so these stay
	// filename-gated on disk and are excluded from Git blob candidates; see
	// knownPayloadSize below for why a size-less entry cannot be name-free.
	// https://socket.dev/blog/polinrider-github-packagist
	{Filename: "tailwind.config.js", SHA256: "7d47c430e6e404dc2fa8b4837678d1cbdb4d0aeacec9b405655cab79d54a2ad9", Desc: "PolinRider injected tailwind.config.js payload", Attack: "polinrider (DPRK)"},
	{Filename: "tailwind.config.js", SHA256: "b7ede935d4979146b55f12b9eec7c83b61962b478f5dc9b8db251e539ec2abd3", Desc: "PolinRider injected tailwind.config.js payload", Attack: "polinrider (DPRK)"},
	{Filename: "tailwind.config.js", SHA256: "ccb187dc9de0cc7477c9817ae53365d273e121407c0305f863e2ab67c35d6395", Desc: "PolinRider injected tailwind.config.js payload", Attack: "polinrider (DPRK)"},
	{Filename: "tailwind.config.js", SHA256: "139ea03dcddf4aa810d55740be3cf6c92ce7a9f3cbcbbb35440e25b769a87683", Desc: "PolinRider injected tailwind.config.js payload", Attack: "polinrider (DPRK)"},
	{Filename: "tailwind.config.js", SHA256: "515a53291d25d229e1f9fa72e66407e1cfd7e77c91478400b24d5185af68531a", Desc: "PolinRider injected tailwind.config.js payload", Attack: "polinrider (DPRK)"},
}

// knownPayloadSize reports an exact length match against a sized hash entry.
// Size is what buys filename independence: a known length is a cheap candidate
// filter, so any file or Git blob of exactly that length can be hashed no
// matter what it is called. Entries published without a size stay filename-
// gated, because the alternative — hashing every blob and every file — is not
// an acceptable default cost.
func knownPayloadSize(size int64) bool {
	for _, h := range KnownRepoPayloadHashes {
		if h.Size != 0 && h.Size == size {
			return true
		}
	}
	return false
}

// knownPayloadName reports whether a basename is a published payload filename.
func knownPayloadName(name string) bool {
	return slices.ContainsFunc(KnownRepoPayloadHashes, func(h RepoPayloadHash) bool { return h.Filename == name })
}

// knownPayloadBlob reports a Git object ID published as a payload blob identity.
// Matching this needs no body read at all: the object ID is already in hand.
func knownPayloadBlob(id string) (RepoPayloadHash, bool) {
	for _, h := range KnownRepoPayloadHashes {
		if h.GitBlobSHA1 != "" && h.GitBlobSHA1 == id {
			return h, true
		}
	}
	return RepoPayloadHash{}, false
}

// GitignoreInjectedLines are exact .gitignore entries a documented attack adds
// to conceal a file it dropped. Matched as a whole line.
// https://opensourcemalware.com/blog/developer-guide-getting-over-polinrider
var GitignoreInjectedLines = []PayloadSignature{
	{Signature: "config.bat", Desc: "PolinRider hid its orchestrator from git status by adding it to .gitignore", Attack: "polinrider (DPRK)"},
}

// --- Patched package-manager entrypoints ---

// NpmCLIGlobs are glob patterns for the global npm CLI entrypoint across the
// install layouts surplies supports. Globs rather than `npm root -g` on
// purpose: multiple node installs routinely coexist (system, Homebrew, nvm,
// fnm, Volta, n) and asking one of them where it lives reports on that one
// only. Paths are resolved against the home directory where relative.
//
// PolinRider overwrites this file with a ~1 MB malicious npm CLI. It matters
// more than a poisoned project config because every `npm`, `npx`, or
// `npm exec` call then re-spawns the malware, and it survives a reboot — one
// developer traced their reinfection to an editor silently running
// `npm exec <package>@latest` in the background.
// https://opensourcemalware.com/blog/developer-guide-getting-over-polinrider
func NpmCLIGlobs(homeDir string) []string {
	rel := []string{
		filepath.Join(".nvm", "versions", "node", "*", "lib", "node_modules", "npm", "lib", "cli.js"),
		filepath.Join(".volta", "tools", "image", "npm", "*", "lib", "node_modules", "npm", "lib", "cli.js"),
		filepath.Join(".local", "share", "fnm", "node-versions", "*", "installation", "lib", "node_modules", "npm", "lib", "cli.js"),
		filepath.Join("n", "lib", "node_modules", "npm", "lib", "cli.js"),
		filepath.Join(".npm-global", "lib", "node_modules", "npm", "lib", "cli.js"),
		filepath.Join("node_modules", "npm", "lib", "cli.js"),
	}

	globs := make([]string, 0, len(rel)+6)
	for _, r := range rel {
		globs = append(globs, filepath.Join(homeDir, r))
	}

	if runtime.GOOS == "windows" {
		if appData := os.Getenv("APPDATA"); appData != "" {
			globs = append(globs, filepath.Join(appData, "npm", "node_modules", "npm", "lib", "cli.js"))
		}
		if pf := os.Getenv("ProgramFiles"); pf != "" {
			globs = append(globs, filepath.Join(pf, "nodejs", "node_modules", "npm", "lib", "cli.js"))
		}
		return globs
	}

	return append(globs,
		"/usr/lib/node_modules/npm/lib/cli.js",
		"/usr/local/lib/node_modules/npm/lib/cli.js",
		"/opt/homebrew/lib/node_modules/npm/lib/cli.js",
		"/opt/local/lib/node_modules/npm/lib/cli.js",
	)
}

// NpmCLIMaxNormalBytes is the size above which a global npm CLI entrypoint is
// treated as overwritten. The real file is a few hundred bytes across every
// npm major version — four lines that require the implementation — while the
// PolinRider replacement is roughly 1 MB with the payload appended after a
// long whitespace run starting on line 5. The threshold sits two orders of
// magnitude above normal and three below the malicious size, so it does not
// depend on either number staying exact.
const NpmCLIMaxNormalBytes = 100 << 10 // 100 KiB

// ApplicationEntrypointGlobs locates the documented injection targets in
// conventional installation layouts. Layouts are discovery paths, not IOCs:
// presence alone never flags an application. Recursive discovery supplements
// these patterns for custom installs; ASAR archives are not unpacked. No installed executable is invoked.
// Targets: https://www.stepsecurity.io/blog/joyfill-npm-supply-chain-compromise
// Roots: https://github.com/OsamaCodes62/nullreceiver-ir-kit/blob/main/scan_macos.sh
// VS Code out/main.js and exact __inzCR / M260630A markers:
// https://github.com/n0m4dz/ByteGuard/blob/ac0f609ecdfeab88d731ed7b47ffdf38deb8256d/src/scanner.ts
func ApplicationEntrypointGlobs(home, goos string, getenv func(string) string) []string {
	var roots, discord []string
	switch goos {
	case "darwin":
		for _, base := range []string{"/Applications", filepath.Join(home, "Applications")} {
			for _, app := range []string{"Visual Studio Code", "Visual Studio Code - Insiders", "Cursor", "Antigravity", "GitHub Desktop"} {
				roots = append(roots, filepath.Join(base, app+".app", "Contents", "Resources", "app"))
			}
		}
		discord = append(discord, filepath.Join(home, "Library", "Application Support", "discord*"))
	case "windows":
		roots, discord = windowsApplicationRoots(home, getenv)
	default:
		for _, base := range []string{"/usr/share", "/usr/lib", "/opt", filepath.Join(home, ".local", "share")} {
			for _, app := range []string{"code", "code-insiders", "cursor", "Cursor", "antigravity", "github-desktop"} {
				roots = append(roots, filepath.Join(base, app, "resources", "app"))
			}
		}
		config := getenv("XDG_CONFIG_HOME")
		if config == "" {
			config = filepath.Join(home, ".config")
		}
		discord = append(discord, filepath.Join(config, "discord*"))
	}
	var paths []string
	for _, root := range roots {
		for _, target := range []string{"out/main.js", "main.js", "node_modules/@vscode/deviceid/dist/index.js"} {
			paths = append(paths, filepath.Join(root, filepath.FromSlash(target)))
		}
	}
	for _, root := range discord {
		paths = append(paths,
			filepath.Join(root, "*", "modules", "discord_desktop_core*", "discord_desktop_core", "index.js"),
			filepath.Join(root, "modules", "discord_desktop_core*", "discord_desktop_core", "index.js"))
	}
	return paths
}

func windowsApplicationRoots(home string, getenv func(string) string) (roots, discord []string) {
	for _, base := range []string{getenv("ProgramFiles"), getenv("ProgramFiles(x86)"), filepath.Join(home, "AppData", "Local", "Programs")} {
		if base == "" {
			continue
		}
		for _, app := range []string{"Microsoft VS Code", "Microsoft VS Code Insiders", "cursor", "Antigravity"} {
			roots = append(roots, filepath.Join(base, app, "resources", "app"))
		}
	}
	local := getenv("LOCALAPPDATA")
	if local == "" {
		local = filepath.Join(home, "AppData", "Local")
	}
	for _, app := range []string{"Microsoft VS Code", "cursor", "Antigravity"} {
		roots = append(roots, filepath.Join(local, "Programs", app, "resources", "app"))
	}
	roots = append(roots, filepath.Join(local, "GitHubDesktop", "app-*", "resources", "app"))
	roaming := getenv("APPDATA")
	if roaming == "" {
		roaming = filepath.Join(home, "AppData", "Roaming")
	}
	discord = append(discord, filepath.Join(roaming, "discord*"), filepath.Join(local, "Discord*", "app-*"))
	return roots, discord
}

// Public staging paths, warnings only because these names also have benign uses.
// https://github.com/OsamaCodes62/nullreceiver-ir-kit/blob/main/iocs/iocs.csv
// The same source identifies ~/.node_modules/node_modules as runtime storage.
var NullReceiverStagingNames = []string{"get-pip.py", ".pip", ".npm"}

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
	"seed2.getsession.org",  // mini-shai-hulud (TanStack sub-incident) — Session seed for exfil channel
	"seed3.getsession.org",  // mini-shai-hulud (TanStack sub-incident) — Session seed for exfil channel
	"litter.catbox.moe",     // mini-shai-hulud (TanStack sub-incident) — secondary payload host (legit service abused)
	"t.m-kosche.com",        // mini-shai-hulud (@antv wave, May 19 2026) — RSA+AES exfil disguised as OpenTelemetry traces (/api/public/otel/v1/traces)
}

// KnownC2IPs are command-and-control IP addresses from documented supply chain attacks.
//
// The PolinRider entries are a snapshot, not a fixed list. That campaign
// resolves its C2 off the Ethereum blockchain (the NullReceiver technique:
// the IPv4 address is encoded in the destination address bytes of a zero-value
// transaction from wallet 0xa322E5f3D311D3080e6f0121063e9aDC2490Ef1a, tailed
// with ASCII `helloipbot!!`). There is no domain, registrar or host to seize,
// and republishing the next address costs the operator one transaction, so
// these rotate on their whim and a miss here means nothing.
//
// The Ethereum JSON-RPC endpoints the loader queries (1rpc.io, eth.drpc.org,
// ethereum-rpc.publicnode.com, eth-mainnet.public.blastapi.io,
// eth.blockscout.com — the first, second and last of those confirmed again in
// https://osv.dev/vulnerability/MAL-2026-11136 and
// https://osv.dev/vulnerability/MAL-2026-11132) are deliberately NOT listed as
// C2 domains: they are
// legitimate public infrastructure, and flagging them would report every web3
// developer as compromised. Egress to them from a machine that has no business
// speaking JSON-RPC is a real signal, but it is one for network monitoring,
// not for a filesystem scanner's connection check.
var KnownC2IPs = []string{
	"142.11.206.73", // axios

	// PolinRider — C2 hosts observed in the Packagist wave. All AS149440
	// (Evoxt), the provider the operator rotates hosts within.
	// https://socket.dev/blog/polinrider-github-packagist
	"193.247.144.38",
	"166.88.73.46",
	"166.88.134.62",
	"23.27.13.135",

	// PolinRider — the interim firewall-block list from OSM's remediation
	// guide, published as a snapshot of then-live infrastructure.
	// https://opensourcemalware.com/blog/developer-guide-getting-over-polinrider
	"166.88.54.158",
	"198.105.127.210",
	"23.27.202.27",
	"154.91.0.103",
	"136.0.9.8",
	"166.88.4.2",
	"23.27.120.142",
	"202.155.8.173",
	"166.88.134.82",
	"188.43.33.249",
	"23.27.13.43",
}

// --- Filesystem artifacts ---

// ArtifactsDarwin are known malicious file paths on macOS (relative to home or absolute).
var ArtifactsDarwin = []ArtifactCheck{
	{Path: "/Library/Caches/com.apple.act.mond", Absolute: true, Desc: "axios RAT payload (macOS)", Attack: "axios 1.14.1/0.30.4"},
	{Path: "/tmp/6202033", Absolute: true, Desc: "axios AppleScript dropper (macOS)", Attack: "axios 1.14.1/0.30.4"},
	{Path: "Library/LaunchAgents/com.user.gh-token-monitor.plist", Absolute: false, Desc: "mini-shai-hulud LaunchAgent persistence", Attack: "mini-shai-hulud (May 2026)"},
	{Path: "Library/LaunchAgents/com.user.kitty-monitor.plist", Absolute: false, Desc: "mini-shai-hulud kitty-monitor LaunchAgent persistence (@antv wave)", Attack: "mini-shai-hulud (@antv wave, May 19 2026)"},
	{Path: "/var/tmp/.gh_update_state", Absolute: true, Desc: "mini-shai-hulud C2 execution state file (@antv wave)", Attack: "mini-shai-hulud (@antv wave, May 19 2026)"},
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
	{Path: ".config/systemd/user/kitty-monitor.service", Absolute: false, Desc: "mini-shai-hulud kitty-monitor systemd persistence unit (@antv wave)", Attack: "mini-shai-hulud (@antv wave, May 19 2026)"},
	{Path: "/var/tmp/.gh_update_state", Absolute: true, Desc: "mini-shai-hulud C2 execution state file (@antv wave)", Attack: "mini-shai-hulud (@antv wave, May 19 2026)"},
}

// ArtifactsCrossPlatform are checked on all platforms (paths relative to home dir).
var ArtifactsCrossPlatform = []ArtifactCheck{
	// litellm C2 backdoor and persistence
	{Path: ".config/sysmon/sysmon.py", Absolute: false, Desc: "litellm C2 backdoor script", Attack: "litellm 1.82.7/1.82.8"},
	{Path: ".config/systemd/user/sysmon.service", Absolute: false, Desc: "litellm systemd persistence unit", Attack: "litellm 1.82.7/1.82.8"},
	// mini-shai-hulud token-monitor persistence script
	{Path: ".local/bin/gh-token-monitor.sh", Absolute: false, Desc: "mini-shai-hulud token-monitor persistence script", Attack: "mini-shai-hulud (May 2026)"},
	// mini-shai-hulud kitty-monitor C2 daemon (@antv wave, May 19 2026) — polls GitHub for `firedalazer` commits
	{Path: ".local/share/kitty/cat.py", Absolute: false, Desc: "mini-shai-hulud kitty-monitor C2 daemon (@antv wave)", Attack: "mini-shai-hulud (@antv wave, May 19 2026)"},
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
	// mini-shai-hulud (Red Hat Cloud Services wave, June 1 2026)
	{"tmp.0987654321.lock", "mini-shai-hulud Bun loader execution lock file (Red Hat Cloud Services wave)"},
	{"b-*/b.zip", "mini-shai-hulud Bun loader staged payload archive, extracted under /tmp/b-* (Red Hat Cloud Services wave)"},
}
