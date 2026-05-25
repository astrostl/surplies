package main

import (
	"os"
	"path/filepath"
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
var KnownProjectArtifacts = map[string][]ProjectArtifact{
	".claude": {
		{Filename: "router_runtime.js", Desc: "mini-shai-hulud Bun payload dropped via Claude Code SessionStart hook", Attack: "mini-shai-hulud (May 2026)"},
		{Filename: "execution.js", Desc: "mini-shai-hulud Bun payload (alternate filename for the same campaign)", Attack: "mini-shai-hulud (May 2026)"},
		{Filename: "setup.mjs", Desc: "mini-shai-hulud shared setup module", Attack: "mini-shai-hulud (May 2026)"},
		{Filename: "index.js", Desc: "mini-shai-hulud Bun payload copy committed to repos (@antv wave)", Attack: "mini-shai-hulud (@antv wave, May 19 2026)"},
	},
	".vscode": {
		{Filename: "execution.js", Desc: "mini-shai-hulud Bun payload (alternate filename for the same campaign)", Attack: "mini-shai-hulud (May 2026)"},
		{Filename: "setup.mjs", Desc: "mini-shai-hulud shared setup module dropped via VS Code folderOpen task", Attack: "mini-shai-hulud (May 2026)"},
	},
}

// KnownNpmPayloadFiles maps an npm scope (e.g., "@tanstack") to filenames a
// documented supply chain attack is known to drop inside packages of that
// scope. Each package in node_modules/<scope>/* is checked for these files
// during the node_modules walk, independent of the version check.
// Sources:
//   - TanStack postmortem (router_init.js)
//     https://tanstack.com/blog/npm-supply-chain-compromise-postmortem
//   - Aikido writeup (tanstack_runner.js + SHA-256)
//     https://www.aikido.dev/blog/mini-shai-hulud-is-back-tanstack-compromised
//
// tanstack_runner.js SHA-256: 2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96
var KnownNpmPayloadFiles = map[string][]ProjectArtifact{
	"@tanstack": {
		{Filename: "router_init.js", Desc: "Mini Shai-Hulud TanStack sub-incident payload (~2.3 MB obfuscated JS)", Attack: "mini-shai-hulud (TanStack sub-incident, May 2026)"},
		{Filename: "tanstack_runner.js", Desc: "Mini Shai-Hulud TanStack sub-incident runner (Bun-loaded via prepare hook)", Attack: "mini-shai-hulud (TanStack sub-incident, May 2026)"},
	},
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
	"seed2.getsession.org",  // mini-shai-hulud (TanStack sub-incident) — Session seed for exfil channel
	"seed3.getsession.org",  // mini-shai-hulud (TanStack sub-incident) — Session seed for exfil channel
	"litter.catbox.moe",     // mini-shai-hulud (TanStack sub-incident) — secondary payload host (legit service abused)
	"t.m-kosche.com",        // mini-shai-hulud (@antv wave, May 19 2026) — RSA+AES exfil disguised as OpenTelemetry traces (/api/public/otel/v1/traces)
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
}
