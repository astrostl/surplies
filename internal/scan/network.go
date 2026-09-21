package scan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const networkTimeout = 5 * time.Second

type networkCollector func(context.Context) ([]byte, error)
type hostResolver func(context.Context, string) ([]string, error)

// macOS truncates the address column by default, cutting link-local IPv6 peers
// mid-address (fe80::1caa:a604:.55584), which parses as neither host nor port.
// Every Mac near another Apple device holds such connections open via rapportd,
// so the default flags cost a coverage warning on essentially every scan. -l is
// documented as "Print full IPv6 address" on macOS only; on Linux -l means
// "listening sockets", which would empty the snapshot.
func netstatArgs() []string {
	if runtime.GOOS == "darwin" {
		return []string{"-n", "-l"}
	}
	return []string{"-n"}
}

func (s *Scanner) checkNetworkIOCs() {
	s.inspectNetwork(func(ctx context.Context) ([]byte, error) {
		cmd := exec.CommandContext(ctx, "netstat", netstatArgs()...)
		cmd.WaitDelay = time.Second
		return cmd.Output()
	}, net.DefaultResolver.LookupHost, networkTimeout)
}

// Injected collectors permit offline tests. Workers cannot mutate findings.
func (s *Scanner) inspectNetwork(collect networkCollector, lookup hostResolver, timeout time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	type result struct {
		name string
		ips  []string
		data []byte
		err  error
	}
	results := make(chan result, len(KnownC2Domains)+1)
	go func() { data, err := collect(ctx); results <- result{name: "netstat", data: data, err: err} }()
	for _, domain := range KnownC2Domains {
		go func() { ips, err := lookup(ctx, domain); results <- result{name: domain, ips: ips, err: err} }()
	}
	pending := map[string]bool{"netstat": true}
	for _, d := range KnownC2Domains {
		pending[d] = true
	}
	resolved := map[string][]string{}
	var output []byte
	for len(pending) > 0 {
		select {
		case r := <-results:
			delete(pending, r.name)
			if r.err != nil {
				var dnsErr *net.DNSError
				if errors.As(r.err, &dnsErr) && dnsErr.IsNotFound {
					s.addFinding(Finding{Check: "scan-limited", Severity: SevInfo, Path: r.name, Detail: "DNS returned no such host; domain endpoint matching unavailable for this snapshot."})
				} else {
					s.networkError(r.name, r.err)
				}
				continue
			}
			if r.name == "netstat" {
				output = r.data
				continue
			}
			resolved[r.name] = routableIPs(r.ips)
			if len(resolved[r.name]) == 0 {
				s.addFinding(Finding{Check: "scan-limited", Severity: SevInfo, Path: r.name, Detail: "DNS completed with no routable addresses; domain endpoint matching unavailable for this snapshot (possibly blocked or sinkholed)."})
			}
		case <-ctx.Done():
			for name := range pending {
				s.networkError(name, ctx.Err())
				delete(pending, name)
			}
		}
	}
	s.matchNetworkEndpoints(output, resolved)
}

func (s *Scanner) networkError(name string, err error) {
	s.addFinding(Finding{Check: "scan-incomplete", Severity: SevWarn, Path: name, coverageCategory: "network collection", Detail: fmt.Sprintf("Network collection failed: %v; connection coverage is incomplete", err)})
}
func (s *Scanner) networkMatch(indicator, ip string) {
	s.addFinding(Finding{Check: "network-ioc-active-connection", Severity: SevCritical, Path: "netstat", Detail: fmt.Sprintf("Established TCP remote endpoint %s matches known C2 indicator %q", ip, indicator)})
}
func canonicalIP(value string) string {
	if ip, err := netip.ParseAddr(value); err == nil {
		return ip.Unmap().WithZone("").String()
	}
	return ""
}
func routableIPs(ips []string) []string {
	var out []string
	for _, v := range ips {
		ip := net.ParseIP(v)
		if ip != nil && ip.IsGlobalUnicast() && !ip.IsPrivate() {
			out = append(out, ip.String())
		}
	}
	return out
}

// macOS uses address.port; Linux and Windows use address:port. Only
// established TCP peers qualify. Mapped IPv6 normalizes to IPv4.
func endpointIP(value string) string {
	if host, port, err := net.SplitHostPort(value); err == nil && validPort(port) {
		return canonicalIP(host)
	}
	// Try macOS's final dot first; IPv4-mapped IPv6 contains colons too.
	if i := strings.LastIndex(value, "."); i >= 0 && validPort(value[i+1:]) {
		if ip := canonicalIP(value[:i]); ip != "" {
			return ip
		}
	}
	if i := strings.LastIndex(value, ":"); i >= 0 && validPort(value[i+1:]) {
		return canonicalIP(value[:i])
	}
	return ""
}
func validPort(port string) bool { _, err := strconv.ParseUint(port, 10, 16); return err == nil }
func remoteEndpoints(output string) (map[string]bool, error) {
	out := map[string]bool{}
	var parseErr error
	for line := range strings.SplitSeq(output, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || !strings.HasPrefix(strings.ToLower(f[0]), "tcp") {
			continue
		}
		peer, state := 0, 0
		if f[0] == "TCP" {
			peer, state = 2, 3
		} else {
			peer, state = 4, 5
		}
		if len(f) <= state {
			parseErr = fmt.Errorf("unrecognized TCP row format")
			continue
		}
		if !strings.EqualFold(f[state], "ESTABLISHED") {
			continue
		}
		ip := endpointIP(f[peer])
		if ip == "" {
			parseErr = fmt.Errorf("unrecognized remote endpoint format")
			continue
		}
		out[ip] = true
	}
	return out, parseErr
}

func (s *Scanner) matchNetworkEndpoints(output []byte, resolved map[string][]string) {
	endpoints, err := remoteEndpoints(string(output))
	if err != nil {
		s.networkError("netstat", err)
	}
	for _, ip := range KnownC2IPs {
		if endpoints[canonicalIP(ip)] {
			s.networkMatch(ip, ip)
		}
	}
	for domain, ips := range resolved {
		for _, ip := range ips {
			if endpoints[ip] {
				s.networkMatch(domain, ip)
				break
			}
		}
	}
}
