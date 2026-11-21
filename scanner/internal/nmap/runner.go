package nmap

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/agh-cbi/asi-scanner/internal/contract"
)

type nmapRun struct {
	Hosts []nmapHost `xml:"host"`
}

type nmapHost struct {
	Status    nmapStatus    `xml:"status"`
	Addresses []nmapAddress `xml:"address"`
	Hostnames []nmapName    `xml:"hostnames>hostname"`
	Ports     []nmapPort    `xml:"ports>port"`
}

type nmapStatus struct {
	State string `xml:"state,attr"`
}

type nmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type nmapName struct {
	Name string `xml:"name,attr"`
}

type nmapPort struct {
	Protocol string       `xml:"protocol,attr"`
	PortID   int          `xml:"portid,attr"`
	State    nmapState    `xml:"state"`
	Service  nmapService  `xml:"service"`
	Scripts  []nmapScript `xml:"script"`
}

type nmapState struct {
	State string `xml:"state,attr"`
}

type nmapService struct {
	Name       string `xml:"name,attr"`
	Tunnel     string `xml:"tunnel,attr"`
	Product    string `xml:"product,attr"`
	Version    string `xml:"version,attr"`
	ExtraInfo  string `xml:"extrainfo,attr"`
	DeviceType string `xml:"devicetype,attr"`
}

type nmapScript struct {
	ID     string `xml:"id,attr"`
	Output string `xml:"output,attr"`
}

var (
	// Ścisła biała lista bezpiecznych flag bezargumentowych nmap (blokuje --script, -o*, -iL, --datadir itp.)
	allowedNoArgFlags = map[string]bool{
		"-sT":                   true,
		"-sS":                   true,
		"-sV":                   true,
		"-sU":                   true,
		"-sn":                   true,
		"-Pn":                   true,
		"-n":                    true,
		"-R":                    true,
		"-6":                    true,
		"-F":                    true,
		"--open":                true,
		"--version-light":       true,
		"--defeat-rst-ratelimit": true,
		"-T0":                   true,
		"-T1":                   true,
		"-T2":                   true,
		"-T3":                   true,
		"-T4":                   true,
	}

	// Bezpieczne flagi z jednym zwalidowanym argumentem liczbowym / czasowym
	allowedValueFlags = map[string]*regexp.Regexp{
		"--max-retries":       regexp.MustCompile(`^[0-5]$`),
		"--version-intensity": regexp.MustCompile(`^[0-5]$`),
		"--max-rate":          regexp.MustCompile(`^[1-9][0-9]{0,4}$`),
		"--min-rate":          regexp.MustCompile(`^[1-9][0-9]{0,4}$`),
		"--host-timeout":      regexp.MustCompile(`^[1-9][0-9]{0,3}(ms|s|m)$`),
		"--top-ports":         regexp.MustCompile(`^[1-9][0-9]{0,3}$`),
		"--max-rtt-timeout":   regexp.MustCompile(`^[1-9][0-9]{0,4}(ms|s)$`),
		"--initial-rtt-timeout": regexp.MustCompile(`^[1-9][0-9]{0,4}(ms|s)$`),
	}

	portsSpecRe  = regexp.MustCompile(`^(top-1000|[0-9,\-TU:]+)$`)
	safeDomainRe = regexp.MustCompile(`^(?i)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)

	blockedHostnames = map[string]bool{
		"localhost":             true,
		"localhost.localdomain": true,
		"postgres":              true,
		"asi_postgres":          true,
		"redis":                 true,
		"asi_redis":             true,
		"backend":               true,
		"asi_backend":           true,
		"frontend":              true,
		"asi_frontend":          true,
		"metadata.google.internal": true,
	}

	blockedCIDRs []*net.IPNet
)

func init() {
	for _, raw := range []string{
		"127.0.0.0/8",
		"0.0.0.0/8",
		"169.254.0.0/16",
		"::1/128",
		"fe80::/10",
	} {
		_, ipnet, err := net.ParseCIDR(raw)
		if err == nil {
			blockedCIDRs = append(blockedCIDRs, ipnet)
		}
	}
}

// ValidateNmapFlags parsuje i weryfikuje flagi nmap względem ścisłej białej listy (ochrona przed flag-injection / RCE).
func ValidateNmapFlags(rawFlags string) ([]string, error) {
	tokens := strings.Fields(strings.TrimSpace(rawFlags))
	validated := make([]string, 0, len(tokens))
	for i := 0; i < len(tokens); i++ {
		tok := tokens[i]
		if allowedNoArgFlags[tok] {
			validated = append(validated, tok)
			continue
		}
		// Obsługa formy --flag=val
		if eqIdx := strings.IndexByte(tok, '='); eqIdx > 0 {
			flagName := tok[:eqIdx]
			flagVal := tok[eqIdx+1:]
			re, ok := allowedValueFlags[flagName]
			if !ok || !re.MatchString(flagVal) {
				return nil, fmt.Errorf("disallowed or invalid nmap flag: %q", tok)
			}
			validated = append(validated, flagName, flagVal)
			continue
		}
		if re, ok := allowedValueFlags[tok]; ok {
			if i+1 >= len(tokens) {
				return nil, fmt.Errorf("nmap flag %q missing value", tok)
			}
			val := tokens[i+1]
			if !re.MatchString(val) {
				return nil, fmt.Errorf("invalid value %q for nmap flag %q", val, tok)
			}
			validated = append(validated, tok, val)
			i++
			continue
		}
		return nil, fmt.Errorf("disallowed nmap flag (blocked by allowlist): %q", tok)
	}
	return validated, nil
}

// ValidatePorts waliduje specyfikację portów przekazywaną do nmap -p.
func ValidatePorts(rawPorts string) error {
	cleaned := strings.TrimSpace(rawPorts)
	if cleaned == "" || cleaned == "top-1000" {
		return nil
	}
	if !portsSpecRe.MatchString(cleaned) {
		return fmt.Errorf("invalid ports specification: %q", rawPorts)
	}
	return nil
}

// ValidateTarget odrzuca niebezpieczne cele wewnętrzne (loopback, metadata, kontenery infrastruktury) i flag-injection.
func ValidateTarget(target string) error {
	t := strings.TrimSpace(target)
	if t == "" || strings.HasPrefix(t, "-") || strings.ContainsAny(t, " \t\n\r;|&$`") {
		return fmt.Errorf("invalid scan target: %q", target)
	}
	lower := strings.ToLower(t)
	if blockedHostnames[lower] {
		return fmt.Errorf("blocked internal target hostname: %q", target)
	}

	if ip, ipnet, err := net.ParseCIDR(t); err == nil {
		for _, blocked := range blockedCIDRs {
			if blocked.Contains(ip) || ipnet.Contains(blocked.IP) {
				return fmt.Errorf("blocked internal/loopback/metadata CIDR: %q", target)
			}
		}
		return nil
	}

	if ip := net.ParseIP(t); ip != nil {
		for _, blocked := range blockedCIDRs {
			if blocked.Contains(ip) {
				return fmt.Errorf("blocked internal/loopback/metadata IP: %q", target)
			}
		}
		return nil
	}

	if safeDomainRe.MatchString(t) {
		return nil
	}
	return fmt.Errorf("unrecognized or unsafe scan target: %q", target)
}

func containsFlag(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}

func isSingleHostTarget(target string) bool {
	t := strings.TrimSpace(target)
	if _, ipnet, err := net.ParseCIDR(t); err == nil {
		ones, bits := ipnet.Mask.Size()
		return ones == bits
	}
	if net.ParseIP(t) != nil {
		return true
	}
	return safeDomainRe.MatchString(t)
}

// Run wykonuje bezpieczny skan nmap z białą listą flag, --max-rate, --host-timeout i kontrolą okna czasowego.
func Run(ctx context.Context, targetCIDR string, profile contract.ScanProfile) ([]contract.HostResult, error) {
	if err := ValidateTarget(targetCIDR); err != nil {
		return nil, err
	}
	if err := ValidatePorts(profile.Ports); err != nil {
		return nil, err
	}
	safeFlags, err := ValidateNmapFlags(profile.NmapFlags)
	if err != nil {
		return nil, err
	}

	args := []string{"-oX", "-"}
	if profile.RateLimitPPS > 0 {
		args = append(args, "--max-rate", strconv.Itoa(profile.RateLimitPPS))
	}
	if !containsFlag(safeFlags, "--host-timeout") {
		args = append(args, "--host-timeout", "60s")
	}
	// Dla pojedynczego hosta/domeny (np. host.docker.internal lub host za firewallem ICMP) automatycznie dodajemy -Pn
	if isSingleHostTarget(targetCIDR) && !containsFlag(safeFlags, "-Pn") && !containsFlag(safeFlags, "-sn") {
		args = append(args, "-Pn")
	}
	// Automatyczne wsparcie IPv6
	if strings.Contains(targetCIDR, ":") && !containsFlag(safeFlags, "-6") {
		args = append(args, "-6")
	}
	// Automatyczne dodanie -sU jeśli specyfikacja portów zawiera porty UDP (U:...)
	if strings.Contains(profile.Ports, "U:") && !containsFlag(safeFlags, "-sU") {
		args = append(args, "-sU")
	}
	if profile.Ports != "" && profile.Ports != "top-1000" {
		args = append(args, "-p", profile.Ports)
	}
	args = append(args, safeFlags...)
	args = append(args, "--", targetCIDR)

	cmd := exec.CommandContext(ctx, "nmap", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		errDetail := strings.TrimSpace(stderr.String())
		if errDetail != "" {
			return nil, fmt.Errorf("nmap failed: %w (%s)", err, errDetail)
		}
		return nil, fmt.Errorf("nmap failed: %w", err)
	}

	var parsed nmapRun
	if err := xml.Unmarshal(out, &parsed); err != nil {
		return nil, fmt.Errorf("parse nmap xml: %w", err)
	}

	targetIsDomain := net.ParseIP(strings.TrimSpace(targetCIDR)) == nil && !strings.Contains(targetCIDR, "/")
	results := make([]contract.HostResult, 0, len(parsed.Hosts))
	for _, h := range parsed.Hosts {
		ip := ""
		for _, a := range h.Addresses {
			if a.AddrType == "ipv4" || a.AddrType == "ipv6" {
				ip = a.Addr
				break
			}
		}
		if ip == "" {
			continue
		}
		var hostname *string
		if len(h.Hostnames) > 0 && h.Hostnames[0].Name != "" {
			name := h.Hostnames[0].Name
			hostname = &name
		} else if targetIsDomain {
			name := strings.TrimSpace(targetCIDR)
			hostname = &name
		}
		// Przekazujemy jawnie zamknięte/filtrowane porty dla ograniczonych list portów (<= 100),
		// aby backend mógł natychmiast wykryć zniknięcie pojedynczej usługi na żywym hoście (TCP RST).
		includeClosedPorts := len(h.Ports) <= 100
		services := make([]contract.ServiceResult, 0, len(h.Ports))
		for _, p := range h.Ports {
			rawState := strings.ToLower(strings.TrimSpace(p.State.State))
			var state string
			switch rawState {
			case "open":
				state = "open"
			case "closed":
				state = "closed"
			case "filtered", "open|filtered", "closed|filtered":
				state = "filtered"
			default:
				continue
			}
			if state != "open" && !includeClosedPorts {
				continue
			}
			normalizedName := normalizeServiceName(p.Service.Name, p.Service.Tunnel)
			svcName := strPtrOrNil(normalizedName)
			prod := strPtrOrNil(p.Service.Product)
			ver := strPtrOrNil(p.Service.Version)
			banner := buildServiceBanner(p.Service, p.Scripts)
			services = append(services, contract.ServiceResult{
				Port:             p.PortID,
				Protocol:         p.Protocol,
				State:            state,
				ServiceName:      svcName,
				Product:          prod,
				Version:          ver,
				Banner:           banner,
				SignatureMatches: []contract.SignatureMatch{},
			})
		}
		results = append(results, contract.HostResult{
			IP:       ip,
			Hostname: hostname,
			IsUp:     h.Status.State == "up",
			Services: services,
		})
	}
	return results, nil
}

func buildServiceBanner(svc nmapService, scripts []nmapScript) *string {
	for _, sc := range scripts {
		if sc.ID == "banner" && strings.TrimSpace(sc.Output) != "" {
			out := strings.TrimSpace(sc.Output)
			return &out
		}
	}
	var parts []string
	if svc.Product != "" {
		parts = append(parts, svc.Product)
	}
	if svc.Version != "" {
		parts = append(parts, svc.Version)
	}
	if svc.ExtraInfo != "" {
		parts = append(parts, "("+svc.ExtraInfo+")")
	}
	if svc.DeviceType != "" {
		parts = append(parts, "["+svc.DeviceType+"]")
	}
	if len(parts) == 0 {
		return nil
	}
	combined := strings.Join(parts, " ")
	return &combined
}

func normalizeServiceName(name, tunnel string) string {
	n := strings.TrimSpace(name)
	t := strings.ToLower(strings.TrimSpace(tunnel))
	if t == "ssl" {
		ln := strings.ToLower(n)
		if ln == "" || ln == "http" || ln == "http-alt" || ln == "http-proxy" {
			return "https"
		}
		if !strings.Contains(ln, "https") && !strings.HasPrefix(ln, "ssl/") {
			return "ssl/" + n
		}
	}
	return n
}

func strPtrOrNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
