package owl24

// Task 8 (todolist.md), expanded 2026-08-23 from the original 4 bare
// regexes. Faithful port of owl24-js's masking.js (the reference
// implementation - see that file's own header for the full research/
// rationale behind every category here) - same detection categories, same
// masking formats, same tests translated to this language.

import (
	"regexp"
	"strconv"
	"strings"
)

// --- PCI-DSS payment cards -------------------------------------------
var cardCandidateRe = regexp.MustCompile(`\b(?:\d[ -]?){13,19}\b`)
var cardBrandRe = regexp.MustCompile(`^(4\d{12}(?:\d{3})?|5[1-5]\d{14}|2(?:22[1-9]|2[3-9]\d|[3-6]\d{2}|7[01]\d|720)\d{12}|3[47]\d{13}|6(?:011|5\d{2})\d{12})$`)

func luhnValid(digits string) bool {
	sum := 0
	alternate := false
	for i := len(digits) - 1; i >= 0; i-- {
		n := int(digits[i] - '0')
		if alternate {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		alternate = !alternate
	}
	return sum%10 == 0
}

// PCI DSS "truncation" convention: first 6 + last 4 visible, middle masked.
func maskCard(match string) string {
	digits := strings.NewReplacer(" ", "", "-", "").Replace(match)
	if !cardBrandRe.MatchString(digits) || !luhnValid(digits) {
		return match // not a real card - leave untouched
	}
	return digits[:6] + strings.Repeat("*", len(digits)-10) + digits[len(digits)-4:]
}

// --- Secrets & credentials --------------------------------------------
// Vendor-prefixed formats ported from gitleaks' config/gitleaks.toml (MIT).
var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`),
	regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}\b`),
	regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{22,}\b`),
	// No trailing \b, same reasoning as the JWT pattern below: the token
	// body's character class includes '-', a non-\w character, so a token
	// ending in '-' would fail a trailing \b. A bare greedy repetition with
	// no trailing assertion already stops at the first non-matching
	// character on its own.
	regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}`),
	regexp.MustCompile(`\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b`),
	regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----`),
}

// Tightened from "Bearer + anything JWT-shaped" to the real structure (eyJ
// prefix + 3 dot-separated base64url segments). No trailing \b: base64url's
// alphabet includes '-'/'_', which aren't \w characters, so a segment that
// happens to end in one would fail a trailing \b assertion (the real bug
// found and fixed in the JS reference implementation - verified with a
// real test JWT ending in '-'). A bare greedy `+` with no trailing
// assertion already stops at the first non-matching character on its own,
// so dropping \b entirely is the correct fix here, not just a workaround -
// Go's RE2 has no lookahead to express it the other three languages' way,
// but doesn't need one.
var bearerJwtRe = regexp.MustCompile(`\bBearer\s+eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)

// --- Financial / banking -------------------------------------------------
var ibanCandidateRe = regexp.MustCompile(`\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b`)

func mod97(numeric string) int {
	remainder := 0
	for _, c := range numeric {
		remainder = (remainder*10 + int(c-'0')) % 97
	}
	return remainder
}

func ibanNumeric(iban string) string {
	rearranged := iban[4:] + iban[:4]
	var sb strings.Builder
	for _, c := range rearranged {
		if c >= 'A' && c <= 'Z' {
			sb.WriteString(strconv.Itoa(int(c) - 55))
		} else {
			sb.WriteRune(c)
		}
	}
	return sb.String()
}

func ibanValid(iban string) bool {
	return mod97(ibanNumeric(iban)) == 1
}

// Masks by preserving the country code and regenerating a valid checksum on
// an all-zero masked body, so the result still round-trips as a
// structurally valid IBAN (dlpx-core's IBAN masking pattern).
func maskIban(match string) string {
	iban := strings.ToUpper(match)
	if !ibanValid(iban) {
		return match // not a real IBAN - leave untouched
	}
	country := iban[:2]
	bban := strings.Repeat("0", len(iban)-4)
	remainder := mod97(ibanNumeric(country + "00" + bban))
	checkDigits := strconv.Itoa(98 - remainder)
	if len(checkDigits) < 2 {
		checkDigits = "0" + checkDigits
	}
	return country + checkDigits + bban
}

// US routing numbers: 9 digits, weighted (3,7,1 repeating) checksum.
var routingCandidateRe = regexp.MustCompile(`\b\d{9}\b`)
var routingWeights = [9]int{3, 7, 1, 3, 7, 1, 3, 7, 1}

func routingValid(digits string) bool {
	sum := 0
	for i := 0; i < 9; i++ {
		sum += int(digits[i]-'0') * routingWeights[i]
	}
	return sum%10 == 0
}

// --- Location / geolocation ---------------------------------------------
// IPv4: zero the last octet. IPv6: keep the first 48 bits, zero the rest -
// both match Google Analytics' old anonymizeIp.
var ipv4Re = regexp.MustCompile(`\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b`)
var ipv6Re = regexp.MustCompile(`\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b`)

func truncateIpv4(match string) string {
	parts := strings.Split(match, ".")
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n > 255 {
			return match
		}
	}
	return parts[0] + "." + parts[1] + "." + parts[2] + ".0"
}

func truncateIpv6(match string) string {
	groups := strings.Split(match, ":")
	return strings.Join(append(groups[:3], "0", "0", "0", "0", "0"), ":")
}

// --- Internal network topology -------------------------------------------
// RFC1918 (+loopback/link-local) via real numeric subnet math, not regex.
type privateRange struct {
	base string
	bits int
}

var privateIPv4Ranges = []privateRange{
	{"10.0.0.0", 8}, {"172.16.0.0", 12}, {"192.168.0.0", 16}, {"127.0.0.0", 8}, {"169.254.0.0", 16},
}

func ipv4ToUint32(ip string) uint32 {
	var result uint32
	for _, part := range strings.Split(ip, ".") {
		n, _ := strconv.Atoi(part)
		result = (result << 8) + uint32(n)
	}
	return result
}

// IsPrivateIPv4 reports whether ip falls in an RFC1918 (or loopback/
// link-local) range, via real numeric subnet math.
func IsPrivateIPv4(ip string) bool {
	ipInt := ipv4ToUint32(ip)
	for _, r := range privateIPv4Ranges {
		var mask uint32
		if r.bits != 0 {
			mask = uint32(0xFFFFFFFF << (32 - r.bits))
		}
		if (ipInt & mask) == (ipv4ToUint32(r.base) & mask) {
			return true
		}
	}
	return false
}

// Hostnames/internal DNS/cluster names have no universal spec - a small
// default suffix denylist, extended via ConfigureMasking().
var defaultInternalHostnameSuffixes = []string{".internal", ".svc.cluster.local", ".corp"}

func buildHostnameSuffixRes(suffixes []string) []*regexp.Regexp {
	res := make([]*regexp.Regexp, 0, len(suffixes))
	for _, suffix := range suffixes {
		res = append(res, regexp.MustCompile(`(?i)\b[\w-]+(?:\.[\w-]+)*`+regexp.QuoteMeta(suffix)+`\b`))
	}
	return res
}

// --- Customer-configurable field-name allow/deny list ---------------------
// Denylist-default (mask only what's configured, everything else passes
// through), not allowlist-default - matches owl24-js's decision: owl24's
// "one line of code, 5-minute setup" pitch doesn't work if a customer has
// to enumerate every safe field up front.
var defaultSensitiveFieldNamePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)password`), regexp.MustCompile(`(?i)secret`), regexp.MustCompile(`(?i)token`),
	regexp.MustCompile(`(?i)api[_-]?key`), regexp.MustCompile(`(?i)credential`), regexp.MustCompile(`(?i)authorization`),
	regexp.MustCompile(`(?i)\bssn\b`), regexp.MustCompile(`(?i)social[_-]?security`), regexp.MustCompile(`(?i)\bpin\b`),
	regexp.MustCompile(`(?i)\bbalance\b`), regexp.MustCompile(`(?i)account[_-]?number`),
	regexp.MustCompile(`(?i)routing[_-]?number`), regexp.MustCompile(`(?i)credit[_-]?score`),
	regexp.MustCompile(`(?i)\bdob\b`), regexp.MustCompile(`(?i)date[_-]?of[_-]?birth`),
}

var customFieldNamePatterns []*regexp.Regexp
var hostnameSuffixRes = buildHostnameSuffixRes(defaultInternalHostnameSuffixes)

func compileWildcard(pattern string) *regexp.Regexp {
	parts := strings.Split(pattern, "*")
	quoted := make([]string, len(parts))
	for i, p := range parts {
		quoted[i] = regexp.QuoteMeta(p)
	}
	return regexp.MustCompile(`(?i)^` + strings.Join(quoted, ".*") + `$`)
}

// ConfigureMasking lets a customer extend (not replace) the default
// sensitive-field-name list and the internal-hostname suffix list.
// maskFields accepts exact names or '*'-wildcard patterns (e.g.
// "*api_key*", "pricing.*", "internal_customer_id"). Call before Init(),
// or any time afterward to change behavior live.
func ConfigureMasking(maskFields []string, internalHostnameSuffixes []string) {
	compiled := make([]*regexp.Regexp, 0, len(maskFields))
	for _, f := range maskFields {
		compiled = append(compiled, compileWildcard(f))
	}
	customFieldNamePatterns = compiled

	suffixes := append([]string{}, defaultInternalHostnameSuffixes...)
	suffixes = append(suffixes, internalHostnameSuffixes...)
	hostnameSuffixRes = buildHostnameSuffixRes(suffixes)
}

// IsSensitiveFieldName reports whether name (an attribute/log-field name)
// should have its value masked wholesale, regardless of shape.
func IsSensitiveFieldName(name string) bool {
	for _, re := range defaultSensitiveFieldNamePatterns {
		if re.MatchString(name) {
			return true
		}
	}
	for _, re := range customFieldNamePatterns {
		if re.MatchString(name) {
			return true
		}
	}
	return false
}

// Order matters (see owl24-js's masking.js for the full story of why):
// vendor-prefixed/checksum-gated patterns must run BEFORE the generic
// phone pattern, or phone's boundary-bounded-but-still-generic digit match
// can claim a 10-digit body out of a hyphen-delimited secret token before
// the secret pattern gets a chance to match the whole span.
var phoneRe = regexp.MustCompile(`\b(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b`)
var emailRe = regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)

// maskSensitiveData is value-based masking - runs regardless of field
// name, since these formats are identifiable from their own shape wherever
// they appear.
func maskSensitiveData(text string) string {
	masked := emailRe.ReplaceAllString(text, "[EMAIL_MASKED]")

	for _, re := range secretPatterns {
		masked = re.ReplaceAllString(masked, "[SECRET_MASKED]")
	}

	masked = bearerJwtRe.ReplaceAllString(masked, "[TOKEN_MASKED]")
	masked = cardCandidateRe.ReplaceAllStringFunc(masked, maskCard)
	masked = ibanCandidateRe.ReplaceAllStringFunc(masked, maskIban)
	masked = routingCandidateRe.ReplaceAllStringFunc(masked, func(m string) string {
		if routingValid(m) {
			return "[ROUTING_MASKED]"
		}
		return m
	})
	masked = ipv4Re.ReplaceAllStringFunc(masked, truncateIpv4)
	masked = ipv6Re.ReplaceAllStringFunc(masked, truncateIpv6)

	for _, re := range hostnameSuffixRes {
		masked = re.ReplaceAllString(masked, "[HOSTNAME_MASKED]")
	}

	masked = phoneRe.ReplaceAllString(masked, "[PHONE_MASKED]")

	return masked
}
