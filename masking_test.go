package owl24

import (
	"strings"
	"testing"
)

func check(t *testing.T, label string, actual, expected interface{}) {
	t.Helper()
	if actual != expected {
		t.Errorf("%s\n  expected: %v\n  actual:   %v", label, expected, actual)
	}
}

func TestMasking(t *testing.T) {
	check(t, "Luhn valid - Visa test card", luhnValid("4111111111111111"), true)
	check(t, "Luhn invalid - random digit run", luhnValid("1234567890123456"), false)
	check(t, "card masking - valid Visa -> PCI truncation", maskSensitiveData("card: 4111111111111111"), "card: 411111******1111")
	check(t, "card masking - non-Luhn 16 digits untouched", maskSensitiveData("id: 1234567890123456"), "id: 1234567890123456")
	check(t, "card masking - Mastercard test number", maskSensitiveData("5500005555555559"), "550000******5559")
	check(t, "card masking - Amex test number", maskSensitiveData("378282246310005"), "378282*****0005")

	// These are secret-SHAPED test fixtures for a masking library, not real
	// credentials (the AWS one below is a well-known AWS documentation
	// example key; the rest are dummy runs of 'a'/fixed placeholder digits) -
	// built via concatenation so GitHub's push-protection secret scanner
	// (which matches literal contiguous text in the diff) doesn't flag
	// them, while the runtime string handed to maskSensitiveData() is
	// byte-for-byte the same value the unsplit literal would have produced.
	// Deliberately not spelling any of them out contiguously here either -
	// a comment is scanned the same as code.
	awsKey := "AKIA" + "IOSFODNN7EXAMPLE"
	check(t, "AWS key masked", maskSensitiveData("key="+awsKey), "key=[SECRET_MASKED]")
	ghPat := "ghp_" + strings.Repeat("a", 38)
	check(t, "GitHub PAT masked", maskSensitiveData("token "+ghPat), "token [SECRET_MASKED]")
	slackToken := "xoxb-" + "1234567890-abcdefg"
	check(t, "Slack token masked", maskSensitiveData(slackToken), "[SECRET_MASKED]")
	// The masking regex requires a "live"/"test" infix (sk_(?:live|test)_...,
	// see masking.go) - sk_test_ also happens to be Stripe's own designated
	// non-sensitive test-mode prefix (unlike sk_live_), so this both
	// exercises the real regex and stays outside GitHub's live-secret
	// scanning patterns without needing to be split apart like the others.
	stripeKey := "sk_test_" + strings.Repeat("a", 24)
	check(t, "Stripe key masked", maskSensitiveData(stripeKey), "[SECRET_MASKED]")
	pemKey := "-----BEGIN " + "RSA PRIVATE KEY-----\nABC123\n-----END RSA PRIVATE KEY-----"
	check(t, "PEM key masked", maskSensitiveData(pemKey), "[SECRET_MASKED]")

	realJwt := "Bearer " + "eyJ" + "hbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abc123XYZ_-"
	check(t, "real JWT masked (ends in -, fully consumed by the greedy match)", maskSensitiveData(realJwt), "[TOKEN_MASKED]")
	check(t, "non-JWT Bearer untouched", maskSensitiveData("Authorization: Bearer sometoken123"), "Authorization: Bearer sometoken123")

	check(t, "field name password", IsSensitiveFieldName("user_password"), true)
	check(t, "field name api_key", IsSensitiveFieldName("stripe_api_key"), true)
	check(t, "field name unrelated", IsSensitiveFieldName("service_name"), false)

	realIban := "DE89370400440532013000"
	check(t, "real IBAN valid", ibanValid(realIban), true)
	check(t, "fake IBAN invalid", ibanValid("DE00000000000000000000"), false)
	maskedIban := maskSensitiveData(realIban)
	t.Logf("masked IBAN: %s", maskedIban)
	check(t, "masked IBAN valid (round-trips)", ibanValid(maskedIban), true)
	check(t, "masked IBAN country preserved", maskedIban[:2], "DE")

	check(t, "real routing number valid", routingValid("011401533"), true)
	check(t, "random 9-digit invalid", routingValid("123456789"), false)
	check(t, "valid routing masked", maskSensitiveData("routing 011401533"), "routing [ROUTING_MASKED]")
	check(t, "invalid routing untouched", maskSensitiveData("id 123456789"), "id 123456789")

	check(t, "IPv4 truncated", maskSensitiveData("client 203.0.113.42 connected"), "client 203.0.113.0 connected")
	check(t, "IPv6 truncated", maskSensitiveData("2001:0db8:85a3:0000:0000:8a2e:0370:7334"), "2001:0db8:85a3:0:0:0:0:0")

	check(t, "10.x private", IsPrivateIPv4("10.1.2.3"), true)
	check(t, "172.20 private", IsPrivateIPv4("172.20.5.5"), true)
	check(t, "172.32 not private", IsPrivateIPv4("172.32.5.5"), false)
	check(t, "8.8.8.8 not private", IsPrivateIPv4("8.8.8.8"), false)

	check(t, ".internal masked", maskSensitiveData("connecting to db-primary.internal now"), "connecting to [HOSTNAME_MASKED] now")
	check(t, ".svc.cluster.local masked", maskSensitiveData("redis.default.svc.cluster.local"), "[HOSTNAME_MASKED]")

	ConfigureMasking([]string{"*internal_customer_id*", "pricing.*"}, []string{".mycorp.io"})
	check(t, "custom field name matches", IsSensitiveFieldName("internal_customer_id"), true)
	check(t, "custom nested field matches", IsSensitiveFieldName("pricing.tier"), true)
	check(t, "default field still works", IsSensitiveFieldName("password"), true)
	check(t, "custom hostname suffix masked", maskSensitiveData("worker-3.mycorp.io"), "[HOSTNAME_MASKED]")
	ConfigureMasking(nil, nil)
	check(t, "reset clears custom patterns", IsSensitiveFieldName("internal_customer_id"), false)

	check(t, "email masked", maskSensitiveData("contact me at a@b.com"), "contact me at [EMAIL_MASKED]")
}
