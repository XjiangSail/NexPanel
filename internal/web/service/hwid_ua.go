package service

import (
	"regexp"
	"strings"
)

var (
	androidVersionRE = regexp.MustCompile(`android[\s/]+([0-9]+(?:\.[0-9]+)*)`)
	iosVersionRE     = regexp.MustCompile(`os ([0-9_]+) like mac os x`)
	windowsVersionRE = regexp.MustCompile(`windows nt ([0-9.]+)`)
	macosVersionRE   = regexp.MustCompile(`mac os x[ /]([0-9_.]+)`)
)

// deviceMetaFromUserAgent infers the platform for clients that omit the
// X-Device-OS headers. Explicit headers always take precedence at the call site.
func deviceMetaFromUserAgent(ua string) (osName, osVersion string) {
	lower := strings.ToLower(ua)
	if lower == "" {
		return "", ""
	}
	switch {
	case strings.Contains(lower, "android"):
		return "Android", versionOf(androidVersionRE, lower)
	case strings.Contains(lower, "iphone"), strings.Contains(lower, "ipad"), strings.Contains(lower, "ipod"):
		return "iOS", versionOf(iosVersionRE, lower)
	case strings.Contains(lower, "windows nt"):
		return "Windows", versionOf(windowsVersionRE, lower)
	case strings.Contains(lower, "mac os x"), strings.Contains(lower, "macintosh"):
		return "macOS", versionOf(macosVersionRE, lower)
	case strings.Contains(lower, "linux"):
		return "Linux", ""
	}
	switch {
	case strings.Contains(lower, "v2rayng"),
		strings.Contains(lower, "nekobox"),
		strings.Contains(lower, "matsuri"),
		strings.Contains(lower, "sagernet"),
		strings.Contains(lower, "clashmetaforandroid"):
		return "Android", ""
	case strings.Contains(lower, "v2rayn"):
		return "Windows", ""
	case strings.Contains(lower, "shadowrocket"),
		strings.Contains(lower, "streisand"),
		strings.Contains(lower, "quantumult"),
		strings.Contains(lower, "stash"),
		strings.Contains(lower, "loon"):
		return "iOS", ""
	}
	return "", ""
}

func versionOf(re *regexp.Regexp, ua string) string {
	m := re.FindStringSubmatch(ua)
	if len(m) < 2 {
		return ""
	}
	return strings.ReplaceAll(m[1], "_", ".")
}
