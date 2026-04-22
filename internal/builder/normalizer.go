package builder

import (
	"net/url"
	"regexp"
	"sort"
	"strings"
)

var (
	reUUID    = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	reInt     = regexp.MustCompile(`^\d+$`)
	reHex     = regexp.MustCompile(`(?i)^[0-9a-f]{16,}$`)
	reToken   = regexp.MustCompile(`^[A-Za-z0-9\-_=+/]{20,}$`)
	reISO8601 = regexp.MustCompile(`T.*(?:Z|[+-]\d{2}:?\d{2})$`)
	// reFilename matches segments that end with a known document/binary file extension.
	// Deliberately excludes TLD-like suffixes (.com, .org, .io, etc.) so hostnames are unaffected.
	reFilename = regexp.MustCompile(`(?i)\.(pdf|docx?|xlsx?|pptx?|csv|txt|zip|tar|gz|png|jpe?g|gif|svg|mp4|mov|avi|mp3|wav|webm|json|xml|html?)$`)
)

// NormalizeURL replaces dynamic path/query segments with placeholders
// for stable grouping across requests to the same logical endpoint.
func NormalizeURL(rawURL string) string {
	qIdx := strings.IndexByte(rawURL, '?')
	rawPath := rawURL
	rawQuery := ""
	if qIdx >= 0 {
		rawPath = rawURL[:qIdx]
		rawQuery = rawURL[qIdx+1:]
	}

	// Normalize path segments.
	segments := strings.Split(rawPath, "/")
	for i, seg := range segments {
		if seg == "" {
			continue
		}
		switch {
		case reUUID.MatchString(seg):
			segments[i] = "{uuid}"
		case reInt.MatchString(seg):
			segments[i] = "{id}"
		case reHex.MatchString(seg):
			segments[i] = "{hash}"
		case reToken.MatchString(seg):
			segments[i] = "{token}"
		case reFilename.MatchString(seg):
			segments[i] = "{filename}"
		}
	}
	normalizedPath := strings.Join(segments, "/")

	if rawQuery == "" {
		return normalizedPath
	}

	// Normalize and sort query params.
	params, err := url.ParseQuery(rawQuery)
	if err != nil {
		return normalizedPath + "?" + rawQuery
	}

	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var parts []string
	for _, k := range keys {
		for _, v := range params[k] {
			parts = append(parts, k+"="+normalizeQueryValue(v))
		}
	}
	return normalizedPath + "?" + strings.Join(parts, "&")
}

func normalizeQueryValue(v string) string {
	switch {
	case reUUID.MatchString(v):
		return "{uuid}"
	case reInt.MatchString(v):
		return "{number}"
	case reISO8601.MatchString(v):
		return "{timestamp}"
	case reToken.MatchString(v):
		return "{token}"
	default:
		return v
	}
}
