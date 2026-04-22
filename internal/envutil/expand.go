package envutil

import (
	"os"
	"regexp"
)

var (
	bracedEnvRefPattern  = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)
	fullDollarEnvPattern = regexp.MustCompile(`^\$([A-Za-z_][A-Za-z0-9_]*)$`)
)

// Expand resolves environment variables while avoiding accidental mutation of
// arbitrary strings that merely contain '$'. It expands:
//  1. ${VAR} anywhere in the string
//  2. $VAR only when the full value is exactly "$VAR"
func Expand(value string) string {
	expanded, _, _ := ExpandWithStatus(value)
	return expanded
}

// ExpandWithStatus expands env references and returns metadata:
//   - hadEnvRef: whether the value contained any supported env reference
//   - unresolved: whether at least one referenced env var was unset
func ExpandWithStatus(value string) (expanded string, hadEnvRef bool, unresolved bool) {
	if value == "" {
		return value, false, false
	}

	expanded = bracedEnvRefPattern.ReplaceAllStringFunc(value, func(match string) string {
		hadEnvRef = true
		submatches := bracedEnvRefPattern.FindStringSubmatch(match)
		if len(submatches) != 2 {
			return match
		}
		if val, ok := os.LookupEnv(submatches[1]); ok {
			return val
		}
		unresolved = true
		return ""
	})

	if expanded != value {
		return expanded, hadEnvRef, unresolved
	}

	submatches := fullDollarEnvPattern.FindStringSubmatch(value)
	if len(submatches) == 2 {
		hadEnvRef = true
		if val, ok := os.LookupEnv(submatches[1]); ok {
			return val, hadEnvRef, unresolved
		}
		unresolved = true
		return "", hadEnvRef, unresolved
	}

	return value, hadEnvRef, unresolved
}

// ContainsEnvReference returns true when a value contains at least one supported
// environment-variable reference.
func ContainsEnvReference(value string) bool {
	if value == "" {
		return false
	}
	return bracedEnvRefPattern.MatchString(value) || fullDollarEnvPattern.MatchString(value)
}
