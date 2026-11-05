// Package plaintext checks text an administrator sets that fga shows to
// other administrators, to people and to agents: a sign-in key's label, a
// data tool's title and descriptions. Such text is valid UTF-8 with no
// control characters (Cc, C0 and C1 alike) and no format characters
// (Cf): no bidirectional overrides or isolates, no zero-width or other
// invisible characters, so what one person reads is what another wrote
// (security review of 5 November 2026, finding 4). One line also holds no
// line or paragraph separators.
package plaintext

import (
	"unicode"
	"unicode/utf8"
)

// Line reports whether s is one line of plain text of 1 to max
// characters.
func Line(s string, max int) bool { return plain(s, max, false) }

// Text reports whether s is plain text of 1 to max characters, in lines:
// line feeds and tabs are allowed too.
func Text(s string, max int) bool { return plain(s, max, true) }

func plain(s string, max int, lines bool) bool {
	if !utf8.ValidString(s) {
		return false
	}
	n := 0
	for _, r := range s {
		if n++; n > max {
			return false
		}
		switch {
		case lines && (r == '\n' || r == '\t'):
		case unicode.In(r, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp):
			return false
		}
	}
	return n > 0
}
