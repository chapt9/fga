package main

import (
	"strconv"
	"testing"
)

// TestPrintable: a key that holds anything a terminal would act on is
// printed quoted (security review of 4 November 2026, finding 7).
func TestPrintable(t *testing.T) {
	esc, bell, rlo, tab, cr := string(rune(0x1b)), string(rune(7)), string(rune(0x202e)), string(rune(9)), string(rune(13))
	for _, in := range []string{"reports/q3.txt", "with space.txt", "umlaut-ü.txt"} {
		if got := printable(in); got != in {
			t.Errorf("printable(%q) = %s, want it unchanged", in, got)
		}
	}
	for _, in := range []string{"a" + esc + "]0;owned" + bell + "b", "x" + rlo + "y", "tab" + tab + "here", "line" + cr + "over"} {
		if got, want := printable(in), strconv.Quote(in); got != want {
			t.Errorf("printable(%q) = %s, want %s", in, got, want)
		}
	}
}
