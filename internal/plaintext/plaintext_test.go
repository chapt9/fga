package plaintext

import (
	"strings"
	"testing"
)

// TestPlainText is the regression test of the security review of 5
// November 2026, finding 4: labels and titles took bidirectional
// overrides, zero-width characters and C1 controls, which make one text
// read as another, or two texts look the same.
func TestPlainText(t *testing.T) {
	for _, s := range []string{"Dana's laptop, browser", "Temperature: past readings", "Grünhaus Nord", "温室の温度", "مستشعر الدفيئة",
		"ok 👍", strings.Repeat("é", 100)} {
		if !Line(s, 100) || !Text(s, 100) {
			t.Errorf("%q refused", s)
		}
	}
	if !Text("Past temperatures.\n\tNewest first.", 100) {
		t.Error("lines refused in text")
	}
	for name, s := range map[string]string{
		"empty":                    "",
		"too long":                 strings.Repeat("é", 101),
		"not UTF-8":                "laptop\xff",
		"a C0 control":             "laptop\x07",
		"DEL":                      "laptop\x7f",
		"a C1 control (NEL)":       "laptop\u0085",
		"a right-to-left override": "Dana's laptop\u202epot-pal",
		"a right-to-left isolate":  "Dana\u2067laptop\u2069",
		"a left-to-right mark":     "Dana\u200elaptop",
		"a zero-width space":       "read_climate\u200b",
		"a zero-width joiner":      "Dana\u200dlaptop",
		"a byte order mark":        "\ufeffDana's laptop",
		"a soft hyphen":            "lap\u00adtop",
		"a tag character":          "laptop\U000e0041",
		"a line separator":         "Climate\u2028latest",
		"a paragraph separator":    "Climate\u2029latest",
		"a carriage return":        "Climate\rlatest",
	} {
		if Line(s, 100) || Text(s, 100) {
			t.Errorf("%s: %q accepted", name, s)
		}
	}
	for _, s := range []string{"Climate:\nlatest", "Climate:\tlatest"} {
		if Line(s, 100) {
			t.Errorf("%q accepted as one line", s)
		}
	}
}
