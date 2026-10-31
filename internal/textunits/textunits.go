// Package textunits is the text ingestion profile fga.text/nfc-paragraphs-v1
// (DOC-004): it normalizes UTF-8 text to NFC and splits it into paragraph
// units. The client SDK applies it before encrypting in client mode; the
// storage role applies it to uploaded text in server mode (D-12), so both
// modes split the same text into the same units. It holds no cryptography.
package textunits

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"fga/internal/cryptowire"
)

// NormalizationVersion names the profile; it is recorded in the manifest.
const NormalizationVersion = "fga.text/nfc-paragraphs-v1"

// MaxText bounds the text Split accepts.
const MaxText = 64 << 20

// ErrText is returned for text the profile refuses.
var ErrText = errors.New("textunits: text must be valid UTF-8 of at most 64 MiB")

// Split normalizes text to NFC and splits it into paragraphs at blank
// lines. Empty paragraphs are dropped; paragraphs keep their inner line
// breaks. Text that is not valid UTF-8, too large, empty, or that yields
// more than cryptowire.MaxUnits paragraphs is refused.
func Split(text []byte) ([]string, error) {
	if len(text) > MaxText || !utf8.Valid(text) {
		return nil, ErrText
	}
	normalized := strings.ReplaceAll(norm.NFC.String(string(text)), "\r\n", "\n")
	var units []string
	for _, p := range strings.Split(normalized, "\n\n") {
		if p = strings.Trim(p, "\n"); strings.TrimSpace(p) != "" {
			units = append(units, p)
		}
	}
	if len(units) == 0 || len(units) > cryptowire.MaxUnits {
		return nil, fmt.Errorf("%w: it yields %d units; between 1 and %d are allowed", ErrText, len(units), cryptowire.MaxUnits)
	}
	return units, nil
}
