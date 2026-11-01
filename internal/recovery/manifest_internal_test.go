package recovery

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// TestManifestTablesMustMatch covers fga-audit F-17: restore empties every
// table of Tables and loads those the manifest names, so a manifest that
// leaves one out or adds one is refused before any table is touched.
func TestManifestTablesMustMatch(t *testing.T) {
	read := func(names []string) error {
		dir := t.TempDir()
		m := Manifest{Format: Format}
		for _, n := range names {
			m.Tables = append(m.Tables, FileEntry{Name: n, File: n + ".copy"})
		}
		b, _ := json.Marshal(m)
		if err := os.WriteFile(filepath.Join(dir, "manifest.json"), b, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := ReadManifest(dir, nil)
		return err
	}
	for name, names := range map[string][]string{
		"a table left out": Tables[:len(Tables)-1],
		"a table added":    append(slices.Clone(Tables), "pg_authid"),
		"tables reordered": append([]string{Tables[1], Tables[0]}, Tables[2:]...),
	} {
		if err := read(names); err == nil || err.Error() != "recovery: the backup's tables are not this version's; restore it with the version that took it" {
			t.Errorf("%s: %v", name, err)
		}
	}
	// The same tables pass this check and go on to the file digests.
	if err := read(Tables); err == nil || err.Error() == "recovery: the backup's tables are not this version's; restore it with the version that took it" {
		t.Errorf("this version's tables: %v", err)
	}
}
