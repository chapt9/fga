package content

import "fga/internal/registry"

// unitTypes are the resource type and operations of a document's units:
// the text units of a document, or the entries of a text collection
// (DOC-005), whose write action is update rather than share.
type unitTypes struct {
	typ, write                                                 string
	reuseOp, shareOp, selectOp, readOp, manifestOp, envelopeOp string
	// releaseOp releases a server-mode unit's data key (D-12).
	releaseOp string
}

var (
	textUnits = unitTypes{typ: "document.text_unit", write: "share", reuseOp: registry.OpDocReuseUnits, shareOp: registry.OpDocShareUnits,
		selectOp: registry.OpDocSelectUnits, readOp: registry.OpDocReadUnit, manifestOp: registry.OpDocManifest, envelopeOp: registry.OpDocGetUnitEnvelope,
		releaseOp: registry.OpKeyReleaseUnit}
	textEntries = unitTypes{typ: "text.entry", write: "update", reuseOp: registry.OpDocReuseEntries, shareOp: registry.OpDocShareEntries,
		selectOp: registry.OpDocSelectEntries, readOp: registry.OpDocReadEntry, manifestOp: registry.OpDocManifestEntries,
		envelopeOp: registry.OpDocGetEntryEnvelope, releaseOp: registry.OpKeyReleaseEntry}
)

// unitsOf returns the unit types of a document whose kind attribute is
// kind.
func unitsOf(kind string) unitTypes {
	if kind == "collection" {
		return textEntries
	}
	return textUnits
}
