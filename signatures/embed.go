// Package signatures holds the built-in signature library of Czujka.
// The YAML files are grouped by category and embedded in the binary.
// The DSL is described in docs/SIGNATURES.md; internal/sig parses it.
package signatures

import "embed"

// FS contains every built-in signature file: the hand-written ones (*.yaml in
// this directory) and the imported open corpora (community/*.yaml, generated
// by cmd/sigimport; see community/LICENSES.md).
//
//go:embed *.yaml community/*.yaml
var FS embed.FS
