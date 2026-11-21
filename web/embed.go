//go:build embedui

// Package web holds the built React UI. With the embedui build tag the
// content of web/dist is embedded in the binary.
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// Embedded reports whether the UI is compiled into this binary.
const Embedded = true

// FS returns the built UI rooted at the dist directory (index.html at the root).
func FS() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		panic(err)
	}
	return sub
}
