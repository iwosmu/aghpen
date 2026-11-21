//go:build !embedui

// Package web holds the built React UI. Without the embedui build tag the
// binary carries no UI: FS returns an empty file system, so the Go build
// works before "npm run build" has produced web/dist.
package web

import (
	"io/fs"
	"testing/fstest"
)

// Embedded reports whether the UI is compiled into this binary.
const Embedded = false

// FS returns an empty file system.
func FS() fs.FS {
	return fstest.MapFS{}
}
