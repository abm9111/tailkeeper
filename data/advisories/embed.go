// Package advisories holds the reviewed advisory files of this directory, embedded in the
// binary. It decodes nothing: internal/advisory reads Files with its checked decoder and
// merges what it finds into the one catalog the scan judges by. A file is part of the
// release when its name ends in .json and it sits directly in this directory; testdata and
// the README are not embedded.
package advisories

import "embed"

// Files is the set of catalog files shipped with the binary.
//
//go:embed *.json
var Files embed.FS
