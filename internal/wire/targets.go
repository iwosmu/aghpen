package wire

import (
	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/targets"
)

// TargetParser is api.TargetParser over internal/targets: IP, CIDR, ranges,
// IPv6, domains, CSV and JSON files, exclusion counting.
type TargetParser struct{}

// ParseText parses one target per line.
func (TargetParser) ParseText(text string) ([]model.Target, []model.InvalidLine) {
	r := targets.ParseText(text)
	return r.Targets, r.Invalid
}

// ParseFile parses a CSV or JSON target file.
func (TargetParser) ParseFile(name string, data []byte) ([]model.Target, []model.InvalidLine, error) {
	r, err := targets.ParseFile(name, data)
	return r.Targets, r.Invalid, err
}

// Excluded counts the addresses that the exclusions remove.
func (TargetParser) Excluded(ts []model.Target, exclusions []string) int64 {
	_, ex := targets.Count(ts, exclusions)
	return ex
}
