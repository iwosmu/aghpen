package sigwire

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/sig"
)

// ImportReport says what Import did with a signature file.
type ImportReport struct {
	Created    []string                  `json:"created"` // slugs of new custom signatures
	Updated    []string                  `json:"updated"` // slugs of custom signatures that were replaced
	Skipped    []ImportSkip              `json:"skipped"` // valid signatures that were not stored
	Validation model.SignatureValidation `json:"validation"`
}

// ImportSkip is one signature that Import did not store.
type ImportSkip struct {
	Slug   string `json:"slug"`
	Reason string `json:"reason"`
}

// Import stores every valid signature of a file as a custom row and reloads
// the engine. The file may hold many signatures in any accepted format:
// Czujka YAML, JSON, a list, a map keyed by name, passive nuclei templates.
// A signature that the validator refuses is not stored; the reasons are in
// Validation, and the other signatures of the file are still imported. A
// converted signature is stored as canonical Czujka YAML.
//
// A custom signature with the same id is replaced and keeps its enabled
// flag. A built-in signature is never replaced: that one is skipped.
func (w *Wire) Import(ctx context.Context, text, author string) (ImportReport, error) {
	sigs, val := sig.Parse(text)
	if val.Issues == nil {
		val.Issues = []model.SignatureIssue{}
	}
	if val.Paths == nil {
		val.Paths = []string{}
	}
	rep := ImportReport{Created: []string{}, Updated: []string{}, Skipped: []ImportSkip{}, Validation: val}
	seen := map[string]bool{}
	for _, s := range sigs {
		m := s.Model()
		m.Builtin, m.Enabled = false, true
		if m.Author == "" {
			m.Author = author
		}
		if seen[m.Slug] {
			rep.Skipped = append(rep.Skipped, ImportSkip{m.Slug, "plik zawiera drugą sygnaturę o tym samym id"})
			continue
		}
		seen[m.Slug] = true

		var id int64
		var builtin, enabled bool
		err := w.st.Pool().QueryRow(ctx, `SELECT id, builtin, enabled FROM signatures WHERE slug = $1`, m.Slug).Scan(&id, &builtin, &enabled)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			if _, err := w.st.CreateSignature(ctx, m); err != nil {
				return rep, fmt.Errorf("sigwire: import %s: %w", m.Slug, err)
			}
			rep.Created = append(rep.Created, m.Slug)
		case err != nil:
			return rep, fmt.Errorf("sigwire: import %s: %w", m.Slug, err)
		case builtin:
			rep.Skipped = append(rep.Skipped, ImportSkip{m.Slug, "sygnatura wbudowana o tym id już istnieje; zmień id, aby dodać własną"})
		default:
			m.ID, m.Enabled = id, enabled
			if _, err := w.st.UpdateSignature(ctx, m); err != nil {
				return rep, fmt.Errorf("sigwire: import %s: %w", m.Slug, err)
			}
			rep.Updated = append(rep.Updated, m.Slug)
		}
	}
	w.log.Info("signatures imported", "created", len(rep.Created), "updated", len(rep.Updated), "skipped", len(rep.Skipped), "valid", len(sigs), "file_ok", val.OK)
	if len(rep.Created)+len(rep.Updated) > 0 {
		if _, err := w.Reload(ctx); err != nil {
			return rep, err
		}
	}
	return rep, nil
}
