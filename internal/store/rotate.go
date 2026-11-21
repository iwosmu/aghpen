package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/iwosmu/aghpen/internal/crypto"
)

// encryptedColumn names one field-level encrypted column and the SQL
// expression that rebuilds the associated data of a row.
type encryptedColumn struct {
	table, pk, pkType, col, ad string
}

var encryptedColumns = []encryptedColumn{
	{"hosts", "id", "bigint", "note_enc", `'hosts|note|' || id`},
	{"services", "id", "bigint", "note_enc", `'services|note|' || id`},
	{"findings", "id", "bigint", "note_enc", `'findings|note|' || id`},
	{"findings", "id", "bigint", "evidence_enc", `'findings|evidence|' || key`},
	{"service_observations", "id", "bigint", "secret", `'service_observations|secret|' || service_id || '|' || run_id`},
	{"settings", "key", "text", "secret", `'settings|' || key`},
}

// EncryptedColumns lists "table.column" of every field-level encrypted column.
func EncryptedColumns() []string {
	out := make([]string, 0, len(encryptedColumns))
	for _, c := range encryptedColumns {
		out = append(out, c.table+"."+c.col)
	}
	return out
}

// RotateKeys re-wraps the data key of every ciphertext that is not under the
// current master key. The keyring must still hold the old key. It returns the
// number of re-wrapped values per "table.column". It is safe to run again.
func (s *Store) RotateKeys(ctx context.Context) (map[string]int, error) {
	done := map[string]int{}
	current := "czk1." + s.kr.CurrentID() + ".%"
	for _, c := range encryptedColumns {
		name := c.table + "." + c.col
		done[name] = 0
		for {
			type row struct {
				ID  string `json:"id"`
				Tok string `json:"tok"`
				AD  string `json:"ad"`
			}
			rows, err := jsonRows[row](ctx, s.db, wrapJSON(fmt.Sprintf(`SELECT %s::text AS id, %s AS tok, %s AS ad FROM %s WHERE %s <> '' AND %s NOT LIKE $1 ORDER BY %s LIMIT 1000`,
				c.pk, c.col, c.ad, c.table, c.col, c.col, c.pk)), current)
			if err != nil {
				return done, err
			}
			if len(rows) == 0 {
				break
			}
			for i := range rows {
				tok, changed, err := s.kr.Rewrap(rows[i].Tok, rows[i].AD)
				if err != nil {
					return done, fmt.Errorf("rotate %s %s: %w", name, rows[i].ID, err)
				}
				if !changed {
					return done, fmt.Errorf("rotate %s %s: token did not change", name, rows[i].ID)
				}
				rows[i].Tok = tok
			}
			tag, err := s.db.Exec(ctx, fmt.Sprintf(`UPDATE %s t SET %s = d.tok FROM jsonb_to_recordset($1::jsonb) AS d(id text, tok text) WHERE t.%s = d.id::%s`,
				c.table, c.col, c.pk, c.pkType), js(rows))
			if err != nil {
				return done, mapErr(err)
			}
			done[name] += int(tag.RowsAffected())
		}
	}
	return done, nil
}

// KeyUsage counts the stored ciphertexts per master key id.
func (s *Store) KeyUsage(ctx context.Context) (map[string]int, error) {
	out := map[string]int{}
	for _, c := range encryptedColumns {
		rows, err := s.db.Query(ctx, fmt.Sprintf(`SELECT split_part(%s, '.', 2), count(*) FROM %s WHERE %s <> '' GROUP BY 1`, c.col, c.table, c.col))
		if err != nil {
			return nil, mapErr(err)
		}
		for rows.Next() {
			var id string
			var n int
			if err := rows.Scan(&id, &n); err != nil {
				rows.Close()
				return nil, err
			}
			out[id] += n
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

const keyCheck = "keycheck"

// VerifyKeyring checks that the configured master key can read this database.
// The first start stores a small encrypted canary; later starts must decrypt
// it. A wrong CZUJKA_MASTER_KEY is so found at start, not at the first read.
func (s *Store) VerifyKeyring(ctx context.Context) error {
	var v map[string]any
	secret, _, err := s.getSetting(ctx, keyCheck, &v)
	if errors.Is(err, ErrNotFound) || (err == nil && secret == "") {
		tok, err := s.kr.EncryptString("czujka-key-check", "settings|"+keyCheck)
		if err != nil {
			return err
		}
		return s.putSetting(ctx, keyCheck, map[string]any{"purpose": "detects a wrong master key at start"}, tok)
	}
	if err != nil {
		return err
	}
	if _, err := s.kr.DecryptString(secret, "settings|"+keyCheck); err != nil {
		return fmt.Errorf("the master key does not match this database (data was encrypted with key id %s, the keyring has %v): %w",
			crypto.TokenKeyID(secret), s.kr.IDs(), err)
	}
	return nil
}
