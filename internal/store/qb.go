package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/iwosmu/aghpen/internal/model"
)

// ListOpts are the paging and sorting options of every list endpoint.
type ListOpts struct {
	Limit  int
	Offset int
	Sort   string // field, or -field for descending
	Q      string // free text
}

const (
	defaultLimit = 50
	maxLimit     = 1000
)

func (o ListOpts) norm() ListOpts {
	if o.Limit <= 0 {
		o.Limit = defaultLimit
	}
	if o.Limit > maxLimit {
		o.Limit = maxLimit
	}
	if o.Offset < 0 {
		o.Offset = 0
	}
	return o
}

// where collects conditions written with ? placeholders.
type where struct {
	conds []string
	args  []any
}

func (w *where) add(cond string, args ...any) {
	var b strings.Builder
	i := 0
	for _, r := range cond {
		if r == '?' && i < len(args) {
			w.args = append(w.args, args[i])
			i++
			b.WriteString("$" + strconv.Itoa(len(w.args)))
			continue
		}
		b.WriteRune(r)
	}
	w.conds = append(w.conds, "("+b.String()+")")
}

func (w *where) sql() string {
	if len(w.conds) == 0 {
		return ""
	}
	return " WHERE " + strings.Join(w.conds, " AND ")
}

func like(q string) string {
	r := strings.NewReplacer("\\", "\\\\", "%", "\\%", "_", "\\_")
	return "%" + r.Replace(q) + "%"
}

// orderBy builds a safe ORDER BY clause from a client sort string. allowed
// maps API field names to SQL expressions; tie is appended to make the order stable.
func orderBy(sort string, allowed map[string]string, def, tie string) string {
	var parts []string
	for _, f := range strings.Split(sort, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		dir := "ASC"
		if strings.HasPrefix(f, "-") {
			dir, f = "DESC", f[1:]
		}
		if expr, ok := allowed[f]; ok {
			parts = append(parts, expr+" "+dir+" NULLS LAST")
		}
	}
	if len(parts) == 0 {
		parts = append(parts, def)
	}
	if tie != "" {
		parts = append(parts, tie)
	}
	return " ORDER BY " + strings.Join(parts, ", ")
}

func js(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("store: marshal %T: %v", v, err))
	}
	return b
}

// jsonRows runs a query whose single column is a JSON object and decodes every row into T.
func jsonRows[T any](ctx context.Context, q querier, sql string, args ...any) ([]T, error) {
	out := []T{}
	err := eachJSON(ctx, q, sql, args, func(v *T) error {
		out = append(out, *v)
		return nil
	})
	return out, err
}

func jsonRow[T any](ctx context.Context, q querier, sql string, args ...any) (T, error) {
	var v T
	var raw []byte
	if err := q.QueryRow(ctx, sql, args...).Scan(&raw); err != nil {
		return v, mapErr(err)
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return v, fmt.Errorf("store: decode %T: %w", v, err)
	}
	return v, nil
}

// eachJSON streams the rows of a query to fn without keeping them in memory.
func eachJSON[T any](ctx context.Context, q querier, sql string, args []any, fn func(*T) error) error {
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return mapErr(err)
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return err
		}
		var v T
		if err := json.Unmarshal(raw, &v); err != nil {
			return fmt.Errorf("store: decode %T: %w", v, err)
		}
		if err := fn(&v); err != nil {
			return err
		}
	}
	return mapErr(rows.Err())
}

func wrapJSON(inner string) string { return "SELECT row_to_json(t) FROM (" + inner + ") t" }

// listPage runs the count and the page query of one list endpoint.
// cols and from are SQL fragments; post is applied to every item (decryption).
func listPage[T any](ctx context.Context, q querier, cols, from string, w *where, order string, o ListOpts, post func(*T) error) (model.Page[T], error) {
	o = o.norm()
	page := model.Page[T]{Items: []T{}, Limit: o.Limit, Offset: o.Offset}
	if err := q.QueryRow(ctx, "SELECT count(*) FROM "+from+w.sql(), w.args...).Scan(&page.Total); err != nil {
		return page, mapErr(err)
	}
	if page.Total == 0 || o.Offset >= page.Total {
		return page, nil
	}
	sql := wrapJSON("SELECT " + cols + " FROM " + from + w.sql() + order + fmt.Sprintf(" LIMIT %d OFFSET %d", o.Limit, o.Offset))
	err := eachJSON(ctx, q, sql, w.args, func(v *T) error {
		if post != nil {
			if err := post(v); err != nil {
				return err
			}
		}
		page.Items = append(page.Items, *v)
		return nil
	})
	return page, err
}

// streamAll sends every matching row to fn in order, without paging.
func streamAll[T any](ctx context.Context, q querier, cols, from string, w *where, order string, post func(*T) error, fn func(*T) error) error {
	sql := wrapJSON("SELECT " + cols + " FROM " + from + w.sql() + order)
	return eachJSON(ctx, q, sql, w.args, func(v *T) error {
		if post != nil {
			if err := post(v); err != nil {
				return err
			}
		}
		return fn(v)
	})
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
