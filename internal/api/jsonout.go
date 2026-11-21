package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"reflect"
	"time"

	"github.com/iwosmu/aghpen/internal/auth"
	"github.com/iwosmu/aghpen/internal/model"
)

var (
	timeType      = reflect.TypeOf(time.Time{})
	marshalerType = reflect.TypeOf((*json.Marshaler)(nil)).Elem()
	rawType       = reflect.TypeOf(json.RawMessage{})
	zeroTimeJSON  = []byte(`"0001-01-01T00:00:00Z"`)
)

// encodeJSON is the one JSON encoding of every API response and SSE event:
//
//   - a nil slice serialises as [] and never as null, so a client can always
//     iterate an array field (a copy of the value is normalised; the caller's
//     data is not touched);
//   - a zero time.Time serialises as null and not as "0001-01-01T00:00:00Z".
func encodeJSON(v any) ([]byte, error) {
	b, err := json.Marshal(nonNilSlices(v))
	if err != nil {
		return nil, err
	}
	return bytes.ReplaceAll(b, zeroTimeJSON, []byte("null")), nil
}

// nonNilSlices returns a deep copy of v in which every nil slice is an empty slice.
func nonNilSlices(v any) any {
	if v == nil {
		return nil
	}
	rv := reflect.ValueOf(v)
	cp := reflect.New(rv.Type()).Elem()
	cp.Set(fixSlices(rv, 0))
	return cp.Interface()
}

func skipType(t reflect.Type) bool {
	return t == timeType || t == rawType || (t.Kind() != reflect.Pointer && t.Kind() != reflect.Interface && t.Implements(marshalerType))
}

// fixSlices returns a copy of v with nil slices replaced; it never mutates v.
func fixSlices(v reflect.Value, depth int) reflect.Value {
	if depth > 40 || !v.IsValid() || skipType(v.Type()) {
		return v
	}
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			return v
		}
		p := reflect.New(v.Type().Elem())
		p.Elem().Set(fixSlices(v.Elem(), depth+1))
		return p
	case reflect.Interface:
		if v.IsNil() {
			return v
		}
		out := reflect.New(v.Type()).Elem()
		out.Set(fixSlices(v.Elem(), depth+1))
		return out
	case reflect.Struct:
		out := reflect.New(v.Type()).Elem()
		out.Set(v)
		for i := 0; i < v.NumField(); i++ {
			f := v.Type().Field(i)
			if !f.IsExported() || f.Tag.Get("json") == "-" {
				continue
			}
			out.Field(i).Set(fixSlices(v.Field(i), depth+1))
		}
		return out
	case reflect.Slice:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return v // []byte is base64 text, not an array
		}
		if v.IsNil() {
			return reflect.MakeSlice(v.Type(), 0, 0)
		}
		out := reflect.MakeSlice(v.Type(), v.Len(), v.Len())
		for i := 0; i < v.Len(); i++ {
			out.Index(i).Set(fixSlices(v.Index(i), depth+1))
		}
		return out
	case reflect.Array:
		out := reflect.New(v.Type()).Elem()
		for i := 0; i < v.Len(); i++ {
			out.Index(i).Set(fixSlices(v.Index(i), depth+1))
		}
		return out
	case reflect.Map:
		if v.IsNil() {
			return v
		}
		out := reflect.MakeMapWithSize(v.Type(), v.Len())
		it := v.MapRange()
		for it.Next() {
			out.SetMapIndex(it.Key(), fixSlices(it.Value(), depth+1))
		}
		return out
	}
	return v
}

// WriteJSON writes v as a JSON response with the encoding rules of the API
// (encodeJSON). Sub-routers mounted through Deps.Mounts use it.
func WriteJSON(w http.ResponseWriter, status int, v any) { writeJSON(w, status, v) }

// WriteError writes the API error envelope {"error": {"code", "message"}}.
func WriteError(w http.ResponseWriter, status int, code, msg string) { writeErr(w, status, code, msg) }

// Guard returns the middleware that lets a request through only when its
// principal holds perm (401 without a session, 403 without the permission).
// A sub-router takes it as a parameter, see Mount.
type Guard func(perm model.Permission) func(http.Handler) http.Handler

// Mount is a sub-router of another package. It is mounted under
// /api/v1 + Pattern behind the session, CSRF and audit middleware of the API;
// Router builds it with the permission Guard of this server.
type Mount struct {
	Pattern string // for example "/timeline"
	Router  func(guard Guard) http.Handler
}

// Guard returns the permission middleware of this server.
func (s *Server) Guard() Guard {
	return func(p model.Permission) func(http.Handler) http.Handler { return auth.Require(p, s.authFail) }
}
