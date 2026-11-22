package api

import "github.com/iwosmu/aghpen/internal/i18n"

// ErrorMessageIn returns an error message of the API in lang.
func ErrorMessageIn(msg, lang string) string { return i18n.ErrorMessage(msg, lang) }
