package analyze

import "github.com/iwosmu/aghpen/internal/model"

// kindLabelPL is the one table of change kind labels on the server (the
// report and the webhook). It follows the labels of the UI.
var kindLabelPL = map[model.ChangeKind]string{
	model.ChangeHostNew: "nowy host", model.ChangeHostBack: "host wrócił", model.ChangeHostGone: "host nieaktywny",
	model.ChangeHostMissing: "host nie odpowiada (niepotwierdzone)", model.ChangeHostUnstable: "host niestabilny",
	model.ChangeServiceNew: "nowa usługa", model.ChangeServiceGone: "usługa zniknęła", model.ChangeServiceReturned: "usługa wróciła",
	model.ChangeServiceUnreachable: "usługa nie odpowiada (niepotwierdzone)", model.ChangeServiceChanged: "usługa zmieniona",
	model.ChangeResponseSlower: "usługa odpowiada wolniej", model.ChangeResponseRecovered: "usługa znów szybka",
	model.ChangeTechNew: "nowa technologia", model.ChangeTechGone: "technologia zniknęła", model.ChangeTechVersion: "zmiana wersji",
	model.ChangeTitle: "zmiana tytułu", model.ChangeHTTPStatus: "zmiana kodu HTTP", model.ChangeCert: "zmiana certyfikatu",
	model.ChangeHeaders: "zmiana nagłówków", model.ChangeCookies: "zmiana ciasteczek", model.ChangeContent: "zmiana treści",
	model.ChangeRedirect: "zmiana przekierowania", model.ChangeClass: "zmiana klasy",
}

// KindLabel is the short label of a change kind; the kind itself when unknown.
func KindLabel(k model.ChangeKind) string {
	if l, ok := kindLabelPL[k]; ok {
		return l
	}
	return string(k)
}
