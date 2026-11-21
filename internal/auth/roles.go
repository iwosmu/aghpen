package auth

import (
	"github.com/iwosmu/aghpen/internal/model"
)

// BuiltinRoles returns the four built-in roles of docs/ARCHITECTURE.md §6.
// They map to the roles that the challenge requires.
func BuiltinRoles() []model.Role {
	read := []model.Permission{model.PermTargetsRead, model.PermScansRead, model.PermResultsRead, model.PermSignaturesRead}
	analyst := append(append([]model.Permission{}, read...),
		model.PermTargetsUpdate, model.PermResultsUpdate, model.PermSignaturesUpdate, model.PermScansRun, model.PermExportRun,
		// Anyone who may start a scan may also stop all scans at once. Releasing
		// the stop (safety:manage) stays with the administrator.
		model.PermEmergencyStop)
	editor := append(append([]model.Permission{}, analyst...),
		model.PermTargetsCreate, model.PermTargetsDelete, model.PermResultsCreate, model.PermResultsDelete,
		model.PermSignaturesCreate, model.PermSignaturesDelete, model.PermScansConfigure)
	return []model.Role{
		{Slug: model.RoleAdmin, Name: "Administrator", Description: "Administracja: pełny dostęp, użytkownicy, role, polityka bezpieczeństwa", Builtin: true, Permissions: ordered(model.AllPermissions)},
		{Slug: model.RoleEditor, Name: "Edytor", Description: "Dodawanie, usuwanie, modyfikacja: cele, wyniki, sygnatury, konfiguracja i uruchamianie skanów, eksport", Builtin: true, Permissions: ordered(editor)},
		{Slug: model.RoleAnalyst, Name: "Analityk", Description: "Modyfikacja i odczyt: edycja celów, wyników i sygnatur, uruchamianie skanów, eksport", Builtin: true, Permissions: ordered(analyst)},
		{Slug: model.RoleViewer, Name: "Obserwator", Description: "Odczyt: tylko podgląd", Builtin: true, Permissions: ordered(read)},
	}
}

// ordered returns the permissions in the display order of model.AllPermissions.
func ordered(p []model.Permission) []model.Permission {
	set := map[model.Permission]bool{}
	for _, x := range p {
		set[x] = true
	}
	out := make([]model.Permission, 0, len(set))
	for _, x := range model.AllPermissions {
		if set[x] {
			out = append(out, x)
		}
	}
	return out
}

// PermissionInfo describes one permission for the role editor of the UI.
type PermissionInfo struct {
	Permission model.Permission `json:"permission"`
	Group      string           `json:"group"`
	LabelPL    string           `json:"label_pl"`
	LabelEN    string           `json:"label_en"`
}

// PermissionCatalog lists every permission with its group and labels.
func PermissionCatalog() []PermissionInfo {
	labels := map[model.Permission][3]string{
		model.PermTargetsRead:      {"targets", "Podgląd zakresów i celów", "View scopes and targets"},
		model.PermTargetsCreate:    {"targets", "Dodawanie celów", "Add targets"},
		model.PermTargetsUpdate:    {"targets", "Edycja celów", "Edit targets"},
		model.PermTargetsDelete:    {"targets", "Usuwanie celów", "Delete targets"},
		model.PermScansRead:        {"scans", "Podgląd skanów i profili", "View scans and profiles"},
		model.PermScansRun:         {"scans", "Uruchamianie, wstrzymywanie i anulowanie skanów", "Start, pause and cancel scans"},
		model.PermScansConfigure:   {"scans", "Konfiguracja profili i harmonogramów", "Configure profiles and schedules"},
		model.PermResultsRead:      {"results", "Podgląd wyników", "View results"},
		model.PermResultsUpdate:    {"results", "Edycja wyników, tagów i ustaleń", "Edit results, tags and findings"},
		model.PermResultsCreate:    {"results", "Dodawanie ustaleń i import wyników", "Add findings and import results"},
		model.PermResultsDelete:    {"results", "Usuwanie wyników", "Delete results"},
		model.PermSignaturesRead:   {"signatures", "Podgląd sygnatur", "View signatures"},
		model.PermSignaturesCreate: {"signatures", "Dodawanie sygnatur", "Add signatures"},
		model.PermSignaturesUpdate: {"signatures", "Edycja sygnatur", "Edit signatures"},
		model.PermSignaturesDelete: {"signatures", "Usuwanie sygnatur", "Delete signatures"},
		model.PermExportRun:        {"export", "Eksport danych i wysyłka do DefectDojo", "Export data and push to DefectDojo"},
		model.PermIntegrations:     {"admin", "Zarządzanie integracjami", "Manage integrations"},
		model.PermSafetyManage:     {"safety", "Polityka bezpieczeństwa i zwolnienie blokady", "Safety policy and release of the stop"},
		model.PermEmergencyStop:    {"safety", "Awaryjne zatrzymanie skanowania", "Emergency stop"},
		model.PermUsersManage:      {"admin", "Zarządzanie użytkownikami", "Manage users"},
		model.PermRolesManage:      {"admin", "Zarządzanie rolami", "Manage roles"},
		model.PermAuditRead:        {"admin", "Podgląd dziennika audytu", "View the audit log"},
	}
	out := make([]PermissionInfo, 0, len(model.AllPermissions))
	for _, p := range model.AllPermissions {
		l := labels[p]
		out = append(out, PermissionInfo{Permission: p, Group: l[0], LabelPL: l[1], LabelEN: l[2]})
	}
	return out
}

// ValidPermission reports whether p is a known permission.
func ValidPermission(p model.Permission) bool {
	for _, x := range model.AllPermissions {
		if x == p {
			return true
		}
	}
	return false
}

// missing returns the permissions of want that have does not contain.
func missing(have map[model.Permission]bool, want []model.Permission) []model.Permission {
	var out []model.Permission
	for _, p := range want {
		if !have[p] {
			out = append(out, p)
		}
	}
	return out
}
