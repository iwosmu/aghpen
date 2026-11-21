// Package doctor checks that an installation of Czujka can work: the
// database, pg_tde, the master key, nmap, raw sockets, DNS, free disk, the
// backup tools and a route to the scan networks. Every failed check carries a
// plain Polish fix. Nothing here sends a packet to a scan target: the route
// check only asks the kernel which interface a packet would leave through.
package doctor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/store"
)

// Status of one check.
const (
	OK   = "ok"
	Warn = "warn"
	Fail = "fail"
	Skip = "skip"
)

// Check is the result of one check. Fix is a plain Polish instruction, set
// when the status is warn or fail.
type Check struct {
	Name   string `json:"name"`
	Title  string `json:"title"` // Polish
	Status string `json:"status"`
	Detail string `json:"detail"`
	Fix    string `json:"fix,omitempty"`
	Ms     int64  `json:"ms"`
}

// Report is the result of every check.
type Report struct {
	OK      bool      `json:"ok"` // no check failed (warnings allowed)
	Version string    `json:"version"`
	At      time.Time `json:"at"`
	Checks  []Check   `json:"checks"`
}

// Deps is what the checks look at. A nil Store skips the checks that need the
// database (its own check reports why).
type Deps struct {
	Version  string
	Store    *store.Store
	StoreErr error // why the store could not be opened
	KeyErr   error // why the master key could not be loaded (nil: loaded)
	KeyInfo  string
	NmapPath string
	DataDir  string // where the key file and the backups live
	TDEMode  string // require | auto | off

	// Seams for tests; nil uses the real thing.
	LookPath   func(string) (string, error)
	Command    func(ctx context.Context, name string, args ...string) ([]byte, error)
	RawSocket  func() error
	Resolve    func(ctx context.Context, host string) ([]string, error)
	Route      func(dst netip.Addr) (src netip.Addr, err error)
	Interfaces func() ([]netip.Prefix, error)
	FreeBytes  func(dir string) (uint64, error)
	ReadFile   func(path string) ([]byte, error)
}

// MinNmap is the oldest nmap version that the engine is tested with.
const MinNmap = 7.80

// Run runs every check.
func Run(ctx context.Context, d Deps) Report {
	d.defaults()
	r := Report{Version: d.Version, At: time.Now().UTC()}
	add := func(name, title string, f func() (status, detail, fix string)) {
		t0 := time.Now()
		st, detail, fix := f()
		if st == OK || st == Skip {
			fix = ""
		}
		r.Checks = append(r.Checks, Check{Name: name, Title: title, Status: st, Detail: detail, Fix: fix, Ms: time.Since(t0).Milliseconds()})
	}
	add("database", "Baza danych", func() (string, string, string) { return d.database(ctx) })
	add("pg_tde", "Szyfrowanie bazy (pg_tde)", func() (string, string, string) { return d.tde(ctx) })
	add("master_key", "Klucz główny", func() (string, string, string) { return d.masterKey(ctx) })
	add("nmap", "nmap", func() (string, string, string) { return d.nmap(ctx) })
	add("raw_sockets", "Gniazda surowe (SYN, ICMP, ARP)", d.rawSockets)
	add("dns", "DNS", func() (string, string, string) { return d.dns(ctx) })
	add("disk", "Wolne miejsce na dysku", d.disk)
	add("backup_tools", "Narzędzia kopii zapasowej (pg_dump, pg_restore)", d.backupTools)
	add("scan_networks", "Trasa do sieci skanowanych", func() (string, string, string) { return d.scanNetworks(ctx) })
	add("neighbour_table", "Tablica sąsiadów jądra (ARP)", func() (string, string, string) { return d.neighbourTable(ctx) })
	r.OK = true
	for _, c := range r.Checks {
		if c.Status == Fail {
			r.OK = false
		}
	}
	return r
}

func (d *Deps) defaults() {
	if d.LookPath == nil {
		d.LookPath = exec.LookPath
	}
	if d.Command == nil {
		d.Command = func(ctx context.Context, name string, args ...string) ([]byte, error) {
			ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			return exec.CommandContext(ctx, name, args...).CombinedOutput()
		}
	}
	if d.RawSocket == nil {
		d.RawSocket = func() error {
			c, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
			if err != nil {
				return err
			}
			return c.Close()
		}
	}
	if d.Resolve == nil {
		d.Resolve = func(ctx context.Context, host string) ([]string, error) {
			ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			return net.DefaultResolver.LookupHost(ctx, host)
		}
	}
	if d.Route == nil {
		d.Route = routeSource
	}
	if d.Interfaces == nil {
		d.Interfaces = interfacePrefixes
	}
	if d.FreeBytes == nil {
		d.FreeBytes = freeBytes
	}
	if d.ReadFile == nil {
		d.ReadFile = os.ReadFile
	}
	if d.NmapPath == "" {
		d.NmapPath = "nmap"
	}
	if d.DataDir == "" {
		d.DataDir, _ = os.Getwd()
	}
}

func (d *Deps) database(ctx context.Context) (string, string, string) {
	if d.Store == nil {
		detail := "brak połączenia"
		if d.StoreErr != nil {
			detail = d.StoreErr.Error()
		}
		return Fail, detail, "Sprawdź CZUJKA_DB_URL (adres, hasło, nazwa bazy) i czy baza działa: docker compose -f deploy/docker-compose.yml ps db. Przy instalacji bez dockera uruchom PostgreSQL 17 z pg_tde (obraz deploy/db albo pakiet Percona)."
	}
	var v string
	if err := d.Store.Pool().QueryRow(ctx, `SHOW server_version`).Scan(&v); err != nil {
		return Fail, err.Error(), "Baza odpowiada, ale nie wykonuje zapytań: sprawdź uprawnienia roli z CZUJKA_DB_URL i dziennik bazy."
	}
	major, _ := strconv.Atoi(strings.SplitN(v, ".", 2)[0])
	if major < 17 {
		return Fail, "PostgreSQL " + v, "Czujka wymaga PostgreSQL 17 z pg_tde: użyj obrazu deploy/db (Percona Distribution for PostgreSQL 17)."
	}
	return OK, "PostgreSQL " + v, ""
}

func (d *Deps) tde(ctx context.Context) (string, string, string) {
	if d.Store == nil {
		return Skip, "bez bazy danych nie da się sprawdzić", ""
	}
	t := d.Store.TDE(ctx)
	detail := fmt.Sprintf("zaszyfrowane tabele: %d z %d, WAL: %v", t.Encrypted, t.Tables, map[bool]string{true: "szyfrowany", false: "nieszyfrowany"}[t.WALEncrypted])
	if t.Reason != "" {
		detail += "; " + t.Reason
	}
	fix := "Użyj obrazu bazy z deploy/db: ładuje pg_tde (shared_preload_libraries=pg_tde), tworzy dostawcę kluczy i klucz główny tabel. Przy własnym serwerze wykonaj kroki z deploy/db/initdb/10-pg-tde.sh, potem czujka migrate."
	switch {
	case t.Active && t.WALEncrypted:
		return OK, detail, ""
	case t.Active:
		return Warn, detail, "Tabele są szyfrowane, dziennik WAL nie: ALTER SYSTEM SET pg_tde.wal_encrypt = on; i restart bazy."
	case d.TDEMode == "off":
		return Warn, detail + " (CZUJKA_TDE=off)", fix
	default:
		return Fail, detail, fix
	}
}

func (d *Deps) masterKey(ctx context.Context) (string, string, string) {
	if d.KeyErr != nil {
		return Fail, d.KeyErr.Error(), "Ustaw CZUJKA_MASTER_KEY (32 bajty w base64, czujka genkey) albo CZUJKA_MASTER_KEY_FILE ze ścieżką do pliku klucza. Bez właściwego klucza zaszyfrowanych pól nie da się odczytać."
	}
	if d.Store == nil {
		return Warn, d.KeyInfo + "; bez bazy nie da się sprawdzić, czy klucz do niej pasuje", "Najpierw napraw połączenie z bazą."
	}
	if err := d.Store.VerifyKeyring(ctx); err != nil {
		return Fail, err.Error(), "Klucz nie pasuje do danych w bazie. Przywróć właściwy plik klucza (kopia z instalacji) albo dopisz poprzedni klucz do CZUJKA_MASTER_KEY_OLD lub do pliku <plik klucza>.old i uruchom czujka rotate-key."
	}
	return OK, d.KeyInfo + "; klucz pasuje do danych w bazie", ""
}

var reNmapVersion = regexp.MustCompile(`Nmap version ([0-9]+)\.([0-9]+)`)

func (d *Deps) nmap(ctx context.Context) (string, string, string) {
	fix := "Zainstaluj nmap (Debian/Ubuntu: apt install nmap; Alpine: apk add nmap) albo wskaż plik w CZUJKA_NMAP_PATH. Bez nmap silnik używa wbudowanego skanera TCP connect (wolniejszy, bez wykrywania wersji usług)."
	path, err := d.LookPath(d.NmapPath)
	if err != nil {
		return Warn, "nie znaleziono: " + d.NmapPath, fix
	}
	out, err := d.Command(ctx, path, "--version")
	if err != nil {
		return Warn, fmt.Sprintf("%s nie odpowiada: %v", path, err), fix
	}
	m := reNmapVersion.FindStringSubmatch(string(out))
	if m == nil {
		return Warn, path + ": nieznany format wersji", fix
	}
	v, _ := strconv.ParseFloat(m[1]+"."+fmt.Sprintf("%02s", m[2]), 64)
	detail := fmt.Sprintf("%s, wersja %s.%s", path, m[1], m[2])
	if v < MinNmap {
		return Warn, detail, fmt.Sprintf("Wersja nmap jest starsza niż %.2f: zaktualizuj pakiet nmap.", MinNmap)
	}
	return OK, detail, ""
}

func (d *Deps) rawSockets() (string, string, string) {
	if err := d.RawSocket(); err != nil {
		return Warn, "brak: " + err.Error() + " (silnik użyje nmap -sT, bez ICMP i ARP)",
			"Daj procesowi uprawnienie CAP_NET_RAW: w docker compose cap_add: [NET_RAW, NET_ADMIN] (jest w deploy/docker-compose.yml); bez dockera: sudo setcap cap_net_raw,cap_net_admin+eip $(command -v nmap) oraz sudo setcap cap_net_raw+ep $(command -v czujka), albo AmbientCapabilities w jednostce systemd (deploy/systemd)."
	}
	return OK, "dostępne: skan SYN, wykrywanie ICMP i ARP", ""
}

func (d *Deps) dns(ctx context.Context) (string, string, string) {
	names := []string{}
	if d.Store != nil {
		for _, t := range d.targets(ctx) {
			if t.Kind == model.TargetDomain && len(names) < 5 {
				names = append(names, t.Value)
			}
		}
	}
	if len(names) == 0 {
		names = []string{"localhost"}
	}
	var bad []string
	for _, n := range names {
		if _, err := d.Resolve(ctx, n); err != nil {
			bad = append(bad, n)
		}
	}
	detail := fmt.Sprintf("rozwiązano %d z %d nazw (%s)", len(names)-len(bad), len(names), strings.Join(names, ", "))
	switch {
	case len(bad) == 0:
		return OK, detail, ""
	case len(bad) == len(names):
		return Fail, detail + "; błąd: " + strings.Join(bad, ", "), "Serwer DNS nie odpowiada: sprawdź /etc/resolv.conf (w kontenerze: ustawienia dns w docker compose) i czy serwer DNS jest osiągalny z hosta Czujki."
	default:
		return Warn, detail + "; nie rozwiązano: " + strings.Join(bad, ", "), "Sprawdź te nazwy w zakresach: mogły zniknąć z DNS albo są dostępne tylko z innego serwera DNS."
	}
}

func (d *Deps) disk() (string, string, string) {
	free, err := d.FreeBytes(d.DataDir)
	if err != nil {
		return Warn, err.Error(), "Sprawdź, czy katalog danych istnieje i jest dostępny: " + d.DataDir
	}
	detail := fmt.Sprintf("%s: wolne %.1f GiB", d.DataDir, float64(free)/(1<<30))
	switch {
	case free < 512<<20:
		return Fail, detail, "Zwolnij miejsce albo powiększ wolumen: poniżej 0,5 GiB baza i kopie zapasowe przestaną się zapisywać."
	case free < 2<<30:
		return Warn, detail, "Mniej niż 2 GiB wolnego miejsca: zaplanuj powiększenie wolumenu albo usuń stare kopie zapasowe."
	}
	return OK, detail, ""
}

func (d *Deps) backupTools() (string, string, string) {
	var missing []string
	for _, t := range []string{"pg_dump", "pg_restore"} {
		if _, err := d.LookPath(t); err != nil {
			missing = append(missing, t)
		}
	}
	if len(missing) > 0 {
		return Warn, "brak: " + strings.Join(missing, ", "), "czujka backup i czujka restore potrzebują klienta PostgreSQL 17 (Debian/Ubuntu: apt install postgresql-client-17; Alpine: apk add postgresql17-client). Obraz deploy/Dockerfile go zawiera."
	}
	return OK, "pg_dump i pg_restore są dostępne", ""
}

// targets returns the enabled targets of the scopes of the enabled profiles.
func (d *Deps) targets(ctx context.Context) []model.Target {
	profiles, err := d.Store.ListProfiles(ctx, store.ListOpts{Limit: 1000})
	if err != nil {
		return nil
	}
	seen := map[int64]bool{}
	var ids []int64
	for _, p := range profiles.Items {
		if !p.Enabled {
			continue
		}
		for _, id := range p.ScopeIDs {
			if !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}
	if len(ids) == 0 {
		return nil
	}
	ts, err := d.Store.EnabledTargets(ctx, ids)
	if err != nil {
		return nil
	}
	return ts
}

// firstAddr is one address of a target, used to ask for a route.
func firstAddr(ctx context.Context, t model.Target, resolve func(context.Context, string) ([]string, error)) (netip.Addr, error) {
	v := strings.TrimSpace(t.Value)
	switch t.Kind {
	case model.TargetIP:
		return netip.ParseAddr(v)
	case model.TargetCIDR:
		p, err := netip.ParsePrefix(v)
		if err != nil {
			return netip.Addr{}, err
		}
		a := p.Masked().Addr()
		if p.Bits() < a.BitLen()-1 {
			a = a.Next()
		}
		return a, nil
	case model.TargetRange:
		from, _, _ := strings.Cut(v, "-")
		return netip.ParseAddr(strings.TrimSpace(from))
	case model.TargetDomain:
		addrs, err := resolve(ctx, v)
		if err != nil || len(addrs) == 0 {
			return netip.Addr{}, fmt.Errorf("nazwa się nie rozwiązuje")
		}
		return netip.ParseAddr(addrs[0])
	}
	return netip.Addr{}, fmt.Errorf("nieznany rodzaj celu %q", t.Kind)
}

func (d *Deps) scanNetworks(ctx context.Context) (string, string, string) {
	if d.Store == nil {
		return Skip, "bez bazy danych nie da się odczytać zakresów", ""
	}
	targets := d.targets(ctx)
	if len(targets) == 0 {
		return Warn, "żaden włączony profil nie ma zakresu z włączonymi celami", "Dodaj zakres z celami (Zakresy → Dodaj cele) i przypisz go do włączonego profilu skanowania."
	}
	local, _ := d.Interfaces()
	const limit = 50
	var direct, gateway int
	var unreachable []string
	for i, t := range targets {
		if i >= limit {
			break
		}
		a, err := firstAddr(ctx, t, d.Resolve)
		if err != nil {
			unreachable = append(unreachable, fmt.Sprintf("%s (%v)", t.Value, err))
			continue
		}
		if _, err := d.Route(a); err != nil {
			unreachable = append(unreachable, fmt.Sprintf("%s (brak trasy: %v)", t.Value, err))
			continue
		}
		onLink := false
		for _, p := range local {
			onLink = onLink || p.Contains(a.Unmap())
		}
		if onLink {
			direct++
		} else {
			gateway++
		}
	}
	checked := min(len(targets), limit)
	detail := fmt.Sprintf("sprawdzono %d z %d celów: %d w sieci lokalnej (ARP), %d przez bramę", checked, len(targets), direct, gateway)
	if len(unreachable) > 0 {
		detail += "; bez trasy: " + strings.Join(unreachable, ", ")
		st := Warn
		if len(unreachable) == checked {
			st = Fail
		}
		return st, detail, "Host Czujki nie ma trasy do tych sieci. W dockerze dołącz kontener do sieci skanowanej (deploy/docker-compose.scan-network.yml, CZUJKA_SCAN_NETWORK) albo użyj network_mode: host; bez dockera dodaj trasę (ip route add <sieć> via <brama>) albo interfejs w tej sieci."
	}
	return OK, detail, ""
}

// GCThresh3 is where the kernel's IPv4 neighbour table limit is readable,
// also inside a container: the limit is global, not per network namespace.
const GCThresh3 = "/proc/sys/net/ipv4/neigh/default/gc_thresh3"

// OnLinkAddresses counts the IPv4 addresses of the targets that share a subnet
// with one of the scanner's interfaces: each of them gets a neighbour entry
// (ARP) when it is probed. largest is the largest sum over one scope.
func OnLinkAddresses(ctx context.Context, targets []model.Target, local []netip.Prefix, resolve func(context.Context, string) ([]string, error)) (total, largest int64) {
	perScope := map[int64]int64{}
	for _, t := range targets {
		n := onLink(ctx, t, local, resolve)
		total += n
		perScope[t.ScopeID] += n
	}
	for _, n := range perScope {
		largest = max(largest, n)
	}
	return total, largest
}

func onLink(ctx context.Context, t model.Target, local []netip.Prefix, resolve func(context.Context, string) ([]string, error)) int64 {
	var best int64
	v := strings.TrimSpace(t.Value)
	for _, lp := range local {
		if !lp.Addr().Is4() {
			continue
		}
		var n int64
		switch t.Kind {
		case model.TargetIP, model.TargetDomain:
			if a, err := firstAddr(ctx, t, resolve); err == nil && lp.Contains(a.Unmap()) {
				n = 1
			}
		case model.TargetCIDR:
			tp, err := netip.ParsePrefix(v)
			if err != nil || !tp.Addr().Is4() {
				continue
			}
			tp = tp.Masked()
			switch {
			case lp.Bits() <= tp.Bits() && lp.Contains(tp.Addr()):
				n = int64(1) << (32 - tp.Bits())
			case tp.Bits() < lp.Bits() && tp.Contains(lp.Addr()):
				n = int64(1) << (32 - lp.Bits())
			}
		case model.TargetRange:
			a, b, _ := strings.Cut(v, "-")
			from, err1 := netip.ParseAddr(strings.TrimSpace(a))
			to, err2 := netip.ParseAddr(strings.TrimSpace(b))
			if err1 != nil || err2 != nil || !from.Is4() || !to.Is4() {
				continue
			}
			lo, hi := u32(from), u32(to)
			plo := u32(lp.Masked().Addr())
			phi := plo + uint32(uint64(1)<<(32-lp.Bits())-1)
			if lo < plo {
				lo = plo
			}
			if hi > phi {
				hi = phi
			}
			if hi >= lo {
				n = int64(hi-lo) + 1
			}
		}
		best = max(best, n)
	}
	return best
}

func u32(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// NeighbourSysctl returns the sysctl lines for n on-link addresses.
func NeighbourSysctl(n int64) string {
	t3 := int64(4096)
	for t3 < 2*n+1024 {
		t3 *= 2
	}
	return fmt.Sprintf("net.ipv4.neigh.default.gc_thresh1 = %d\nnet.ipv4.neigh.default.gc_thresh2 = %d\nnet.ipv4.neigh.default.gc_thresh3 = %d", t3/8, t3/2, t3)
}

// neighbourTable compares the kernel's neighbour table limit with the number
// of on-link addresses of the largest enabled scope. When the table overflows
// during a scan, the kernel evicts the host's own entries too: name
// resolution and other traffic of the whole host break.
func (d *Deps) neighbourTable(ctx context.Context) (string, string, string) {
	raw, err := d.ReadFile(GCThresh3)
	if err != nil {
		return Skip, "nie można odczytać " + GCThresh3 + " (system inny niż Linux?)", ""
	}
	limit, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil {
		return Skip, "nieczytelna wartość gc_thresh3: " + strings.TrimSpace(string(raw)), ""
	}
	if d.Store == nil {
		return OK, fmt.Sprintf("gc_thresh3 = %d; bez bazy danych nie da się policzyć celów w sieci lokalnej", limit), ""
	}
	local, _ := d.Interfaces()
	total, largest := OnLinkAddresses(ctx, d.targets(ctx), local, d.Resolve)
	detail := fmt.Sprintf("gc_thresh3 = %d; adresów w sieci lokalnej skanera: %d w największym zakresie, %d we wszystkich włączonych", limit, largest, total)
	if largest == 0 {
		return OK, detail + " (skan przez bramę nie zapełnia tablicy sąsiadów)", ""
	}
	fix := "Skan sieci lokalnej tworzy wpis ARP dla każdego sondowanego adresu. Limit jest wspólny dla całego hosta (także dla kontenerów): po przepełnieniu jądro usuwa wpisy hosta i przestaje działać m.in. DNS. Na hoście (nie w kontenerze) wykonaj:\n" +
		"cat <<'EOF' | sudo tee /etc/sysctl.d/90-czujka-neigh.conf\n" + NeighbourSysctl(largest) + "\nEOF\nsudo sysctl --system"
	switch {
	case limit < largest:
		return Fail, detail + ": skan przepełni tablicę sąsiadów", fix
	case limit < 2*largest+1024:
		return Warn, detail + ": mały zapas na wpisy samego hosta", fix
	}
	return OK, detail, ""
}

// routeSource asks the kernel for the source address of a packet to dst. A
// UDP "connect" picks the route and sends nothing.
func routeSource(dst netip.Addr) (netip.Addr, error) {
	c, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(dst, 9)))
	if err != nil {
		return netip.Addr{}, err
	}
	defer c.Close()
	ap := c.LocalAddr().(*net.UDPAddr).AddrPort()
	return ap.Addr(), nil
}

func interfacePrefixes() ([]netip.Prefix, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	var out []netip.Prefix
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if p, err := netip.ParsePrefix(n.String()); err == nil && !p.Addr().IsLoopback() {
				out = append(out, p.Masked())
			}
		}
	}
	return out, nil
}

func freeBytes(dir string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return st.Bavail * uint64(st.Bsize), nil
}

// DataDir returns the directory of the key file, else the working directory.
func DataDir(keyFile string) string {
	if keyFile != "" {
		return filepath.Dir(keyFile)
	}
	wd, _ := os.Getwd()
	return wd
}

// Text renders a report for the terminal.
func Text(r Report) string {
	var b strings.Builder
	mark := map[string]string{OK: "OK  ", Warn: "UWAGA", Fail: "BŁĄD", Skip: "POMIN"}
	fmt.Fprintf(&b, "czujka doctor %s, %s\n\n", r.Version, r.At.Local().Format("2006-01-02 15:04:05"))
	for _, c := range r.Checks {
		fmt.Fprintf(&b, "[%-5s] %s: %s\n", mark[c.Status], c.Title, c.Detail)
		if c.Fix != "" {
			fmt.Fprintf(&b, "        Co zrobić: %s\n", c.Fix)
		}
	}
	if r.OK {
		b.WriteString("\nWynik: instalacja jest gotowa do pracy.\n")
	} else {
		b.WriteString("\nWynik: są błędy; popraw je według wskazówek powyżej.\n")
	}
	return b.String()
}

// ErrFailed is returned by the CLI when a check failed.
var ErrFailed = errors.New("doctor: at least one check failed")

func targetOf(kind, value string) model.Target {
	return model.Target{Kind: model.TargetKind(kind), Value: value}
}
