package report

import "html/template"

// The page is designed for A4 first: the screen view shows the same sheet.
// Colours carry the severity only; every severity also has its word, so a
// black-and-white print loses nothing.
const css = `
:root{--ink:#14181d;--soft:#47525e;--rule:#cdd3da;--wash:#f2f4f6;--high:#9b1c1c;--medium:#8f4e00;--low:#14506e;--info:#47525e}
*{box-sizing:border-box}
html{background:#e7eaee}
body{margin:0;font:400 10pt/1.45 "Inter","Segoe UI",system-ui,-apple-system,"Helvetica Neue",Arial,sans-serif;color:var(--ink);font-variant-numeric:tabular-nums;-webkit-print-color-adjust:exact;print-color-adjust:exact;-webkit-text-size-adjust:100%}
::selection{background:#cfe1ec}
.sheet{background:#fff;max-width:210mm;margin:8mm auto;padding:15mm 15mm 13mm}
h1,h2,h3,p,ol,ul,dl,dd,table{margin:0;padding:0}
h1{font-size:21pt;line-height:1.15;font-weight:700;letter-spacing:-.015em;text-wrap:balance}
h2{font-size:12pt;line-height:1.25;font-weight:700;margin:6mm 0 1.8mm;break-after:avoid;text-wrap:balance}
h2 .n{font-weight:400;color:var(--soft);margin-left:.4em}
code,.mono{font-family:ui-monospace,"SF Mono","Cascadia Mono",Menlo,Consolas,monospace;font-size:.92em}
.head{display:flex;justify-content:space-between;align-items:flex-end;gap:8mm;padding-bottom:3.5mm;border-bottom:1.5pt solid var(--ink)}
.brand{text-align:right;color:var(--soft);font-size:8.5pt;white-space:nowrap}
.brand b{display:block;color:var(--ink);font-size:10pt}
.meta{display:grid;grid-template-columns:minmax(0,1.3fr) minmax(0,1.5fr) auto minmax(0,1.1fr);gap:1mm 7mm;padding:2.5mm 0;border-bottom:.5pt solid var(--rule)}
.meta div:nth-child(3) dd{white-space:nowrap}
.meta dt{font-size:8pt;color:var(--soft)}
.meta dd{font-weight:600}
.notice{margin-top:4mm;padding:2.5mm 3.5mm;background:var(--wash);border:.5pt solid var(--medium);color:var(--medium);font-weight:600}
.lead{font-size:13pt;line-height:1.4;font-weight:500;margin-top:4.5mm;max-width:68ch;text-wrap:pretty}
.figures{display:grid;grid-template-columns:repeat(6,1fr);margin-top:4.5mm;border-top:.5pt solid var(--rule);border-bottom:.5pt solid var(--rule)}
.fig{padding:2.5mm 3mm 2.5mm 0}
.fig+.fig{padding-left:3mm;border-left:.5pt solid var(--rule)}
.fig b{display:block;font-size:18pt;line-height:1.1;font-weight:700;letter-spacing:-.01em}
.fig span{display:block;font-size:8.5pt;line-height:1.25;margin-top:.8mm}
.fig small{display:block;font-size:7.5pt;line-height:1.25;color:var(--soft);margin-top:.6mm}
.chg{break-inside:avoid}
.changes{list-style:none}
.changes li{display:grid;grid-template-columns:21mm 1fr;gap:0 2mm;padding:1mm 0;border-top:.5pt solid var(--rule);break-inside:avoid}
.changes li:last-child{border-bottom:.5pt solid var(--rule)}
.sev{font-size:8pt;font-weight:700;line-height:1.75;white-space:nowrap}
.sev::before{content:"";display:inline-block;width:2mm;height:2mm;margin-right:1.4mm;background:currentColor;vertical-align:-.1mm}
.sev-high{color:var(--high)}.sev-medium{color:var(--medium)}.sev-low{color:var(--low)}
.sev-info{color:var(--info)}.sev-info::before{background:none;box-shadow:inset 0 0 0 .5pt currentColor}
.more,.none,.expected{color:var(--soft);font-size:9pt;margin-top:1.5mm}
.none{margin-top:0}
.expected{margin-top:4mm;padding:2.2mm 3.5mm;background:var(--wash);color:var(--ink)}
.finding{padding:1.6mm 0;border-top:.5pt solid var(--rule);break-inside:avoid}
.finding:last-of-type{border-bottom:.5pt solid var(--rule)}
.finding header{display:grid;grid-template-columns:21mm 1fr auto;gap:0 2mm;align-items:baseline}
.finding h3{font-size:10pt;font-weight:700;line-height:1.35}
.score{font-size:8.5pt;color:var(--soft);white-space:nowrap}
.score b{color:var(--ink);font-size:10pt}
.finding .where{margin-left:23mm;font-size:9pt;color:var(--soft);overflow-wrap:anywhere}
.finding .where .mono{color:var(--ink)}
.ev{list-style:none;margin:.6mm 0 0 23mm;font-size:8.5pt;line-height:1.4}
.ev li{display:grid;grid-template-columns:40mm 1fr;gap:0 2mm;overflow-wrap:anywhere}
.ev code{color:var(--soft)}
table{width:100%;border-collapse:collapse;font-size:9pt}
th{text-align:left;font-size:8pt;font-weight:600;color:var(--soft);padding:0 2mm 1mm 0;border-bottom:.75pt solid var(--ink);vertical-align:bottom}
td{padding:1.1mm 2mm 1.1mm 0;border-bottom:.5pt solid var(--rule);vertical-align:top;overflow-wrap:anywhere}
th:last-child,td:last-child{padding-right:0}
tr{break-inside:avoid}
thead{display:table-header-group}
.r{text-align:right}
td.r,td.mono{white-space:nowrap}
td small{display:block;color:var(--soft);font-size:8.5pt}
.cols{display:grid;grid-template-columns:1.25fr 1fr;gap:0 9mm;break-inside:avoid}
.kv th{width:42%;font-size:9pt;font-weight:400;color:var(--soft);border-bottom:.5pt solid var(--rule);padding:1.1mm 2mm 1.1mm 0;vertical-align:top}
.kv tr:first-child th,.kv tr:first-child td{border-top:.75pt solid var(--ink)}
.safety{margin-top:2.5mm;font-size:9pt;max-width:75ch}
.foot{margin-top:4mm;padding-top:2mm;border-top:.5pt solid var(--rule);color:var(--soft);font-size:8pt}
@page{size:A4;margin:12mm 15mm}
@media print{html{background:#fff}.sheet{max-width:none;margin:0;padding:0}}
@media screen and (max-width:720px){
.sheet{margin:0;padding:6mm 4.5mm}
h1{font-size:17pt}
.head{flex-direction:column;align-items:flex-start;gap:2mm}
.brand{text-align:left;white-space:normal}.brand b{display:inline;margin-right:.5em}
.meta{grid-template-columns:1fr 1fr}.meta div:nth-child(3) dd{white-space:normal}
.lead{font-size:12pt}
.figures{grid-template-columns:repeat(2,1fr);border-bottom:0}
.fig,.fig+.fig{padding:2.5mm 2mm 2.5mm 0;border-left:0;border-bottom:.5pt solid var(--rule)}
.changes li,.finding header{grid-template-columns:1fr}
.finding .where,.ev{margin-left:0}
.ev li{grid-template-columns:1fr}
.cols{grid-template-columns:1fr}
.scroll{overflow-x:auto}
.scroll table{min-width:150mm}
td.mono{white-space:normal}
}
`

var htmlTemplate = template.Must(template.New("report").Parse(`<!doctype html>
<html lang="pl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}} · {{.Brand}}</title>
<style>` + css + `</style>
</head>
<body>
<main class="sheet">
<div class="head">
<h1>{{.Title}}</h1>
<p class="brand"><b>{{.Brand}}</b>{{.Generated}}</p>
</div>
<dl class="meta">{{range .Meta}}<div><dt>{{.K}}</dt><dd>{{.V}}</dd></div>{{end}}</dl>
{{if .Notice}}<p class="notice">{{.Notice}}</p>{{end}}
<p class="lead">{{.Lead}}</p>
<div class="figures">{{range .Figures}}<div class="fig"><b>{{.Value}}</b><span>{{.Label}}</span>{{if .Note}}<small>{{.Note}}</small>{{end}}</div>{{end}}</div>
{{range .Sections}}{{if or .Rows .Empty}}<section class="chg">
<h2>{{.Title}}{{if .Count}}<span class="n">{{.Count}}</span>{{end}}</h2>
{{if .Rows}}<ol class="changes">{{range .Rows}}
<li><span class="sev sev-{{.Sev}}">{{.SevLabel}}</span><span>{{.Summary}}</span></li>{{end}}
</ol>{{else}}<p class="none">{{.Empty}}</p>{{end}}
{{if .More}}<p class="more">{{.More}}</p>{{end}}
</section>
{{end}}{{end}}{{if .Expected}}<p class="expected">{{.Expected}}</p>
{{end}}{{if .Findings}}<section>
<h2>Najważniejsze obserwacje</h2>{{range .Findings}}
<article class="finding">
<header><span class="sev sev-{{.Sev}}">{{.SevLabel}}</span><h3>{{.Title}}</h3><span class="score">ciekawość <b>{{.Interest}}</b>/100</span></header>
<p class="where"><span class="mono">{{.Addr}}</span>{{range .Notes}} · {{.}}{{end}}</p>
{{if .Evidence}}<ul class="ev">{{range .Evidence}}<li><code>{{.Where}}</code><span>{{.Snippet}}</span></li>{{end}}{{if .EvidenceMore}}<li><code></code><span>i {{.EvidenceMore}} więcej w aplikacji</span></li>{{end}}</ul>{{end}}
</article>{{end}}
{{if .FindingsMore}}<p class="more">{{.FindingsMore}}</p>{{end}}
</section>
{{end}}{{if .Services}}<section>
<h2>Najciekawsze usługi</h2>
<div class="scroll"><table>
<thead><tr><th>Adres</th><th>Usługa</th><th>Dlaczego</th><th class="r">Ciekawość</th></tr></thead>
<tbody>{{range .Services}}
<tr><td class="mono">{{.Addr}}</td><td>{{.What}}</td><td>{{range $i, $w := .Why}}{{if $i}}<br>{{end}}{{$w}}{{end}}</td><td class="r"><b>{{.Interest}}</b></td></tr>{{end}}
</tbody></table></div>
</section>
{{end}}{{if .Hosts}}<section>
<h2>Hosty niestabilne i nieaktywne</h2>
<div class="scroll"><table>
<thead><tr><th>Host</th><th>Stan</th><th>Zwykły rytm</th><th class="r">Szansa, że nadal istnieje</th><th class="r">Odpowiada w</th><th class="r">Braki z rzędu</th></tr></thead>
<tbody>{{range .Hosts}}
<tr><td><span class="mono">{{.IP}}</span>{{if .Name}}<small>{{.Name}}</small>{{end}}</td><td>{{.Status}}</td><td>{{.Pattern}}</td><td class="r">{{.PAlive}}</td><td class="r">{{.Stability}} skanów</td><td class="r">{{.Misses}}</td></tr>{{end}}
</tbody></table></div>
{{if .HostsMore}}<p class="more">{{.HostsMore}}</p>{{end}}
</section>
{{end}}<section class="cols">
<div>
<h2>Parametry skanu</h2>
<table class="kv">{{range .Params}}<tr><th scope="row">{{.K}}</th><td>{{.V}}</td></tr>{{end}}</table>
</div>
<div>
<h2>Ruch faktycznie wysłany</h2>
<table class="kv">{{range .Traffic}}<tr><th scope="row">{{.K}}</th><td>{{.V}}</td></tr>{{end}}</table>
</div>
</section>
<p class="safety">{{.Safety}}</p>
<p class="foot">{{.Footer}}</p>
</main>
</body>
</html>
`))
