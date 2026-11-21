package httpfp

import (
	"strings"

	"golang.org/x/net/html"
)

// htmlDoc is what the collector extracts from a page.
type htmlDoc struct {
	title     string
	generator string
	icons     []string // href values of <link rel="icon"> and friends, best first
}

const maxHTMLParseBytes = 512 << 10

// parseHTML reads the title, the generator meta tag and the icon links with a
// forgiving tokenizer. It never fails: broken markup yields what was found.
func parseHTML(body string) htmlDoc {
	var doc htmlDoc
	if body == "" || !strings.Contains(body, "<") {
		return doc
	}
	if len(body) > maxHTMLParseBytes {
		body = truncateUTF8(body, maxHTMLParseBytes)
	}
	z := html.NewTokenizer(strings.NewReader(body))
	var touch []string
	inTitle, haveTitle := false, false
	var title strings.Builder
	for {
		switch z.Next() {
		case html.ErrorToken:
			if inTitle && !haveTitle {
				doc.title = cleanText(title.String(), maxTitleRunes)
			}
			doc.icons = append(doc.icons, touch...)
			return doc
		case html.TextToken:
			if inTitle {
				title.Write(z.Text())
			}
		case html.EndTagToken:
			name, _ := z.TagName()
			if inTitle && string(name) == "title" {
				inTitle, haveTitle = false, true
				doc.title = cleanText(title.String(), maxTitleRunes)
			}
		case html.StartTagToken, html.SelfClosingTagToken:
			name, hasAttr := z.TagName()
			switch string(name) {
			case "title":
				// Only the first <title> counts; SVG icons carry their own titles.
				if !haveTitle {
					inTitle = true
					title.Reset()
				}
			case "meta":
				if !hasAttr {
					continue
				}
				a := attrs(z)
				if strings.EqualFold(a["name"], "generator") && doc.generator == "" {
					doc.generator = cleanText(a["content"], 200)
				}
			case "link":
				if !hasAttr {
					continue
				}
				a := attrs(z)
				href := strings.TrimSpace(a["href"])
				if href == "" {
					continue
				}
				rel := " " + strings.ToLower(a["rel"]) + " "
				switch {
				case strings.Contains(rel, " icon "):
					doc.icons = append(doc.icons, href)
				case strings.Contains(rel, "apple-touch-icon"), strings.Contains(rel, "mask-icon"):
					touch = append(touch, href)
				}
			}
		}
	}
}

func attrs(z *html.Tokenizer) map[string]string {
	m := map[string]string{}
	for {
		k, v, more := z.TagAttr()
		if len(k) > 0 {
			if _, dup := m[string(k)]; !dup {
				m[string(k)] = string(v)
			}
		}
		if !more {
			return m
		}
	}
}

// cleanText collapses whitespace and bounds the length in runes.
func cleanText(s string, maxRunes int) string {
	s = strings.Join(strings.Fields(strings.ToValidUTF8(s, "")), " ")
	if n := 0; len(s) > maxRunes {
		for i := range s {
			if n == maxRunes {
				return s[:i]
			}
			n++
		}
	}
	return s
}
