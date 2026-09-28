// Command checkui statically analyses the Svelte frontend for two classes of
// defect that no compiler or linter reports.
//
// Dead interactivity: a `<button>` that carries no event handler, or a handler
// function that nothing in the component references, renders fine, compiles
// fine and produces no Svelte compiler warning - it is simply inert at
// runtime, which is exactly the class of defect that shipped as "the Edit
// button does nothing".
//
// Renderer escape hatches: the GUI's webview is bound to the full Go bridge
// (ShowPassword, ImportPGPKeyFile, OpenLocalStore, CloneStore,
// ChangeLockPassword), so any script running in it owns the vault. Svelte
// escapes every interpolation, which is why the app is safe by default, but
// that safety lives in a convention nobody can see. This tool fails the build
// on `{@html}`, on the DOM/eval sinks that bypass Svelte's escaping, on inline
// styles (which the policy in index.html blocks anyway, so they are a styling
// bug with no error message), and on a frontend whose index.html has lost or
// weakened its Content-Security-Policy meta tag.
//
// It is wired into `go test ./tools/checkui` (so it runs as part of the normal
// `go test ./...` gate) rather than being a standalone CI step, so the same
// check guards local development and CI.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Finding describes a single dead-interactivity problem in a Svelte component.
type Finding struct {
	// File is the component path, relative to the scanned root.
	File string
	// Line is the 1-based line the finding starts on.
	Line int
	// Rule is the stable identifier of the violated rule, e.g. "button-no-handler".
	Rule string
	// Message explains the problem in one sentence.
	Message string
}

func (f Finding) String() string {
	return fmt.Sprintf("%s:%d: %s: %s", f.File, f.Line, f.Rule, f.Message)
}

// Rules reported by this tool. They are listed here so the README/AGENTS notes
// and the tool's own output cannot drift apart silently.
const (
	// ruleButtonNoHandler fires for a <button> that is neither a submit button
	// nor bound to a click handler, making it permanently inert.
	ruleButtonNoHandler = "button-no-handler"
	// ruleOrphanHandler fires for a function declared in the <script> block that
	// is never referenced anywhere else in the component, so it can never run.
	ruleOrphanHandler = "orphan-handler"
	// ruleDeadInterpolation fires for a {placeholder} written inside a quoted
	// string in an attribute expression. Svelte does not interpolate there, so
	// the text reaches the DOM as part of a class name and the styling it
	// asked for is simply absent.
	ruleDeadInterpolation = "dead-interpolation"
	// ruleRawHTML fires for a `{@html ...}` tag, the single Svelte construct
	// that inserts a value into the document as markup rather than as text.
	ruleRawHTML = "raw-html"
	// ruleHTMLSink fires for a DOM or eval sink that parses markup or executes
	// code, which is what turns an injection bug into script execution.
	ruleHTMLSink = "html-sink"
	// ruleInlineStyle fires for an inline style: a style attribute (or Svelte
	// style: directive) in markup, or a write through the CSSOM. The shipped
	// policy sets style-src 'self', so the webview silently drops these and
	// the styling disappears - a failure with no error message anywhere.
	ruleInlineStyle = "inline-style"
	// ruleMissingCSP fires when index.html carries no Content-Security-Policy
	// meta tag. Wails v2 has no CSP option, so that tag is the only place the
	// renderer policy can live.
	ruleMissingCSP = "missing-csp"
	// ruleWeakCSP fires when a Content-Security-Policy exists but does not
	// actually constrain script or style, e.g. a wildcard source or
	// 'unsafe-inline'.
	ruleWeakCSP = "weak-csp"
)

// allowMarker suppresses a finding on a line that names the construct without
// using it (prose, a comment) or that uses it deliberately after review. Without
// an escape hatch a gate like this one eventually gets deleted instead of
// obeyed.
const allowMarker = "checkui:allow"

// sink is a frontend construct that can execute code or parse markup as HTML.
type sink struct {
	rule string
	re   *regexp.Regexp
	what string
}

// sinks is the complete set of constructs this tool refuses to ignore. The
// markup and eval entries are deliberately conservative: the app has no need
// for any of them today, and each one is a one-line change away from turning
// untrusted vault data into code running with ShowPassword. The style entries
// are not an escape hatch but the same class of problem: the shipped CSP
// blocks them, so using one is a silent styling bug.
var sinks = []sink{
	{ruleHTMLSink, regexp.MustCompile(`\.(inner|outer)HTML\s*=`), "assigns parsed HTML, bypassing Svelte's escaping"},
	{ruleHTMLSink, regexp.MustCompile(`\.insertAdjacentHTML\s*\(`), "parses its argument as HTML"},
	{ruleHTMLSink, regexp.MustCompile(`\.\s*srcdoc\s*=`), "assigns an iframe srcdoc document"},
	{ruleHTMLSink, regexp.MustCompile(`document\s*\.\s*writeln?\s*\(`), "writes markup into the document"},
	{ruleHTMLSink, regexp.MustCompile(`\beval\s*\(`), "executes a string as code"},
	{ruleHTMLSink, regexp.MustCompile(`new\s+Function\s*\(`), "compiles a string as code"},
	{ruleRawHTML, regexp.MustCompile(`\{@html\b`), "{@html} renders its expression as markup instead of text"},
	{ruleInlineStyle, regexp.MustCompile(`\.\s*style\s*=`), "assigns the whole style property"},
	{ruleInlineStyle, regexp.MustCompile(`\.\s*style\s*\.\s*[A-Za-z_$][\w$-]*\s*=`), "writes a CSS property through the CSSOM"},
	{ruleInlineStyle, regexp.MustCompile(`\.\s*style\s*\.\s*(setProperty|removeProperty)\s*\(`), "writes CSS through the CSSOM"},
	{ruleInlineStyle, regexp.MustCompile(`setAttribute\s*\(\s*["'` + "`" + `]style["'` + "`" + `]`), "sets a style attribute"},
	{ruleInlineStyle, regexp.MustCompile(`createElement\s*\(\s*["'` + "`" + `]style["'` + "`" + `]`), "creates a <style> element"},
}

func main() {
	root := "."
	if len(os.Args) > 1 {
		root = os.Args[1]
	}
	findings, err := CheckTree(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "checkui: %v\n", err)
		os.Exit(2)
	}
	// index.html is the entry document, so it sits next to (or one level above)
	// the scanned source root depending on which directory was passed in.
	for _, candidate := range []string{
		filepath.Join(root, "index.html"),
		filepath.Join(filepath.Dir(filepath.Clean(root)), "index.html"),
	} {
		if _, err := os.Stat(candidate); err != nil {
			continue
		}
		csp, err := CheckIndexHTML(candidate)
		if err != nil {
			fmt.Fprintf(os.Stderr, "checkui: %v\n", err)
			os.Exit(2)
		}
		findings = append(findings, csp...)
		break
	}
	if len(findings) == 0 {
		fmt.Printf("checkui: no dead interactivity or unsafe HTML sinks found under %s\n", root)
		return
	}
	for _, f := range findings {
		fmt.Fprintln(os.Stderr, "checkui: FAIL "+f.String())
	}
	fmt.Fprintf(os.Stderr, "checkui: %d problem(s) found under %s\n", len(findings), root)
	os.Exit(1)
}

// CheckTree walks root for frontend source files and reports every finding,
// sorted by file then line. Svelte components are checked for dead
// interactivity as well as unsafe HTML sinks; plain .ts/.js modules are checked
// for the sinks alone.
func CheckTree(root string) ([]Finding, error) {
	var files []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// Dependencies and build output are never first-party source.
			if name := d.Name(); name == "node_modules" || name == "dist" || name == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		switch strings.ToLower(filepath.Ext(d.Name())) {
		case ".svelte", ".ts", ".js":
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)

	var all []Finding
	for _, path := range files {
		src, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = path
		}
		if strings.EqualFold(filepath.Ext(path), ".svelte") {
			all = append(all, CheckComponent(rel, string(src))...)
			continue
		}
		all = append(all, CheckModule(rel, string(src))...)
	}
	return all, nil
}

// scriptRe captures the contents of a top-level <script> block. The component
// is a single unit, so the first script block is the only one that matters.
var scriptRe = regexp.MustCompile(`(?s)<script[^>]*>(.*?)</script>`)

// funcDeclRe captures the names of functions declared in the script block. The
// leading indent is matched with [ \t] rather than \s so that a match always
// starts on the line the declaration is written on, keeping reported line
// numbers accurate.
var funcDeclRe = regexp.MustCompile(`(?m)^[ \t]*(?:export[ \t]+)?(?:async[ \t]+)?function[ \t]*\*?[ \t]*([A-Za-z_$][\w$]*)`)

// identRe matches an identifier as a whole word, for reference counting.
var identRe = func(name string) *regexp.Regexp {
	return regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\b`)
}

// CheckComponent analyses a single .svelte source file.
func CheckComponent(file, src string) []Finding {
	findings := CheckSinks(file, src)

	for _, tag := range scanTags(src) {
		if isStyleAttribute(tag) {
			if line, ok := attributeLine(src, tag, styleAttrRe); ok {
				findings = append(findings, Finding{
					File:    file,
					Line:    line,
					Rule:    ruleInlineStyle,
					Message: fmt.Sprintf("<%s> sets an inline style; style-src 'self' makes the webview drop it with no error, so put the rule in src/style.css and use a class (suppress with a %q comment if it is deliberate)", tag.name, allowMarker),
				})
			}
		}
		// off is the offset of the dead placeholder itself, so the allow
		// marker is read from the line the mistake is written on.
		if off, ok := deadInterpolation(src, tag); ok && !isSuppressed(src, off) {
			findings = append(findings, Finding{
				File:    file,
				Line:    lineOf(src, off),
				Rule:    ruleDeadInterpolation,
				Message: fmt.Sprintf("<%s> writes a {placeholder} inside a quoted string in an attribute expression, where Svelte does not interpolate; the text reaches the DOM verbatim (put the conditional in a class: directive, or build the string in the script block)", tag.name),
			})
		}
		if tag.name != "button" {
			continue
		}
		if hasClickHandler(tag.attrs) || isSubmitButton(tag.attrs) {
			continue
		}
		findings = append(findings, Finding{
			File:    file,
			Line:    tag.line,
			Rule:    ruleButtonNoHandler,
			Message: "<button> has no on:click handler and no type=\"submit\", so clicking it does nothing",
		})
	}

	// script holds byte index pairs into src: [whole, bodyStart, bodyEnd].
	script := scriptRe.FindStringSubmatchIndex(src)
	if script != nil {
		body := src[script[2]:script[3]]
		for _, m := range funcDeclRe.FindAllStringSubmatchIndex(body, -1) {
			name := body[m[2]:m[3]]
			// A declaration contributes exactly one occurrence of its own
			// name. Anything else in the file (script body, markup, event
			// handler) is a real reference.
			if len(identRe(name).FindAllStringIndex(src, -1)) < 2 {
				findings = append(findings, Finding{
					File:    file,
					Line:    lineOf(src, script[2]+m[0]),
					Rule:    ruleOrphanHandler,
					Message: fmt.Sprintf("function %s is declared but never referenced; it can never be called", name),
				})
			}
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Line != findings[j].Line {
			return findings[i].Line < findings[j].Line
		}
		return findings[i].Rule < findings[j].Rule
	})
	return findings
}

// CheckModule analyses a non-component frontend source file. Dead
// interactivity cannot occur outside a component, so only the raw-markup and
// code-execution sinks apply.
func CheckModule(file, src string) []Finding {
	return CheckSinks(file, src)
}

// CheckSinks reports every {@html} tag, DOM/eval sink and inline-style write in
// src. The webview has the whole Go bridge bound to it, so a value that
// reaches the DOM as markup is not a rendering bug, it is vault access: the
// injected script can call ShowPassword, read the clipboard or rewrite the lock
// password. An inline style is the milder version of the same mistake - the
// policy silently drops it, so the styling is lost with no error to find.
func CheckSinks(file, src string) []Finding {
	var findings []Finding
	type lineRule struct {
		line int
		rule string
	}
	seen := map[lineRule]bool{}
	for _, s := range sinks {
		for _, m := range s.re.FindAllStringIndex(src, -1) {
			key := lineRule{line: lineOf(src, m[0]), rule: s.rule}
			// One finding per line per rule: a single line that trips two
			// patterns from the same rule is one problem, not two.
			if seen[key] {
				continue
			}
			seen[key] = true
			if isSuppressed(src, m[0]) {
				continue
			}
			// Why the construct matters is not the same for every rule: markup
			// sinks are vault access, an inline style is a styling bug the
			// webview drops without a word.
			why := "the webview is bound to ShowPassword/ChangeLockPassword, so this turns injected data into vault access"
			if s.rule == ruleInlineStyle {
				why = "style-src 'self' makes the webview drop this with no error, so the styling is silently lost"
			}
			findings = append(findings, Finding{
				File:    file,
				Line:    key.line,
				Rule:    s.rule,
				Message: fmt.Sprintf("%s; %s (suppress with a %q comment if it is deliberate)", s.what, why, allowMarker),
			})
		}
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Line != findings[j].Line {
			return findings[i].Line < findings[j].Line
		}
		return findings[i].Rule < findings[j].Rule
	})
	return findings
}

// isSuppressed reports whether the line containing off carries the allow
// marker, in a Svelte/HTML/JS comment or simply as trailing text.
func isSuppressed(src string, off int) bool {
	start := strings.LastIndexByte(src[:off], '\n') + 1
	end := strings.IndexByte(src[off:], '\n')
	if end < 0 {
		end = len(src)
	} else {
		end += off
	}
	return strings.Contains(src[start:end], allowMarker)
}

// cspMetaRe matches the CSP meta element regardless of attribute order or
// quoting. Wails serves the document through golang.org/x/net/html, which
// re-encodes attribute values, so the tag must be matched loosely.
var cspMetaRe = regexp.MustCompile(`(?is)<meta[^>]*http-equiv\s*=\s*["']?content-security-policy["']?[^>]*>`)

// attrValue extracts a single attribute value from a tag fragment. The value
// may itself contain quotes (a CSP policy is full of 'self'), so a regexp
// cannot do this; the value runs to the next matching quote.
func attrValue(tag, name string) (string, bool) {
	rest := tag
	for {
		i := strings.Index(rest, name)
		if i < 0 {
			return "", false
		}
		rest = rest[i+len(name):]
		trimmed := strings.TrimLeft(rest, " \t\n\r\f")
		if !strings.HasPrefix(trimmed, "=") {
			continue
		}
		rest = strings.TrimLeft(trimmed[1:], " \t\n\r\f")
		if rest == "" {
			return "", false
		}
		quote := rest[0]
		if quote != '"' && quote != '\'' {
			// Unquoted value: runs to the next space or tag close.
			end := strings.IndexAny(rest, " \t\n\r\f>")
			if end < 0 {
				return rest, true
			}
			return rest[:end], true
		}
		end := strings.IndexByte(rest[1:], quote)
		if end < 0 {
			return rest[1:], true
		}
		return rest[1 : 1+end], true
	}
}

// CheckIndexHTML reports a frontend entry document that has lost its
// Content-Security-Policy, or that has one which does not actually restrict
// script. Wails v2 exposes no CSP option of its own, so this meta tag is the
// entire renderer-side policy: without it a single HTML-injection bug in a
// 1800-line component is complete compromise of the vault.
func CheckIndexHTML(path string) ([]Finding, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	rel := filepath.Base(path)
	tag := cspMetaRe.FindString(string(src))
	if tag == "" {
		return []Finding{{
			File:    rel,
			Line:    1,
			Rule:    ruleMissingCSP,
			Message: "index.html has no <meta http-equiv=\"Content-Security-Policy\">; Wails v2 has no CSP option, so that tag is the only thing stopping injected markup from reaching the Go bridge",
		}}, nil
	}
	policy, ok := attrValue(tag, "content")
	if !ok {
		return []Finding{{
			File:    rel,
			Line:    lineOf(string(src), strings.Index(string(src), tag)),
			Rule:    ruleWeakCSP,
			Message: "the Content-Security-Policy meta tag has no content attribute, so no policy is applied",
		}}, nil
	}

	directives := parseCSP(policy)
	line := lineOf(string(src), strings.Index(string(src), tag))
	var findings []Finding
	def, hasDefault := directives["default-src"]
	if !hasDefault || len(def) == 0 {
		findings = append(findings, Finding{
			File: rel, Line: line, Rule: ruleWeakCSP,
			Message: "the Content-Security-Policy has no default-src, so it constrains nothing",
		})
	}
	// script-src falls back to default-src, so an 'unsafe-inline' in either
	// place re-opens inline script execution.
	script := firstDirective(directives, []string{"script-src"})
	for _, expr := range script {
		switch strings.ToLower(expr) {
		case "*":
			findings = append(findings, Finding{
				File: rel, Line: line, Rule: ruleWeakCSP,
				Message: "the Content-Security-Policy allows scripts from any source; it must stay script-src 'self'",
			})
		case "'unsafe-inline'", "'unsafe-eval'":
			findings = append(findings, Finding{
				File: rel, Line: line, Rule: ruleWeakCSP,
				Message: fmt.Sprintf("script-src allows %s, which is what a Content-Security-Policy is supposed to prevent", expr),
			})
		}
	}

	// style-src has the same problem for style: 'unsafe-inline' lets injected
	// markup restyle the app, and a full-screen overlay over the entry list is
	// all it takes to aim a click at the wrong row. The build ships one linked
	// stylesheet, so nothing in this app needs it. style-src-attr and
	// style-src-elem narrow the rule for attributes and <style> elements
	// respectively, so an 'unsafe-inline' in either of them counts too; the
	// first chain that resolves to one is reported, because one relaxed style
	// directive is one problem however many names inherit it.
	for _, chain := range [][]string{
		{"style-src"},
		{"style-src-attr", "style-src"},
		{"style-src-elem", "style-src"},
	} {
		if !allowsUnsafeInline(firstDirective(directives, chain)) {
			continue
		}
		findings = append(findings, Finding{
			File: rel, Line: line, Rule: ruleWeakCSP,
			Message: chain[0] + " allows 'unsafe-inline', so injected markup can restyle the vault UI (a full-screen overlay is enough to aim a click at the wrong row); ship the rule in src/style.css instead",
		})
		break
	}
	return findings, nil
}

// firstDirective resolves a CSP inheritance chain: the source expressions of
// the first directive in the chain that the policy names, or of default-src if
// it names none of them. style-src-attr and style-src-elem fall back to
// style-src; every directive falls back to default-src.
func firstDirective(directives map[string][]string, chain []string) []string {
	for _, name := range chain {
		if exprs, ok := directives[name]; ok {
			return exprs
		}
	}
	return directives["default-src"]
}

// allowsUnsafeInline reports whether a directive's source expressions permit
// inline style or script.
func allowsUnsafeInline(exprs []string) bool {
	for _, expr := range exprs {
		if strings.EqualFold(strings.TrimSpace(expr), "'unsafe-inline'") {
			return true
		}
	}
	return false
}

// parseCSP splits a policy into directive name -> source expressions.
func parseCSP(policy string) map[string][]string {
	directives := map[string][]string{}
	for _, part := range strings.Split(policy, ";") {
		fields := strings.Fields(part)
		if len(fields) == 0 {
			continue
		}
		name := strings.ToLower(fields[0])
		directives[name] = append(directives[name], fields[1:]...)
	}
	return directives
}

// tag is a parsed Svelte element open tag.
type tag struct {
	name  string
	line  int
	start int
	end   int
	attrs []attr
}

// attr is a single parsed attribute on an element.
type attr struct {
	name string
	// value is the attribute's text: the interpolated text of a quoted
	// attribute, or the expression source of a Svelte attribute value.
	value string
	// expr reports that value is an expression (class={...}) rather than
	// quoted text, which is what decides whether a {placeholder} in it
	// interpolates or reaches the DOM verbatim.
	expr bool
}

// scanTags finds every element open tag in src. It is a small hand-rolled
// scanner rather than a regexp because attribute values routinely contain '>'
// (inline arrow functions, comparisons) and quoted strings, both of which a
// naive `<[^>]*>` match would cut short.
func scanTags(src string) []tag {
	var tags []tag
	for i := 0; i < len(src); i++ {
		if src[i] != '<' {
			continue
		}
		if i+1 >= len(src) {
			break
		}
		// Skip closing tags, comments, doctypes and block openers: only a '<'
		// directly followed by a name character starts an element.
		if !isTagNameStart(src[i+1]) {
			continue
		}
		j := i + 1
		for j < len(src) && isTagNameByte(src[j]) {
			j++
		}
		end, _ := scanTagEnd(src, j)
		tags = append(tags, tag{
			name:  src[i+1 : j],
			line:  lineOf(src, i),
			start: i,
			end:   end,
			attrs: parseAttrs(src[j:end]),
		})
		// Continue scanning right after this tag's attributes. Nested markup is
		// still visited because the loop simply keeps walking the source.
		i = end
	}
	return tags
}

// isTagNameStart reports whether b may begin an element name.
func isTagNameStart(b byte) bool {
	return b == '_' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func isTagNameByte(b byte) bool {
	return b == '-' || b == ':' || b == '.' || b == '_' ||
		(b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// scanTagEnd returns the offset of the '>' that closes a tag whose attributes
// start at from, plus whether the tag is self-closing. It tracks Svelte's two
// nesting constructs so that a '>' inside either one does not end the tag.
func scanTagEnd(src string, from int) (end int, selfClosing bool) {
	depth := 0
	for i := from; i < len(src); i++ {
		switch c := src[i]; c {
		case '"', '\'':
			// Skip to the matching quote, honouring backslash escapes.
			for i++; i < len(src); i++ {
				if src[i] == '\\' {
					i++
					continue
				}
				if src[i] == c {
					break
				}
			}
		case '{':
			depth++
		case '}':
			if depth > 0 {
				depth--
			}
		case '/':
			// Only a '/' immediately before the closing '>' self-closes.
			if depth == 0 && i+1 < len(src) && src[i+1] == '>' {
				return i + 1, true
			}
		case '>':
			if depth == 0 {
				return i, false
			}
		}
	}
	return len(src), false
}

// parseAttrs splits the raw attribute section of a tag into attributes.
func parseAttrs(raw string) []attr {
	var attrs []attr
	for i := 0; i < len(raw); {
		for i < len(raw) && isSpace(raw[i]) {
			i++
		}
		if i >= len(raw) {
			break
		}
		if raw[i] == '/' {
			break
		}
		start := i
		for i < len(raw) && !isSpace(raw[i]) && raw[i] != '=' && raw[i] != '/' {
			i++
		}
		name := raw[start:i]
		if name == "" {
			i++
			continue
		}
		attr := attr{name: name}
		for i < len(raw) && isSpace(raw[i]) {
			i++
		}
		if i < len(raw) && raw[i] == '=' {
			i++
			for i < len(raw) && isSpace(raw[i]) {
				i++
			}
			if i < len(raw) {
				attr.expr = raw[i] == '{'
				var value string
				value, i = scanAttrValue(raw, i)
				attr.value = value
			}
		}
		attrs = append(attrs, attr)
	}
	return attrs
}

// scanAttrValue reads an attribute value starting at raw[i] and returns it along
// with the offset just past the value. Quoted strings, Svelte expression braces
// and bare values are all supported; nested braces and quotes inside an
// expression are tracked so that `{a ? 'x' : 'y'}` is read as one value.
func scanAttrValue(raw string, i int) (string, int) {
	switch raw[i] {
	case '"', '\'':
		quote := raw[i]
		i++
		vs := i
		for i < len(raw) && raw[i] != quote {
			i++
		}
		value := raw[vs:i]
		if i < len(raw) {
			i++
		}
		return value, i
	case '{':
		depth := 0
		vs := i + 1
		for ; i < len(raw); i++ {
			switch raw[i] {
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					return raw[vs:i], i + 1
				}
			case '"', '\'':
				quote := raw[i]
				for i++; i < len(raw) && raw[i] != quote; i++ {
				}
			}
		}
		return raw[vs:], i
	default:
		vs := i
		for i < len(raw) && !isSpace(raw[i]) {
			i++
		}
		return raw[vs:i], i
	}
}

// hasClickHandler reports whether the tag is bound to a click event in either
// Svelte 4 (on:click) or Svelte 5 (onclick) syntax.
func hasClickHandler(attrs []attr) bool {
	for _, a := range attrs {
		n := strings.ToLower(a.name)
		if n == "on:click" || n == "onclick" || n == "on:pointerdown" || n == "on:mousedown" {
			return true
		}
	}
	return false
}

// isSubmitButton reports whether the tag is a form submit button, which is
// activated by its enclosing form's submit handler and needs no click binding.
func isSubmitButton(attrs []attr) bool {
	for _, a := range attrs {
		if strings.ToLower(a.name) == "type" && strings.EqualFold(strings.TrimSpace(a.value), "submit") {
			return true
		}
	}
	return false
}

// isStyleAttribute reports whether the tag carries an inline style: either the
// style attribute itself or one of Svelte's `style:property` directives, both
// of which the compiler renders into a style attribute on the element. A
// stylesheet rule is unaffected: Svelte extracts component CSS into the build's
// stylesheet, so a <style> block stays a same-origin CSS file.
func isStyleAttribute(tag tag) bool {
	for _, a := range tag.attrs {
		name := strings.ToLower(a.name)
		if name == "style" || strings.HasPrefix(name, "style:") {
			return true
		}
	}
	return false
}

// styleAttrRe finds the style attribute (or style: directive) inside a tag's
// attribute section. The leading separator is required so that a class named
// `style-guide` is not mistaken for the attribute itself.
var styleAttrRe = regexp.MustCompile(`(?i)(^|[\s/])style(:[A-Za-z-]+)?\s*=`)

// attributeRe builds a matcher for the named attribute inside a tag's
// attribute section. The leading separator is required so that an attribute
// whose name is a suffix of another (class vs. class:foo) is not matched by
// accident, and the `=` so that the match stops at the value.
func attributeRe(name string) *regexp.Regexp {
	return regexp.MustCompile(`(?i)(^|[\s/])` + regexp.QuoteMeta(name) + `\s*=`)
}

// attributeLine returns the line the attribute matched by re is written on -
// not the line the tag opens on, since a multi-line tag is the normal way to
// write Svelte markup - and reports false when that line carries checkui:allow.
func attributeLine(src string, tag tag, re *regexp.Regexp) (int, bool) {
	at, ok := attributeOffset(src, tag, re)
	if !ok {
		// Unreachable while the caller agreed with the pattern, but a finding
		// at the wrong line is worse than one at the tag's own line.
		at = tag.start
	}
	if isSuppressed(src, at) {
		return 0, false
	}
	return lineOf(src, at), true
}

// attributeOffset returns the offset in src of the attribute re matches, or
// false when the tag has no such attribute.
func attributeOffset(src string, tag tag, re *regexp.Regexp) (int, bool) {
	loc := re.FindStringIndex(src[tag.start:tag.end])
	if loc == nil {
		return 0, false
	}
	return tag.start + loc[0], true
}

// deadInterpolation finds a {placeholder} written inside a quoted string of an
// attribute expression, as in
//
//	class={cond ? 'row {indent()}' : 'row'}
//
// Svelte interpolates {placeholders} in quoted attribute *text* but not in a
// string literal inside an expression, so that text reaches the DOM verbatim:
// the row renders with a class literally called "{indent()}" and none of the
// styling it asked for. It is the same defect the tree-indent regression had,
// and nothing about it fails to compile or render.
func deadInterpolation(src string, tag tag) (int, bool) {
	for _, a := range tag.attrs {
		if !a.expr || isFunctionAttribute(a.name) {
			continue
		}
		off, ok := placeholderInString(a.value)
		if !ok {
			continue
		}
		at, _ := attributeOffset(src, tag, attributeRe(a.name))
		return at + off, true
	}
	return 0, false
}

// isFunctionAttribute reports whether the attribute takes a function or a
// directive rather than text, so a string literal in it is an argument and its
// braces are the argument's business.
func isFunctionAttribute(name string) bool {
	name = strings.ToLower(name)
	return strings.HasPrefix(name, "on") ||
		strings.HasPrefix(name, "bind") ||
		strings.HasPrefix(name, "use") ||
		strings.HasPrefix(name, "in:") ||
		strings.HasPrefix(name, "out:") ||
		strings.HasPrefix(name, "transition:") ||
		strings.HasPrefix(name, "animate:")
}

// placeholderInString returns the offset of the first { that sits inside a
// quoted string in value, and false when there is none. A value that contains a
// template literal is skipped: a backtick delimits a string too, but ${...}
// inside one is real interpolation and the quoting around it cannot be tracked
// with a one-pass scan.
func placeholderInString(value string) (int, bool) {
	if strings.ContainsRune(value, '`') {
		return 0, false
	}
	quote := byte(0)
	for i := 0; i < len(value); i++ {
		switch c := value[i]; {
		case c == '\\' && quote != 0:
			i++
		case quote == 0 && (c == '\'' || c == '"'):
			quote = c
		case c == quote:
			quote = 0
		case c == '{' && quote != 0:
			return i, true
		}
	}
	return 0, false
}

func isSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\f'
}

// lineOf returns the 1-based line number of a byte offset.
func lineOf(src string, off int) int {
	if off > len(src) {
		off = len(src)
	}
	return strings.Count(src[:off], "\n") + 1
}
