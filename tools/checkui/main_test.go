package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/net/html"
)

// TestCheckTreeFrontendIsClean runs the whole rule set over the real
// frontend: no dead interactivity, and no raw-markup escape hatch.
func TestCheckTreeFrontendIsClean(t *testing.T) {
	const root = "../../cmd/gui/frontend/src"
	findings, err := CheckTree(root)
	if err != nil {
		t.Fatalf("CheckTree(%q): %v", root, err)
	}
	if len(findings) != 0 {
		var b strings.Builder
		for _, f := range findings {
			b.WriteString("\n  " + f.String())
		}
		t.Errorf("found %d problem(s) in the Svelte frontend:%s", len(findings), b.String())
	}
}

func TestCheckComponentButtonNoHandler(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Finding
	}{
		{
			name: "button with no handler at all is reported",
			src:  `<button title="Edit">Edit</button>`,
			want: []Finding{{Line: 1, Rule: ruleButtonNoHandler}},
		},
		{
			name: "button with svelte 4 click handler is accepted",
			src:  "<button on:click={openEdit}>Edit</button>",
		},
		{
			name: "button with svelte 5 click handler is accepted",
			src:  `<button onclick={openEdit}>Edit</button>`,
		},
		{
			name: "submit button needs no click handler",
			src:  `<button type="submit" disabled={busy}>Save</button>`,
		},
		{
			name: "non-button elements are ignored",
			src:  `<div class="btn">Not a button</div>`,
		},
		{
			name: "handler on a sibling attribute does not count",
			src:  "<button class={x} title=\"Edit\">Edit</button>",
			want: []Finding{{Line: 1, Rule: ruleButtonNoHandler}},
		},
		{
			name: "line number points at the offending tag",
			src:  "<div>\n  <span/>\n  <button>Edit</button>\n</div>",
			want: []Finding{{Line: 3, Rule: ruleButtonNoHandler}},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := CheckComponent("App.svelte", tc.src)
			assertFindings(t, got, tc.want)
		})
	}
}

func TestCheckComponentOrphanHandler(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Finding
	}{
		{
			name: "unreferenced function is reported",
			src: `<script lang="ts">
	function openEdit(): void {}
	function reveal(): void {}
</script>
<button on:click={reveal}>Show</button>`,
			want: []Finding{{Line: 2, Rule: ruleOrphanHandler}},
		},
		{
			name: "function referenced from a script sibling is fine",
			src: `<script>
	function helper(): void {}
	function reveal(): void { helper() }
</script>
<button on:click={reveal}>Show</button>`,
		},
		{
			name: "function referenced only from markup is fine",
			src: `<script>
	function reveal(): void {}
</script>
<button on:click={reveal}>Show</button>`,
		},
		{
			name: "function with no script block cannot be orphaned",
			src:  `<button>Edit</button>`,
			want: []Finding{{Line: 1, Rule: ruleButtonNoHandler}},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := CheckComponent("App.svelte", tc.src)
			assertFindings(t, got, tc.want)
		})
	}
}

// TestScanTagsHandlesAttributeValues pins down the parser behaviour that a
// regexp-based scanner would get wrong: '>' inside quoted strings and inside
// Svelte expression braces must not terminate the tag early.
func TestScanTagsHandlesAttributeValues(t *testing.T) {
	src := `<button on:click={() => { if (a > b) { go() } }} data-x="a > b" class={c >= d ? 'x' : ''}>Go</button>`
	tags := scanTags(src)
	if len(tags) != 1 {
		t.Fatalf("scanTags returned %d tags, want 1", len(tags))
	}
	attrs := map[string]string{}
	for _, a := range tags[0].attrs {
		attrs[a.name] = a.value
	}
	if _, ok := attrs["on:click"]; !ok {
		t.Errorf("missing on:click in parsed attributes %v", attrs)
	}
	if got := attrs["data-x"]; got != "a > b" {
		t.Errorf("data-x = %q, want %q", got, "a > b")
	}
	if _, ok := attrs["class"]; !ok {
		t.Errorf("missing class in parsed attributes %v", attrs)
	}
}

func TestParseAttrs(t *testing.T) {
	raw := ` on:click={openEdit} title="Edit this entry" disabled={edBusy} autofocus `
	want := map[string]string{
		"on:click":  "openEdit",
		"title":     "Edit this entry",
		"disabled":  "edBusy",
		"autofocus": "",
	}
	got := map[string]string{}
	for _, a := range parseAttrs(raw) {
		got[a.name] = a.value
	}
	if len(got) != len(want) {
		t.Fatalf("parseAttrs(%q) = %v, want %v", raw, got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("attribute %q = %q, want %q", k, got[k], v)
		}
	}
}

func TestCheckTreeSkipsBuildOutput(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, root+"/node_modules/pkg/Widget.svelte", `<button>Inert</button>`)
	mustWrite(t, root+"/dist/Widget.svelte", `<button>Inert</button>`)
	mustWrite(t, root+"/src/Widget.svelte", "<button on:click={go}>Go</button>")

	findings, err := CheckTree(root)
	if err != nil {
		t.Fatalf("CheckTree: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("CheckTree scanned node_modules/dist: %v", findings)
	}
}

func TestCheckSinksRawHTML(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Finding
	}{
		{
			name: "{@html} is reported at its own line",
			src:  "<p>{@html entry.name}</p>",
			want: []Finding{{Line: 1, Rule: ruleRawHTML}},
		},
		{
			name: "plain interpolation is fine",
			src:  "<p>{entry.name}</p>",
		},
		{
			name: "{@const} and {@render} are not raw HTML",
			src:  "{#if x}{@const y = 1}{@render row()}{/if}",
		},
		{
			name: "svelte 5 snippet block is not raw HTML",
			src:  "{#snippet row()}<td>x</td>{/snippet}",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assertFindings(t, CheckSinks("App.svelte", tc.src), tc.want)
		})
	}
}

// TestCheckComponentInlineStyle pins the rule that keeps the style-src side of
// the CSP enforceable: a style attribute, a Svelte style: directive or a CSSOM
// write is dropped by the webview with no error, so the styling just vanishes.
func TestCheckComponentInlineStyle(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Finding
	}{
		{
			name: "a style attribute is reported",
			src:  `<div style="padding-left: 8px"></div>`,
			want: []Finding{{Line: 1, Rule: ruleInlineStyle}},
		},
		{
			name: "a svelte style: directive is reported",
			src:  "<button on:click={go} style:padding-left={depth * 14}>Go</button>",
			want: []Finding{{Line: 1, Rule: ruleInlineStyle}},
		},
		{
			name: "the line of the attribute is reported, not the line of the tag",
			src:  "<button\n  on:click={go}\n  class=\"entry-row\"\n  style=\"padding-left: 8px\">Go</button>",
			want: []Finding{{Line: 4, Rule: ruleInlineStyle}},
		},
		{
			name: "a class named style-guide is not the style attribute",
			src:  "<button\n  on:click={go}\n  class=\"style-guide\"\n  style=\"padding-left: 8px\">Go</button>",
			want: []Finding{{Line: 4, Rule: ruleInlineStyle}},
		},
		{
			name: "classes and stylesheet-driven properties are fine",
			src:  `<button on:click={go} class="entry-row {indentClass(row.depth)} flex">Go</button>`,
		},
		{
			name: "checkui:allow suppresses a deliberate style attribute",
			src:  `<div style="height: {h}px" > <!-- checkui:allow --></div>`,
			want: nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assertFindings(t, CheckComponent("App.svelte", tc.src), tc.want)
		})
	}
}

func TestCheckSinksDOMEval(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Finding
	}{
		{
			name: "innerHTML assignment is reported",
			src:  "el.innerHTML = detail",
			want: []Finding{{Line: 1, Rule: ruleHTMLSink}},
		},
		{
			name: "insertAdjacentHTML is reported",
			src:  "  host.insertAdjacentHTML('beforeend', body)",
			want: []Finding{{Line: 1, Rule: ruleHTMLSink}},
		},
		{
			name: "eval is reported",
			src:  "  const r = eval(expr)",
			want: []Finding{{Line: 1, Rule: ruleHTMLSink}},
		},
		{
			name: "eval at the start of a later line is reported",
			src:  "const f = run()\neval(f)",
			want: []Finding{{Line: 2, Rule: ruleHTMLSink}},
		},
		{
			name: "new Function is reported",
			src:  "const f = new Function('a', body)",
			want: []Finding{{Line: 1, Rule: ruleHTMLSink}},
		},
		{
			name: "document.write is reported",
			src:  "document.writeln(markup)",
			want: []Finding{{Line: 1, Rule: ruleHTMLSink}},
		},
		{
			name: "textContent and createElement are the safe way",
			src:  "el.textContent = detail\nel.className = 'x'\ndocument.createElement('span')",
		},
		{
			name: "a member named evaluate is not eval",
			src:  "await evaluator.evaluate(rows)",
		},
		{
			name: "one finding per line even with two sinks on it",
			src:  "el.innerHTML = a; el.outerHTML = b",
			want: []Finding{{Line: 1, Rule: ruleHTMLSink}},
		},
		{
			name: "line number points at the sink",
			src:  "function f() {\n\tconst s = 1\n\tel.innerHTML = s\n}",
			want: []Finding{{Line: 3, Rule: ruleHTMLSink}},
		},
		{
			name: "checkui:allow suppresses a deliberate use",
			src:  "el.innerHTML = sanitised // checkui:allow",
			want: nil,
		},
		{
			name: "suppression only applies to its own line",
			src:  "// checkui:allow\nel.innerHTML = sanitised",
			want: []Finding{{Line: 2, Rule: ruleHTMLSink}},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assertFindings(t, CheckModule("main.ts", tc.src), tc.want)
		})
	}
}

// TestCheckSinksInlineStyle covers the script-side ways to set an inline style,
// including the ones no markup scan can see.
// TestCheckComponentDeadInterpolation pins the rule that would have caught the
// tree-indent regression: a {placeholder} inside a quoted string in an
// attribute expression never interpolates, so the row renders with a class
// literally named "{indentClass(row.depth)}" and no indent at all.
func TestCheckComponentDeadInterpolation(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Finding
	}{
		{
			name: "a placeholder in a single-quoted branch is reported at the class attribute",
			src:  "<button\n  on:click={go}\n  class={on ? 'row {indentClass(d)}' : 'row'}>Go</button>",
			want: []Finding{{Line: 3, Rule: ruleDeadInterpolation}},
		},
		{
			name: "the same mistake in a double-quoted string is reported",
			src:  `<div class={on ? "row {x}" : "row"}></div>`,
			want: []Finding{{Line: 1, Rule: ruleDeadInterpolation}},
		},
		{
			name: "a dead placeholder in a title is reported too",
			src:  `<button on:click={go} title={a ? 'b {c}' : 'b'}>Go</button>`,
			want: []Finding{{Line: 1, Rule: ruleDeadInterpolation}},
		},
		{
			name: "a placeholder in quoted attribute text does interpolate",
			src:  `<div class="row {indentClass(d)}">x</div>`,
		},
		{
			name: "a template literal placeholder is real interpolation",
			src:  "<div class={`row ${indentClass(d)}`}></div>",
		},
		{
			name: "a call expression has no string to misread",
			src:  `<div class={indentClass(d)}>x</div>`,
		},
		{
			name: "a conditional with no placeholder is fine",
			src:  "<button on:click={go} class={on ? 'row row-active' : 'row'}>Go</button>",
		},
		{
			name: "a string argument to a handler is not a dead placeholder",
			src:  "<button on:click={() => select('{name}')}>Go</button>",
		},
		{
			name: "checkui:allow suppresses it",
			src:  "<div class={on ? 'row {x}' : 'row'}>y</div> // checkui:allow",
			want: nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assertFindings(t, CheckComponent("App.svelte", tc.src), tc.want)
		})
	}
}

func TestCheckSinksInlineStyle(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Finding
	}{
		{
			name: "a CSSOM property write is reported",
			src:  "  row.style.paddingLeft = '8px'",
			want: []Finding{{Line: 1, Rule: ruleInlineStyle}},
		},
		{
			name: "assigning cssText is reported",
			src:  "  el.style.cssText = 'padding:0'",
			want: []Finding{{Line: 1, Rule: ruleInlineStyle}},
		},
		{
			name: "setAttribute('style') is reported",
			src:  `el.setAttribute('style', 'background:red')`,
			want: []Finding{{Line: 1, Rule: ruleInlineStyle}},
		},
		{
			name: "createElement('style') is reported",
			src:  "  const s = document.createElement('style')",
			want: []Finding{{Line: 1, Rule: ruleInlineStyle}},
		},
		{
			name: "setting a class or a data attribute is the safe way",
			src:  "  el.className = 'entry-row-active'\n  el.dataset.depth = String(depth)",
		},
		{
			name: "a variable named style is not an inline style",
			src:  "  const style = compute(a, b)\n  apply(style)",
		},
		{
			name: "checkui:allow suppresses a deliberate CSSOM write",
			src:  "el.style.setProperty('--x', v) // checkui:allow",
			want: nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assertFindings(t, CheckModule("main.ts", tc.src), tc.want)
		})
	}
}

// TestCheckTreeScansModules pins down that the sink rules are not limited to
// .svelte: a helper module is just as capable of injecting markup.
func TestCheckTreeScansModules(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, root+"/helper.ts", "export const render = (el: HTMLElement, s: string) => { el.innerHTML = s }")

	findings, err := CheckTree(root)
	if err != nil {
		t.Fatalf("CheckTree: %v", err)
	}
	assertFindings(t, findings, []Finding{{Line: 1, Rule: ruleHTMLSink}})
}

func TestCheckIndexHTML(t *testing.T) {
	const meta = `<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self'; style-src 'self'"/>`
	tests := []struct {
		name string
		html string
		want []Finding
	}{
		{
			name: "a self-only script and style policy is accepted",
			html: "<html><head>" + meta + "</head><body></body></html>",
		},
		{
			name: "content before http-equiv is accepted too",
			html: `<html><head><meta content="default-src 'self'; script-src 'self'" http-equiv="content-security-policy"/></head></html>`,
		},
		{
			name: "a document with no policy is reported",
			html: "<html><head><title>PassOne</title></head><body></body></html>",
			want: []Finding{{Line: 1, Rule: ruleMissingCSP}},
		},
		{
			name: "script-src unsafe-inline is reported",
			html: `<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline'"/>`,
			want: []Finding{{Line: 1, Rule: ruleWeakCSP}},
		},
		{
			name: "unsafe-eval inherited from default-src is reported",
			html: `<meta http-equiv="Content-Security-Policy" content="default-src 'self' 'unsafe-eval'"/>`,
			want: []Finding{{Line: 1, Rule: ruleWeakCSP}},
		},
		{
			name: "a wildcard script source is reported",
			html: `<meta http-equiv="Content-Security-Policy" content="default-src *; script-src *"/>`,
			want: []Finding{{Line: 1, Rule: ruleWeakCSP}},
		},
		{
			name: "a policy with no default-src is reported",
			html: `<meta http-equiv="Content-Security-Policy" content="script-src 'self'; object-src 'none'"/>`,
			want: []Finding{{Line: 1, Rule: ruleWeakCSP}},
		},
		{
			// The reported Sonar finding: style-src 'unsafe-inline' lets
			// injected markup restyle the app, and a full-screen overlay is
			// all it takes to aim a click at the wrong row.
			name: "style-src unsafe-inline is reported",
			html: `<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"/>`,
			want: []Finding{{Line: 1, Rule: ruleWeakCSP}},
		},
		{
			name: "style-src-attr unsafe-inline is reported on its own",
			html: `<meta http-equiv="Content-Security-Policy" content="default-src 'self'; style-src-attr 'unsafe-inline'"/>`,
			want: []Finding{{Line: 1, Rule: ruleWeakCSP}},
		},
		{
			name: "style-src-elem unsafe-inline is reported on its own",
			html: `<meta http-equiv="Content-Security-Policy" content="default-src 'self'; style-src-elem 'unsafe-inline'"/>`,
			want: []Finding{{Line: 1, Rule: ruleWeakCSP}},
		},
		{
			name: "one relaxed style directive is one finding, however many names inherit it",
			html: `<meta http-equiv="Content-Security-Policy" content="default-src 'self'; style-src-attr 'unsafe-inline'; style-src-elem 'unsafe-inline'"/>`,
			want: []Finding{{Line: 1, Rule: ruleWeakCSP}},
		},
		{
			name: "an unsafe-inline no script or style directive inherits is not a finding",
			html: `<meta http-equiv="Content-Security-Policy" content="default-src 'self' 'unsafe-inline'; script-src 'self'; style-src 'self'"/>`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "index.html")
			mustWrite(t, path, tc.html)
			got, err := CheckIndexHTML(path)
			if err != nil {
				t.Fatalf("CheckIndexHTML: %v", err)
			}
			assertFindings(t, got, tc.want)
		})
	}
}

// TestFrontendIndexHTMLHasCSP is the real-file gate: the production entry
// document must ship the policy that turns a future injection bug into a broken
// panel instead of a full vault compromise.
func TestFrontendIndexHTMLHasCSP(t *testing.T) {
	const path = "../../cmd/gui/frontend/index.html"
	findings, err := CheckIndexHTML(path)
	if err != nil {
		t.Fatalf("CheckIndexHTML(%q): %v", path, err)
	}
	if len(findings) != 0 {
		var b strings.Builder
		for _, f := range findings {
			b.WriteString("\n  " + f.String())
		}
		t.Errorf("%s is not protected by a Content-Security-Policy:%s", path, b.String())
	}
}

// TestCSPSurvivesWailsRender guards an assumption that is invisible in the
// frontend: the Wails asset server does not hand index.html to the webview
// verbatim, it parses it with golang.org/x/net/html, injects its runtime
// <script src> tags and re-renders it. A meta tag that did not survive that
// round trip would leave the production app unprotected while every frontend
// test still passed.
func TestCSPSurvivesWailsRender(t *testing.T) {
	raw, err := os.ReadFile("../../cmd/gui/frontend/index.html")
	if err != nil {
		t.Fatalf("read index.html: %v", err)
	}
	node, err := html.Parse(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("parse index.html: %v", err)
	}
	// Mimic assetserver.insertScriptInHead for the two files Wails injects.
	for _, src := range []string{"/wails/runtime.js", "/wails/ipc.js"} {
		if !injectScript(node, src) {
			t.Fatalf("could not inject %s: index.html has no <head> for Wails to inject into", src)
		}
	}
	var buf bytes.Buffer
	if err := html.Render(&buf, node); err != nil {
		t.Fatalf("render index.html: %v", err)
	}
	// x/net/html re-encodes the quotes inside the policy as entities; the
	// browser decodes them while parsing, so assert against the decoded form.
	out := html.UnescapeString(buf.String())
	if !strings.Contains(out, "http-equiv=\"Content-Security-Policy\"") {
		t.Errorf("the CSP meta tag did not survive the Wails asset server round trip:\n%s", out)
	}
	if !strings.Contains(out, "script-src 'self'") {
		t.Errorf("the CSP directives did not survive the Wails asset server round trip:\n%s", out)
	}
	if !strings.Contains(out, "/wails/runtime.js") || !strings.Contains(out, "/wails/ipc.js") {
		t.Errorf("injected Wails runtime scripts missing, the round trip is not faithful:\n%s", out)
	}
}

// injectScript appends a <script src> element to the document head.
func injectScript(root *html.Node, src string) bool {
	var head *html.Node
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if head == nil && n.Type == html.ElementNode && n.Data == "head" {
			head = n
			return
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(root)
	if head == nil {
		return false
	}
	head.AppendChild(&html.Node{
		Type: html.ElementNode,
		Data: "script",
		Attr: []html.Attribute{{Key: "src", Val: src}, {Key: "type", Val: "text/javascript"}},
	})
	return true
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile(%q): %v", path, err)
	}
}

func assertFindings(t *testing.T, got, want []Finding) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d findings %v, want %d %v", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i].Rule != want[i].Rule || got[i].Line != want[i].Line {
			t.Errorf("finding %d = %s:%d %s, want line %d %s",
				i, got[i].File, got[i].Line, got[i].Rule, want[i].Line, want[i].Rule)
		}
	}
}
