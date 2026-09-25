// Command checkui statically analyses the Svelte frontend for dead
// interactivity. A `<button>` that carries no event handler, or a handler
// function that nothing in the component references, renders fine, compiles
// fine and produces no Svelte compiler warning - it is simply inert at
// runtime, which is exactly the class of defect that shipped as "the Edit
// button does nothing". This tool turns both mistakes into build failures.
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
)

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
	if len(findings) == 0 {
		fmt.Printf("checkui: no dead interactivity found under %s\n", root)
		return
	}
	for _, f := range findings {
		fmt.Fprintln(os.Stderr, "checkui: FAIL "+f.String())
	}
	fmt.Fprintf(os.Stderr, "checkui: %d problem(s) found under %s\n", len(findings), root)
	os.Exit(1)
}

// CheckTree walks root for .svelte files and reports every dead-interactivity
// finding, sorted by file then line.
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
		if strings.HasSuffix(d.Name(), ".svelte") {
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
		all = append(all, CheckComponent(rel, string(src))...)
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
	var findings []Finding

	for _, tag := range scanTags(src) {
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

// tag is a parsed Svelte element open tag.
type tag struct {
	name  string
	line  int
	attrs []attr
}

// attr is a single parsed attribute on an element.
type attr struct {
	name  string
	value string
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
