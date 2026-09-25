package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckTreeFrontendHasNoDeadInteractivity(t *testing.T) {
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
		t.Errorf("found %d dead-interactivity problem(s) in the Svelte frontend:%s", len(findings), b.String())
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
