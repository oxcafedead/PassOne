package main

import (
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The bridge contract suite is the static half of the UI smoke coverage.
// cmd/gui/frontend/src/App.svelte reaches the backend only through the
// generated wailsjs/go/main/App.js, which calls the exported methods of *App by
// name at runtime. Nothing in that chain fails at compile time: rename a Go
// method and the frontend keeps calling the old name, Wails rejects the call at
// runtime, and the button that used it is silently dead. That is how the Edit
// button shipped broken.
//
// These tests close that loop with no browser and no extra tooling:
//
//   - every function the generated bindings export exists on *App, with the
//     same arity and compatible argument types;
//   - the JavaScript and TypeScript bindings describe the same API, so a stale
//     wailsjs checkout cannot pass;
//   - and every binding App.svelte imports is one the backend can actually
//     serve.
//
// tools/checkui already proves every <button> has a handler. This proves the
// handlers call something that exists.

const (
	frontendDir   = "frontend"
	appSveltePath = frontendDir + "/src/App.svelte"
	bindingsDir   = frontendDir + "/wailsjs/go/main"
	bindingsJS    = bindingsDir + "/App.js"
	bindingsDTS   = bindingsDir + "/App.d.ts"
)

// The generated files are machine-written and strictly one function per line:
//
//	export function CreatePassword(arg1,arg2,arg3,arg4) {
//	export function CreatePassword(arg1:string,arg2:string):Promise<string>;
var (
	jsExportRE  = regexp.MustCompile(`^export function (\w+)\(([^)]*)\)`)
	dtsExportRE = regexp.MustCompile(`^export function (\w+)\(([^)]*)\)\s*:`)
	dtsParamRE  = regexp.MustCompile(`^\s*(\w+)\s*:\s*(.+?)\s*$`)
)

// bindingSig is the parameter shape of one generated binding.
type bindingSig struct {
	arity    int
	argTypes []string // TypeScript declarations; empty when parsed from the JS
}

// bridgeMethod is one exported method of *App as the Wails runtime sees it.
type bridgeMethod struct {
	name    string
	arity   int
	inTypes []reflect.Type
}

// exportedBridgeMethods reflects over *App and returns the methods Wails binds.
func exportedBridgeMethods(t *testing.T) map[string]bridgeMethod {
	t.Helper()
	typ := reflect.TypeOf(&App{})
	out := make(map[string]bridgeMethod, typ.NumMethod())
	for i := 0; i < typ.NumMethod(); i++ {
		m := typ.Method(i)
		if m.Name == "NewApp" {
			continue // a constructor, not a bound method
		}
		// Wails cannot marshal a variadic signature; it would be bound as a
		// single slice argument and the frontend would never call it that way.
		if m.Type.IsVariadic() {
			t.Errorf("App.%s is variadic; Wails cannot bind it", m.Name)
			continue
		}
		// Method(i).Type is a method value: In(0) is the receiver, which is
		// not one of the arguments the frontend passes.
		bm := bridgeMethod{name: m.Name, arity: m.Type.NumIn() - 1}
		for j := 1; j < m.Type.NumIn(); j++ {
			bm.inTypes = append(bm.inTypes, m.Type.In(j))
		}
		out[m.Name] = bm
	}
	if len(out) == 0 {
		t.Fatal("no bridge methods found on *App")
	}
	return out
}

// TestBridgeBindingsMatchGoMethods is the core contract: the generated
// JavaScript bindings must describe exactly the methods *App exposes. A method
// added on the Go side without regenerating the bindings, or a binding left
// behind after a rename, fails here.
func TestBridgeBindingsMatchGoMethods(t *testing.T) {
	methods := exportedBridgeMethods(t)
	js := parseBindings(t, bindingsJS, jsExportRE)

	for _, name := range sortedKeys(methods) {
		want := methods[name]
		sig, ok := js[name]
		if !ok {
			t.Errorf("App.%s exists on *App but is missing from %s; "+
				"regenerate the bindings or the frontend cannot call it", name, bindingsJS)
			continue
		}
		if sig.arity != want.arity {
			t.Errorf("App.%s takes %d argument(s) in Go but %s passes %d",
				name, want.arity, bindingsJS, sig.arity)
		}
	}

	for _, name := range sortedKeys(js) {
		if _, ok := methods[name]; !ok {
			t.Errorf("%s exports %s but *App has no method %s; the binding is "+
				"stale and any call to it fails at runtime", bindingsJS, name, name)
		}
	}
}

// TestGeneratedBindingFilesAgree makes sure the checked-in wailsjs is not half
// regenerated: the JS and the type declarations must expose the same names.
func TestGeneratedBindingFilesAgree(t *testing.T) {
	js := parseBindings(t, bindingsJS, jsExportRE)
	ts := parseBindings(t, bindingsDTS, dtsExportRE)

	jsNames := sortedKeys(js)
	tsNames := sortedKeys(ts)
	if len(jsNames) == 0 || len(tsNames) == 0 {
		t.Fatalf("no bindings parsed (js=%d, dts=%d)", len(jsNames), len(tsNames))
	}
	for _, name := range jsNames {
		if _, ok := ts[name]; !ok {
			t.Errorf("%s is declared in %s but not in %s", name, bindingsJS, bindingsDTS)
		}
	}
	for _, name := range tsNames {
		if _, ok := js[name]; !ok {
			t.Errorf("%s is declared in %s but not in %s", name, bindingsDTS, bindingsJS)
		}
	}
	for _, name := range jsNames {
		sig, ok := ts[name]
		if !ok {
			continue
		}
		if sig.arity != js[name].arity {
			t.Errorf("%s takes %d argument(s) in %s but %d in %s",
				name, js[name].arity, bindingsJS, sig.arity, bindingsDTS)
		}
	}
}

// TestBridgeArgTypesMatchGoMethods checks the declared TypeScript parameter
// types against the Go signature. A wrong type is accepted by the JavaScript
// bundler and only fails when the Wails marshaller rejects the value, which in
// practice means a button that quietly stopped working.
func TestBridgeArgTypesMatchGoMethods(t *testing.T) {
	methods := exportedBridgeMethods(t)
	ts := parseBindings(t, bindingsDTS, dtsExportRE)

	for _, name := range sortedKeys(ts) {
		sig := ts[name]
		m, ok := methods[name]
		if !ok {
			continue // reported by TestBridgeBindingsMatchGoMethods
		}
		if len(sig.argTypes) != m.arity {
			t.Errorf("App.%s: %s declares %d parameter(s), Go takes %d",
				name, bindingsDTS, len(sig.argTypes), m.arity)
			continue
		}
		for i, tsType := range sig.argTypes {
			if !tsTypeCompatible(tsType, m.inTypes[i]) {
				t.Errorf("App.%s parameter %d is %q in %s but %s in Go",
					name, i+1, tsType, bindingsDTS, m.inTypes[i])
			}
		}
	}
}

// TestAppSvelteImportsResolve checks that every binding App.svelte imports is
// exported by the generated module and backed by a real *App method. A name the
// Go side dropped means the control calling it is dead at runtime.
func TestAppSvelteImportsResolve(t *testing.T) {
	methods := exportedBridgeMethods(t)
	js := parseBindings(t, bindingsJS, jsExportRE)

	imports := svelteAppImports(t)
	if len(imports) == 0 {
		t.Fatalf("no wailsjs/go/main/App.js import found in %s", appSveltePath)
	}
	for _, name := range imports {
		if _, ok := js[name]; !ok {
			t.Errorf("%s imports %s, which %s does not export", appSveltePath, name, bindingsJS)
			continue
		}
		if _, ok := methods[name]; !ok {
			t.Errorf("%s imports %s, but *App has no method %s: whatever calls "+
				"it is dead at runtime", appSveltePath, name, name)
		}
	}
}

// TestBridgeCoverageOfUIImports guards against the UI silently detaching from
// the backend, and logs the current coverage so a regression is visible in the
// test output.
func TestBridgeCoverageOfUIImports(t *testing.T) {
	js := parseBindings(t, bindingsJS, jsExportRE)
	imports := svelteAppImports(t)

	unused := make([]string, 0, len(js))
	for name := range js {
		if !containsString(imports, name) {
			unused = append(unused, name)
		}
	}
	sort.Strings(unused)
	// A few bindings are legitimately unused by the current UI. A large jump
	// means the frontend shrank or stopped calling the backend.
	const maxUnused = 6
	if len(unused) > maxUnused {
		t.Errorf("%d bindings are no longer imported by %s (was at most %d): %v",
			len(unused), appSveltePath, maxUnused, unused)
	}
	t.Logf("%d of %d generated bindings are used by the UI", len(imports), len(js))
}

// parseBindings reads a generated bindings file and returns the signature of
// every exported function, keyed by name.
func parseBindings(t *testing.T, path string, re *regexp.Regexp) map[string]bindingSig {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	out := map[string]bindingSig{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		m := re.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		name, rawArgs := m[1], m[2]
		if _, dup := out[name]; dup {
			t.Errorf("%s declares %s more than once", path, name)
		}
		sig := bindingSig{}
		for _, arg := range strings.Split(rawArgs, ",") {
			arg = strings.TrimSpace(arg)
			if arg == "" {
				continue
			}
			if pm := dtsParamRE.FindStringSubmatch(arg); pm != nil {
				sig.argTypes = append(sig.argTypes, pm[2])
			}
			sig.arity++
		}
		out[name] = sig
	}
	if len(out) == 0 {
		t.Fatalf("no exported functions found in %s", path)
	}
	return out
}

// svelteAppImports returns the identifiers App.svelte binds from the generated
// App.js module. The <script> block is TypeScript, not parseable as a whole
// here, so the single import list is read textually. The list is located by its
// module path rather than by the first "import {" in the file, which would be
// the Svelte runtime import.
func svelteAppImports(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(appSveltePath)
	if err != nil {
		t.Fatalf("read %s: %v", appSveltePath, err)
	}
	src := string(data)

	const marker = "wailsjs/go/main/App.js"
	modIdx := strings.Index(src, marker)
	if modIdx < 0 {
		return nil
	}
	start := strings.LastIndex(src[:modIdx], "import {")
	if start < 0 {
		return nil
	}
	end := strings.Index(src[start:], "}")
	if end < 0 {
		t.Fatalf("unterminated import list in %s", appSveltePath)
	}

	var names []string
	for _, part := range strings.Split(src[start+len("import {"):start+end], ",") {
		name := strings.TrimSpace(part)
		if name == "" {
			continue
		}
		if i := strings.Index(name, " as "); i >= 0 {
			name = strings.TrimSpace(name[i+len(" as "):])
		}
		names = append(names, name)
	}
	return names
}

// tsTypeCompatible reports whether a declared TypeScript parameter type can
// carry a Go value of type got. Wails marshals through JSON, so the
// correspondence is by JSON kind rather than by name.
func tsTypeCompatible(tsType string, got reflect.Type) bool {
	base := strings.TrimSpace(tsType)
	if i := strings.Index(base, "<"); i >= 0 {
		base = base[:i]
	}
	switch base {
	case "string":
		return got.Kind() == reflect.String
	case "number":
		return got.Kind() >= reflect.Int && got.Kind() <= reflect.Float64
	case "boolean":
		return got.Kind() == reflect.Bool
	}
	// Structs, slices and maps cross as opaque JSON values; the marshaller
	// handles them and the release smoke suite covers the behaviour.
	return true
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
