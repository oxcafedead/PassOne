package main

import (
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// This tool is a CI gate: a bug in it either lets a `-nopackage` build through
// with no icon, or fails a good build. Neither shows up until someone runs it,
// so the parser is pinned here against synthetic images (where every field is
// known) and against a real Windows binary (where the linker chose the layout).

// Header layout of the synthetic images. None of these values have to match a
// real toolchain's choices; they only have to satisfy what checkicon reads.
const (
	synPEOffset  = 0x80
	synOptOffset = synPEOffset + 4 + 20
	synSizeOpt   = 240
	synSecVA     = 0x1000
	synSecVSZ    = 0x400
	synSecRaw    = 0x400
)

// Independent copies of the optional-header layouts. They are deliberately not
// taken from numDataDirectoryOffset/dataDirectoryOffset: a bug in those has to
// surface as a failing test, and an image writer that reused them would cancel
// the bug out instead.
const (
	synNumDataDirs64 = 108
	synNumDataDirs32 = 92
	synDataDir64     = 112
	synDataDir32     = 96

	// beyondFile is a root-relative offset no section covers and which lands
	// past the end of the image, so resolve must reject it.
	beyondFile = 0x7FFFFF00
)

// peImage builds a PE file byte by byte so a test can state exactly which field
// it is exercising.
type peImage struct {
	buf    []byte
	is64   bool
	resRVA uint32
}

// newPEImage writes DOS stub, PE signature, COFF header, a 64- or 32-bit
// optional header whose resource data directory points at the start of .rsrc,
// and one section header describing that section.
func newPEImage(is64 bool) *peImage {
	p := &peImage{buf: make([]byte, synSecRaw+synSecVSZ), is64: is64, resRVA: synSecVA}

	p.buf[0], p.buf[1] = 'M', 'Z'
	p.w32(0x3C, synPEOffset)
	copy(p.buf[synPEOffset:], "PE\x00\x00")

	coff := synPEOffset + 4
	p.w16(coff, 0x8664) // IMAGE_FILE_MACHINE_AMD64
	p.w16(coff+2, 1)    // NumberOfSections
	p.w16(coff+16, synSizeOpt)

	p.w16(synOptOffset, 0x10b) // IMAGE_OPTIONAL_HEADER32
	numDirs, dirTable := synNumDataDirs32, synDataDir32
	if is64 {
		p.w16(synOptOffset, 0x20b) // IMAGE_OPTIONAL_HEADER64
		numDirs, dirTable = synNumDataDirs64, synDataDir64
	}
	p.w32(synOptOffset+numDirs, 16) // NumberOfRvaAndSizes
	p.w32(synOptOffset+dirTable+2*8, p.resRVA)

	sec := synOptOffset + synSizeOpt
	copy(p.buf[sec:], ".rsrc\x00\x00\x00")
	p.w32(sec+8, synSecVSZ)  // VirtualSize
	p.w32(sec+12, synSecVA)  // VirtualAddress
	p.w32(sec+16, synSecVSZ) // SizeOfRawData
	p.w32(sec+20, synSecRaw) // PointerToRawData
	return p
}

func (p *peImage) w16(off int, v uint16) { binary.LittleEndian.PutUint16(p.buf[off:], v) }
func (p *peImage) w32(off int, v uint32) { binary.LittleEndian.PutUint32(p.buf[off:], v) }

// resEntry is one IMAGE_RESOURCE_DIRECTORY_ENTRY.
type resEntry struct {
	id    uint32
	rel   uint32 // offset from the directory root, as the Go linker stores it
	dir   bool   // true: a subdirectory to descend into; false: a data leaf
	named bool   // true: the id field is a name offset, not a type id
}

// resTree writes resource directory nodes into a peImage's .rsrc section and
// hands back the root-relative offsets that go in OffsetToData.
type resTree struct {
	img  *peImage
	base int
	next int
	root int
}

// newResTree reserves the root directory, which by definition sits at offset 0
// of the resource directory — that is the address the PE data directory points
// at, so a root written anywhere else would not be the one checkicon reads.
// rootEntries sizes the root's entry table; fill it in with setRoot once the
// children it points at have been allocated.
func newResTree(img *peImage, rootEntries int) *resTree {
	r := &resTree{img: img, base: synSecRaw}
	r.root = r.alloc(16 + rootEntries*8)
	return r
}

// alloc reserves n bytes at the end of the section and returns the file offset.
func (r *resTree) alloc(n int) int {
	off := r.base + r.next
	r.next += n
	return off
}

// leaf reserves a data entry and returns its root-relative offset. checkicon
// reads the leaf's first word only to prove the offset lands inside the file.
func (r *resTree) leaf() uint32 {
	r.alloc(4)
	return uint32(r.next - 4)
}

// node writes a directory whose counts match len(entries) and returns its
// root-relative offset.
func (r *resTree) node(entries ...resEntry) uint32 {
	off := r.alloc(16 + len(entries)*8)
	r.write(off, entries)
	return uint32(off - r.base)
}

// setRoot fills in the entry table of the root directory reserved by newResTree.
func (r *resTree) setRoot(entries ...resEntry) { r.write(r.root, entries) }

// write emits one IMAGE_RESOURCE_DIRECTORY: a fixed 16-byte header whose last
// two words are the named and id entry counts, then 8 bytes per entry.
func (r *resTree) write(off int, entries []resEntry) {
	var named, ids int
	for i, e := range entries {
		target := e.rel
		if e.dir {
			target |= 0x80000000
		}
		name := e.id
		if e.named {
			name |= 0x80000000
			named++
		} else {
			ids++
		}
		r.img.w32(off+16+i*8, name)
		r.img.w32(off+16+i*8+4, target)
	}
	r.img.w16(off+12, uint16(named))
	r.img.w16(off+14, uint16(ids))
}

// iconTree writes the shape every Windows GUI binary has: one subdirectory per
// resource type, each holding an id entry per resource, each holding a leaf.
// Types are RT_GROUP_ICON, RT_ICON, RT_VERSION and RT_MANIFEST.
func iconTree(img *peImage) {
	r := newResTree(img, 4)
	leaf := r.leaf()
	name := r.node(resEntry{id: 1, rel: leaf})
	group := r.node(resEntry{id: 1, rel: name})
	icon := r.node(resEntry{id: 1, rel: name})
	version := r.node(resEntry{id: 1, rel: leaf})
	manifest := r.node(resEntry{id: 1, rel: leaf})
	r.setRoot(
		resEntry{id: rtGroupIcon, rel: group, dir: true},
		resEntry{id: rtIcon, rel: icon, dir: true},
		resEntry{id: rtVersion, rel: version, dir: true},
		resEntry{id: rtManifest, rel: manifest, dir: true},
	)
}

// writePE puts the image on disk and returns its path.
func writePE(t *testing.T, img *peImage) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "image.exe")
	if err := os.WriteFile(path, img.buf, 0o600); err != nil {
		t.Fatalf("writing synthetic PE: %v", err)
	}
	return path
}

// versionOnlyTree writes a resource directory holding only RT_VERSION, which is
// what a `-nopackage` build produces: real resources, but no icon.
func versionOnlyTree(img *peImage) {
	r := newResTree(img, 1)
	leaf := r.leaf()
	version := r.node(resEntry{id: 1, rel: leaf})
	r.setRoot(resEntry{id: rtVersion, rel: version, dir: true})
}

// groupIconOnlyTree writes RT_GROUP_ICON with no RT_ICON behind it. The group
// icon directory is what Explorer reads, so this is the shape that shows an
// application with no icon at all while still passing the first check.
func groupIconOnlyTree(img *peImage) {
	r := newResTree(img, 1)
	leaf := r.leaf()
	group := r.node(resEntry{id: 1, rel: leaf})
	r.setRoot(resEntry{id: rtGroupIcon, rel: group, dir: true})
}

func TestResourceTypesFindsIconResources(t *testing.T) {
	for _, is64 := range []bool{true, false} {
		width := "32-bit"
		if is64 {
			width = "64-bit"
		}
		t.Run(width, func(t *testing.T) {
			img := newPEImage(is64)
			iconTree(img)
			found, err := resourceTypes(writePE(t, img))
			if err != nil {
				t.Fatalf("resourceTypes: %v", err)
			}
			for _, id := range []uint32{rtGroupIcon, rtIcon, rtVersion, rtManifest} {
				if !found[id] {
					t.Errorf("resource type %d not reported; got %v", id, keys(found))
				}
			}
			if len(found) != 4 {
				t.Errorf("got %d resource types %v, want exactly 4", len(found), keys(found))
			}
		})
	}
}

// TestResourceTypesReportsNamedRootEntriesAsUntyped: only numeric ids at depth 1
// are RT_* type ids. A named root entry is still walked (it can hold resources)
// but contributes no type, so it must not appear in the report.
func TestResourceTypesReportsNamedRootEntriesAsUntyped(t *testing.T) {
	img := newPEImage(true)
	r := newResTree(img, 2)
	leaf := r.leaf()
	group := r.node(resEntry{id: 1, rel: leaf})
	namedChild := r.node(resEntry{id: 1, rel: leaf})
	r.setRoot(
		resEntry{id: rtGroupIcon, rel: group, dir: true},
		resEntry{id: 0x1234, rel: namedChild, dir: true, named: true},
	)
	found, err := resourceTypes(writePE(t, img))
	if err != nil {
		t.Fatalf("resourceTypes: %v", err)
	}
	if !found[rtGroupIcon] || len(found) != 1 {
		t.Errorf("got %v, want only RT_GROUP_ICON", keys(found))
	}
}

// TestResourceTypesRejectsEmptyResourceDirectory: a directory that parses but
// holds nothing is exactly the "no icon was embedded" case, and it has to be an
// error rather than an empty success.
func TestResourceTypesRejectsEmptyResourceDirectory(t *testing.T) {
	img := newPEImage(true)
	newResTree(img, 0)
	_, err := resourceTypes(writePE(t, img))
	if err == nil || !strings.Contains(err.Error(), "empty resource directory") {
		t.Fatalf("got %v, want an empty-resource-directory error", err)
	}
}

// TestResourceTypesRejectsDeepNesting pins the three-level limit. Real resource
// directories are type/name/language; a fourth level means the parser is
// following a cycle or reading garbage, and it must say so rather than recurse.
func TestResourceTypesRejectsDeepNesting(t *testing.T) {
	img := newPEImage(true)
	r := newResTree(img, 1)
	leaf := r.leaf()
	l4 := r.node(resEntry{id: 1, rel: leaf})
	l3 := r.node(resEntry{id: 1, rel: l4, dir: true})
	l2 := r.node(resEntry{id: 1, rel: l3, dir: true})
	l1 := r.node(resEntry{id: 1, rel: l2, dir: true})
	r.setRoot(resEntry{id: rtIcon, rel: l1, dir: true})
	_, err := resourceTypes(writePE(t, img))
	if err == nil || !strings.Contains(err.Error(), "nesting deeper than 3 levels") {
		t.Fatalf("got %v, want a nesting-depth error", err)
	}
}

func TestResourceTypesRejectsMalformedImages(t *testing.T) {
	tests := []struct {
		name  string
		build func(t *testing.T) string
		want  string
	}{
		{
			name: "missing file",
			build: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "absent.exe")
			},
			want: "cannot find",
		},
		{
			name: "not a PE image",
			build: func(t *testing.T) string {
				img := newPEImage(true)
				img.buf[0] = 'X'
				return writePE(t, img)
			},
			want: "bad DOS signature",
		},
		{
			name: "truncated before the PE offset is readable",
			build: func(t *testing.T) string {
				img := newPEImage(true)
				img.buf = img.buf[:0x20]
				return writePE(t, img)
			},
			want: "out of bounds",
		},
		{
			name: "no PE signature at the declared offset",
			build: func(t *testing.T) string {
				img := newPEImage(true)
				img.w32(synPEOffset, 0x00004551)
				return writePE(t, img)
			},
			want: "no PE signature",
		},
		{
			name: "truncated inside the section table",
			build: func(t *testing.T) string {
				img := newPEImage(true)
				img.buf = img.buf[:synOptOffset+synSizeOpt+8]
				return writePE(t, img)
			},
			want: "out of bounds",
		},
		{
			name: "too few data directories to hold the resource entry",
			build: func(t *testing.T) string {
				img := newPEImage(true)
				img.w32(synOptOffset+synNumDataDirs64, 2)
				return writePE(t, img)
			},
			want: "no data directories",
		},
		{
			name: "no resource directory",
			build: func(t *testing.T) string {
				img := newPEImage(true)
				img.w32(synOptOffset+synDataDir64+2*8, 0)
				return writePE(t, img)
			},
			want: "no resource directory",
		},
		{
			name: "resource RVA in no section",
			build: func(t *testing.T) string {
				img := newPEImage(true)
				img.w32(synOptOffset+synDataDir64+2*8, 0x7000)
				return writePE(t, img)
			},
			want: "falls in no section",
		},
		{
			name: "truncated inside the resource tree",
			build: func(t *testing.T) string {
				img := newPEImage(true)
				iconTree(img)
				img.buf = img.buf[:synSecRaw+20]
				return writePE(t, img)
			},
			want: "out of bounds",
		},
		{
			name: "resource leaf offset past the end of the file",
			build: func(t *testing.T) string {
				img := newPEImage(true)
				r := newResTree(img, 1)
				child := r.node(resEntry{id: 1, rel: beyondFile})
				r.setRoot(resEntry{id: rtIcon, rel: child, dir: true})
				return writePE(t, img)
			},
			want: "resolving resource leaf",
		},
		{
			name: "resource subdirectory offset past the end of the file",
			build: func(t *testing.T) string {
				img := newPEImage(true)
				r := newResTree(img, 1)
				child := r.node(resEntry{id: 1, rel: beyondFile, dir: true})
				r.setRoot(resEntry{id: rtIcon, rel: child, dir: true})
				return writePE(t, img)
			},
			want: "resolving resource subdirectory",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := resourceTypes(tc.build(t))
			if err == nil {
				t.Fatalf("expected an error mentioning %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

// TestResourceTypesOnRealWindowsBinary parses a PE this repository did not
// write. link.exe stores resource offsets as absolute RVAs, which the synthetic
// images never produce, so this is the only test that covers the section-table
// arm of resolve against real linker output.
func TestResourceTypesOnRealWindowsBinary(t *testing.T) {
	root := os.Getenv("SystemRoot")
	if root == "" {
		t.Skip("SystemRoot is not set")
	}
	candidates := []string{
		filepath.Join(root, "System32", "notepad.exe"),
		filepath.Join(root, "explorer.exe"),
		filepath.Join(root, "System32", "explorer.exe"),
	}
	var path string
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			path = c
			break
		}
	}
	if path == "" {
		t.Skip("no known Windows GUI binary found to parse")
	}
	found, err := resourceTypes(path)
	if err != nil {
		t.Fatalf("resourceTypes(%q): %v", path, err)
	}
	if !found[rtGroupIcon] {
		t.Errorf("%s reported no RT_GROUP_ICON; got %v", path, keys(found))
	}
	if !found[rtIcon] {
		t.Errorf("%s reported no RT_ICON; got %v", path, keys(found))
	}
}

// TestResolve covers both pointer conventions. The Go linker stores offsets
// relative to the resource root, which no section contains, so the fallback
// applies; link.exe stores absolute RVAs, which the section table resolves.
func TestResolve(t *testing.T) {
	p := &pe{
		data:    make([]byte, 0x1000),
		resRoot: 0x400,
		secs:    []section{{va: 0x1000, vsz: 0x400, raw: 0x800}},
	}
	tests := []struct {
		name string
		ptr  uint32
		want int
	}{
		{name: "rva inside the section", ptr: 0x1100, want: 0x900},
		{name: "first byte of the section", ptr: 0x1000, want: 0x800},
		{name: "last byte of the section", ptr: 0x13FF, want: 0xBFF},
		{name: "root-relative fallback", ptr: 0x40, want: 0x440},
		{name: "root-relative fallback at zero", ptr: 0, want: 0x400},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := p.resolve(tc.ptr)
			if err != nil {
				t.Fatalf("resolve(0x%x): %v", tc.ptr, err)
			}
			if got != tc.want {
				t.Errorf("resolve(0x%x) = 0x%x, want 0x%x", tc.ptr, got, tc.want)
			}
		})
	}

	if _, err := p.resolve(0x9000); err == nil {
		t.Error("resolve past the end of the file should fail")
	} else if !strings.Contains(err.Error(), "outside the file") {
		t.Errorf("got %q, want it to mention being outside the file", err)
	}
}

func TestRVAToOff(t *testing.T) {
	p := &pe{
		data: make([]byte, 0x1000),
		secs: []section{
			{va: 0x1000, vsz: 0x100, raw: 0x400},
			{va: 0x2000, vsz: 0x100, raw: 0x600},
		},
	}
	got, err := p.rvaToOff(0x2050)
	if err != nil {
		t.Fatalf("rvaToOff: %v", err)
	}
	if want := 0x650; got != want {
		t.Errorf("rvaToOff(0x2050) = 0x%x, want 0x%x", got, want)
	}
	if _, err := p.rvaToOff(0x3000); err == nil {
		t.Error("rvaToOff for an unmapped RVA should fail")
	}
}

// TestAddSectionSkipsSectionsWithoutRawData: a section with no raw data occupies
// no bytes in the file, so an RVA pointing into it cannot be mapped to anything.
// Registering it anyway would make rvaToOff answer with an offset that reads
// whatever bytes happen to sit there.
func TestAddSectionSkipsSectionsWithoutRawData(t *testing.T) {
	withData := &pe{data: newPEImage(true).buf}
	if err := withData.addSection(synOptOffset + synSizeOpt); err != nil {
		t.Fatalf("addSection: %v", err)
	}
	if len(withData.secs) != 1 {
		t.Fatalf("got %d sections, want 1", len(withData.secs))
	}

	img := newPEImage(true)
	img.w32(synOptOffset+synSizeOpt+16, 0) // SizeOfRawData
	empty := &pe{data: img.buf}
	if err := empty.addSection(synOptOffset + synSizeOpt); err != nil {
		t.Fatalf("addSection: %v", err)
	}
	if len(empty.secs) != 0 {
		t.Errorf("a section with no raw data was kept: %+v", empty.secs)
	}
	if err := empty.addSection(len(empty.data) - 4); err == nil {
		t.Error("addSection past the end of the file should fail")
	}
}

// TestOptionalHeaderOffsets pins the two tables the whole parse depends on. The
// 64-bit header moves the data directory, so every offset derived from the
// answer shifts; a silent swap would read the wrong directory as the resource
// one.
func TestOptionalHeaderOffsets(t *testing.T) {
	if got := numDataDirectoryOffset(true); got != synNumDataDirs64 {
		t.Errorf("numDataDirectoryOffset(64-bit) = %d, want %d", got, synNumDataDirs64)
	}
	if got := numDataDirectoryOffset(false); got != synNumDataDirs32 {
		t.Errorf("numDataDirectoryOffset(32-bit) = %d, want %d", got, synNumDataDirs32)
	}
	if got := dataDirectoryOffset(true); got != synDataDir64 {
		t.Errorf("dataDirectoryOffset(64-bit) = %d, want %d", got, synDataDir64)
	}
	if got := dataDirectoryOffset(false); got != synDataDir32 {
		t.Errorf("dataDirectoryOffset(32-bit) = %d, want %d", got, synDataDir32)
	}

	wide := &pe{data: newPEImage(true).buf}
	narrow := &pe{data: newPEImage(false).buf}
	for _, tc := range []struct {
		name string
		p    *pe
		want bool
	}{
		{name: "IMAGE_OPTIONAL_HEADER64", p: wide, want: true},
		{name: "IMAGE_OPTIONAL_HEADER32", p: narrow, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.p.is64BitOptionalHeader(synOptOffset)
			if err != nil {
				t.Fatalf("is64BitOptionalHeader: %v", err)
			}
			if got != tc.want {
				t.Errorf("is64BitOptionalHeader = %v, want %v", got, tc.want)
			}
		})
	}
	if _, err := (&pe{data: []byte{0}}).is64BitOptionalHeader(0); err == nil {
		t.Error("is64BitOptionalHeader on an empty file should fail")
	}
}

func TestReadBytesBounds(t *testing.T) {
	p := &pe{data: []byte{1, 2, 3, 4}}
	tests := []struct {
		name    string
		off, n  int
		wantErr bool
	}{
		{name: "exact fit", off: 0, n: 4},
		{name: "interior slice", off: 1, n: 2},
		{name: "empty read at the end", off: 4, n: 0},
		{name: "past the end", off: 3, n: 2, wantErr: true},
		{name: "negative offset", off: -1, n: 1, wantErr: true},
		{name: "negative length", off: 0, n: -1, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := p.readBytes(tc.off, tc.n)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("readBytes(%d, %d) succeeded, want an error", tc.off, tc.n)
				}
				if !strings.Contains(err.Error(), "out of bounds") {
					t.Errorf("got %q, want it to mention being out of bounds", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("readBytes(%d, %d): %v", tc.off, tc.n, err)
			}
			if len(got) != tc.n {
				t.Errorf("got %d bytes, want %d", len(got), tc.n)
			}
		})
	}
}

// The gate's own exit codes are the contract the CI step depends on: 2 for a
// usage mistake, 1 for a binary that should have been rejected, 0 to pass.
// main calls os.Exit, so it runs in a re-invoked copy of this test binary.
const (
	checkiconHelperEnv = "PASSONE_TEST_CHECKICON_HELPER"
	checkiconArgvEnv   = "PASSONE_TEST_CHECKICON_ARGV"
	checkiconArgSep    = "\x1f"

	exitOK    = 0
	exitFail  = 1
	exitUsage = 2
)

// TestHelperCheckicon is not a real test: as a subprocess it runs main() with
// the argv supplied in checkiconArgvEnv. The two variables are separate because
// "no arguments" is itself a case under test, and an empty argv has to be
// distinguishable from "this process is not the helper".
func TestHelperCheckicon(t *testing.T) {
	if os.Getenv(checkiconHelperEnv) == "" {
		return
	}
	os.Args = []string{"checkicon"}
	if argv := os.Getenv(checkiconArgvEnv); argv != "" {
		os.Args = append(os.Args, strings.Split(argv, checkiconArgSep)...)
	}
	main()
}

func TestCheckiconExitCodes(t *testing.T) {
	withIcon := func(t *testing.T) string {
		img := newPEImage(true)
		iconTree(img)
		return writePE(t, img)
	}
	withoutGroupIcon := func(t *testing.T) string {
		img := newPEImage(true)
		r := newResTree(img, 2)
		leaf := r.leaf()
		icon := r.node(resEntry{id: 1, rel: leaf})
		version := r.node(resEntry{id: 1, rel: leaf})
		r.setRoot(
			resEntry{id: rtIcon, rel: icon, dir: true},
			resEntry{id: rtVersion, rel: version, dir: true},
		)
		return writePE(t, img)
	}
	withoutIcon := func(t *testing.T) string {
		img := newPEImage(true)
		groupIconOnlyTree(img)
		return writePE(t, img)
	}
	withoutAnyIcon := func(t *testing.T) string {
		img := newPEImage(true)
		versionOnlyTree(img)
		return writePE(t, img)
	}

	tests := []struct {
		name     string
		argv     []string
		build    func(t *testing.T) string
		wantCode int
		wantErr  string
	}{
		{
			name:     "a correctly packaged binary passes",
			build:    withIcon,
			wantCode: exitOK,
		},
		{
			name:     "no RT_GROUP_ICON is the -nopackage failure",
			build:    withoutGroupIcon,
			wantCode: exitFail,
			wantErr:  "-nopackage",
		},
		{
			name:     "a group icon with no RT_ICON is rejected",
			build:    withoutIcon,
			wantCode: exitFail,
			wantErr:  "no RT_ICON resources",
		},
		{
			name:     "resources but no icon at all is the -nopackage failure",
			build:    withoutAnyIcon,
			wantCode: exitFail,
			wantErr:  "-nopackage",
		},
		{
			name:     "no argument is a usage error",
			argv:     nil,
			wantCode: exitUsage,
			wantErr:  "usage: checkicon",
		},
		{
			name:     "too many arguments is a usage error",
			argv:     []string{"a.exe", "b.exe"},
			wantCode: exitUsage,
			wantErr:  "usage: checkicon",
		},
		{
			name:     "an unparsable binary fails with the parse error",
			argv:     []string{filepath.Join(t.TempDir(), "absent.exe")},
			wantCode: exitFail,
			wantErr:  "cannot find",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			argv := tc.argv
			if tc.build != nil {
				argv = []string{tc.build(t)}
			}
			code, output := runCheckicon(t, argv)
			if code != tc.wantCode {
				t.Errorf("exit code %d, want %d (output: %s)", code, tc.wantCode, output)
			}
			if tc.wantErr != "" && !strings.Contains(output, tc.wantErr) {
				t.Errorf("output %q does not mention %q", output, tc.wantErr)
			}
		})
	}
}

// runCheckicon re-invokes this test binary as the checkicon CLI and returns its
// exit code together with everything it printed.
func runCheckicon(t *testing.T, argv []string) (int, string) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	cmd := exec.Command(exe, "-test.run=TestHelperCheckicon")
	cmd.Env = append(os.Environ(),
		checkiconHelperEnv+"=1",
		checkiconArgvEnv+"="+strings.Join(argv, checkiconArgSep),
	)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return exitOK, string(out)
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("running the checkicon helper: %v (%s)", err, out)
	}
	code := exit.ExitCode()
	if code == -1 {
		t.Fatalf("helper did not exit normally: %v (%s)", err, out)
	}
	return code, string(out)
}

// keys renders a resource-type set in ascending order for readable failures.
func keys(m map[uint32]bool) []int {
	out := make([]int, 0, len(m))
	for k, v := range m {
		if v {
			out = append(out, int(k))
		}
	}
	slices.Sort(out)
	return out
}
