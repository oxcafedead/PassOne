// Command checkicon verifies that a Windows PE executable embeds an application
// icon resource (RT_GROUP_ICON and RT_ICON). Wails only links the icon, the
// application manifest and version information into the final binary when its
// packaging step runs (`wails build` without `-nopackage`); a build using
// `-nopackage` silently produces an exe with no icon resource at all, which shows
// a generic icon in Explorer and the taskbar. The tool is used as a CI quality
// gate immediately after the GUI binary is built.
package main

import (
	"encoding/binary"
	"fmt"
	"os"
)

// Standard Windows RT_* resource type identifiers.
const (
	rtIcon      = 3  // IMAGE_RESOURCE_TYPE_ICON
	rtGroupIcon = 14 // IMAGE_RESOURCE_TYPE_GROUP_ICON
	rtVersion   = 16 // IMAGE_RESOURCE_TYPE_VERSION
	rtManifest  = 24 // IMAGE_RESOURCE_TYPE_MANIFEST
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: checkicon <windows-exe>")
		os.Exit(2)
	}
	path := os.Args[1]

	found, err := resourceTypes(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "checkicon: %v\n", err)
		os.Exit(1)
	}

	types := make([]int, 0, len(found))
	for t := range found {
		types = append(types, int(t))
	}
	fmt.Printf("checkicon: resource types present: %v\n", types)

	if _, ok := found[rtGroupIcon]; !ok {
		fmt.Fprintf(os.Stderr,
			"checkicon: FAIL %s has no RT_GROUP_ICON resource (was it built with -nopackage?)\n", path)
		os.Exit(1)
	}
	if _, ok := found[rtIcon]; !ok {
		fmt.Fprintf(os.Stderr, "checkicon: FAIL %s has no RT_ICON resources\n", path)
		os.Exit(1)
	}
}

// pe holds the parsed layout of a PE file needed to locate its resources.
type pe struct {
	data    []byte
	resRoot int
	secs    []section
}

// readBytes returns a sub-slice of data or reports an error when it is out of range.
func (p *pe) readBytes(off, n int) ([]byte, error) {
	if off < 0 || off+n > len(p.data) || n < 0 {
		return nil, fmt.Errorf("offset %d out of bounds (file length %d)", off, len(p.data))
	}
	return p.data[off : off+n : off+n], nil
}

func (p *pe) u16(off int) (uint16, error) {
	b, err := p.readBytes(off, 2)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint16(b), nil
}

func (p *pe) u32(off int) (uint32, error) {
	b, err := p.readBytes(off, 4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b), nil
}

// resourceTypes returns the set of top-level RT_* type ids present in the PE
// file's resource directory.
func resourceTypes(path string) (map[uint32]bool, error) {
	pe, err := openPE(path)
	if err != nil {
		return nil, err
	}

	found := make(map[uint32]bool)
	if err := pe.walkDir(pe.resRoot, 0, found); err != nil {
		return nil, err
	}
	if len(found) == 0 {
		return nil, fmt.Errorf("%s has an empty resource directory; no icon resources embedded", path)
	}
	return found, nil
}

// resolve converts a resource directory pointer into a file offset. The Go
// linker stores such pointers relative to the resource directory root, while
// most other tooling uses absolute image-base RVAs, so both forms are accepted.
func (p *pe) resolve(ptr uint32) (int, error) {
	rva := uint64(ptr)
	best := p.resRoot + int(rva)
	for _, s := range p.secs {
		if rva >= uint64(s.va) && rva < uint64(s.va)+uint64(s.vsz) {
			return int(uint64(s.raw) + rva - uint64(s.va)), nil
		}
	}
	if best >= 0 && best <= len(p.data) {
		return best, nil
	}
	return 0, fmt.Errorf("resource pointer 0x%x resolves outside the file", ptr)
}

// section describes a PE section for the RVA-to-file-offset mapping.
type section struct {
	va, vsz, raw uint32
}

// openPE parses the DOS, COFF and optional headers and locates the resource
// directory, which must exist for a Windows application image.
func openPE(path string) (*pe, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	p := &pe{data: data}

	peOff, err := p.peHeaderOffset(path)
	if err != nil {
		return nil, err
	}
	coff := int(peOff) + 4
	numSec, err := p.u16(coff + 2)
	if err != nil {
		return nil, err
	}
	sizeOpt, err := p.u16(coff + 16)
	if err != nil {
		return nil, err
	}
	optOfs := coff + 20
	is64, err := p.is64BitOptionalHeader(optOfs)
	if err != nil {
		return nil, err
	}
	resRva, err := p.resourceDirectoryRVA(path, optOfs, is64)
	if err != nil {
		return nil, err
	}

	for i := 0; i < int(numSec); i++ {
		if err := p.addSection(optOfs + int(sizeOpt) + i*40); err != nil {
			return nil, err
		}
	}

	p.resRoot, err = p.rvaToOff(resRva)
	if err != nil {
		return nil, fmt.Errorf("locating resource directory: %w", err)
	}
	return p, nil
}

// peHeaderOffset validates the DOS stub and returns the offset of the PE
// signature. Both signatures are checked before any other field is read, so a
// file that is not a PE image fails with a message saying so rather than with a
// short-read error from wherever the first field happened to land.
func (p *pe) peHeaderOffset(path string) (uint32, error) {
	e, err := p.u16(0)
	if err != nil {
		return 0, err
	}
	if e != 0x5A4D { // "MZ"
		return 0, fmt.Errorf("%s is not a PE file (bad DOS signature)", path)
	}
	peOff, err := p.u32(0x3C)
	if err != nil {
		return 0, err
	}
	sig, err := p.u32(int(peOff))
	if err != nil {
		return 0, err
	}
	if sig != 0x00004550 { // "PE\0\0"
		return 0, fmt.Errorf("%s has no PE signature", path)
	}
	return peOff, nil
}

// is64BitOptionalHeader reports whether the optional header is
// IMAGE_OPTIONAL_HEADER64. It matters because the 64-bit header moves the data
// directory table, so every offset derived from it shifts with the answer.
func (p *pe) is64BitOptionalHeader(optOfs int) (bool, error) {
	magic, err := p.u16(optOfs)
	if err != nil {
		return false, err
	}
	// 0x20B is IMAGE_OPTIONAL_HEADER64, 0x10B the 32-bit one.
	return magic == 0x20B, nil
}

// resourceDirectoryRVA returns the RVA of the resource directory, which is data
// directory entry 2. A zero there is the exact failure this tool exists to
// catch, so it gets a message naming the build flag that causes it.
func (p *pe) resourceDirectoryRVA(path string, optOfs int, is64 bool) (uint32, error) {
	numDD, err := p.u32(optOfs + numDataDirectoryOffset(is64))
	if err != nil {
		return 0, err
	}
	if numDD <= 2 {
		return 0, fmt.Errorf("%s has no data directories", path)
	}
	resRva, err := p.u32(optOfs + dataDirectoryOffset(is64) + 2*8)
	if err != nil {
		return 0, err
	}
	if resRva == 0 {
		return 0, fmt.Errorf("%s has no resource directory (built with -nopackage?)", path)
	}
	return resRva, nil
}

// addSection appends one section header. A section with no raw data occupies no
// bytes in the file, so there is nothing for an RVA in it to map to.
func (p *pe) addSection(o int) error {
	vs, err := p.u32(o + 8)
	if err != nil {
		return err
	}
	va, err := p.u32(o + 12)
	if err != nil {
		return err
	}
	rawSz, err := p.u32(o + 16)
	if err != nil {
		return err
	}
	raw, err := p.u32(o + 20)
	if err != nil {
		return err
	}
	if rawSz == 0 {
		return nil
	}
	p.secs = append(p.secs, section{va: va, vsz: vs, raw: raw})
	return nil
}

func numDataDirectoryOffset(is64 bool) int {
	if is64 {
		return 108
	}
	return 92
}

func dataDirectoryOffset(is64 bool) int {
	if is64 {
		return 112
	}
	return 96
}

// rvaToOff maps a virtual address into a file offset using the section table.
func (p *pe) rvaToOff(rva uint32) (int, error) {
	for _, s := range p.secs {
		if uint64(rva) >= uint64(s.va) && uint64(rva) < uint64(s.va)+uint64(s.vsz) {
			return int(uint64(s.raw) + uint64(rva) - uint64(s.va)), nil
		}
	}
	return 0, fmt.Errorf("rva 0x%x falls in no section", rva)
}

// walkDir recursively visits a resource directory node. At depth 1 the entry ids
// are the RT_* type ids, which are recorded in found. Resource directories have
// at most three levels: type, name, then language.
func (p *pe) walkDir(off, depth int, found map[uint32]bool) error {
	if depth > 3 {
		return fmt.Errorf("resource directory nesting deeper than 3 levels at offset %d", off)
	}
	named, err := p.u16(off + 12)
	if err != nil {
		return err
	}
	ids, err := p.u16(off + 14)
	if err != nil {
		return err
	}
	count := int(named) + int(ids)
	base, err := p.readBytes(off+16, count*8)
	if err != nil {
		return fmt.Errorf("reading resource directory entries at offset %d: %w", off, err)
	}
	for i := 0; i < count; i++ {
		nameOrID := binary.LittleEndian.Uint32(base[i*8:])
		offTo := binary.LittleEndian.Uint32(base[i*8+4:])
		if err := p.walkEntry(nameOrID, offTo, depth, found); err != nil {
			return err
		}
	}
	return nil
}

// walkEntry visits one resource directory entry, which is either a subdirectory
// to descend into or a leaf that has to be readable.
func (p *pe) walkEntry(nameOrID, offTo uint32, depth int, found map[uint32]bool) error {
	if offTo&0x80000000 == 0 { // not IMAGE_RESOURCE_DATA_IS_DIRECTORY
		leaf, err := p.resolve(offTo)
		if err != nil {
			return fmt.Errorf("resolving resource leaf: %w", err)
		}
		// Reading the leaf's first word is only to prove the offset is inside
		// the file: a resource table pointing past the end is malformed.
		if _, err := p.u32(leaf); err != nil {
			return err
		}
		return nil
	}
	child, err := p.resolve(offTo & 0x7FFFFFFF)
	if err != nil {
		return fmt.Errorf("resolving resource subdirectory: %w", err)
	}
	if nameOrID&0x80000000 == 0 && depth == 0 {
		found[nameOrID] = true
	}
	return p.walkDir(child, depth+1, found)
}
