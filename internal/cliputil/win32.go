package cliputil

import (
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	// cfUnicodeText is the Win32 CF_UNICODETEXT clipboard format: the one every
	// text consumer reads.
	cfUnicodeText = 13
	// gmemMoveable is the GlobalAlloc flag the clipboard requires for the
	// handles it takes ownership of.
	gmemMoveable = 0x0002
)

var (
	user32   = windows.NewLazySystemDLL("user32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procOpenClipboard           = user32.NewProc("OpenClipboard")
	procCloseClipboard          = user32.NewProc("CloseClipboard")
	procEmptyClipboard          = user32.NewProc("EmptyClipboard")
	procGetClipboardData        = user32.NewProc("GetClipboardData")
	procSetClipboardData        = user32.NewProc("SetClipboardData")
	procRegisterClipboardFormat = user32.NewProc("RegisterClipboardFormatW")

	procGlobalAlloc  = kernel32.NewProc("GlobalAlloc")
	procGlobalFree   = kernel32.NewProc("GlobalFree")
	procGlobalLock   = kernel32.NewProc("GlobalLock")
	procGlobalUnlock = kernel32.NewProc("GlobalUnlock")
	procGlobalSize   = kernel32.NewProc("GlobalSize")
	procGetProcess   = kernel32.NewProc("GetCurrentProcess")
	procReadProcess  = kernel32.NewProc("ReadProcessMemory")
	procWriteProcess = kernel32.NewProc("WriteProcessMemory")
)

// historySuppression lists the registered clipboard formats that tell Windows
// not to keep a copy of what we place on the clipboard; see the "Cloud
// Clipboard and Clipboard History Formats" section of the Win32 clipboard
// documentation.
//
// This is the only lever that reaches Clipboard History and the cloud
// clipboard. Both snapshot the item as it is set, so no later clear can remove
// what they already took, and neither offers an API for deleting a single item.
// The names are only honoured from Windows 10 1809 on, which is why the outcome
// is reported back to the caller instead of assumed.
//
// ExcludeClipboardContentFromMonitorProcessing is documented as taking "any
// data" and is the strongest of the three; the Can* formats are read as a
// boolean and take a zero to mean "no".
var historySuppression = []namedDword{
	{name: "ExcludeClipboardContentFromMonitorProcessing", value: 1},
	{name: "CanIncludeInClipboardHistory", value: 0},
	{name: "CanUploadToCloudClipboard", value: 0},
}

// namedDword is a registered clipboard format plus the DWORD stored under it.
type namedDword struct {
	name  string
	value uint32
}

// resolvedFormat is a namedDword whose registered format ID is known.
type resolvedFormat struct {
	id    uint32
	value uint32
}

// writeText replaces the clipboard content with text and stores the value of
// every entry in extra under its registered format. The text always goes on
// first, so a format Windows refuses to register costs the caller a warning
// rather than the copy itself; the boolean reports whether every requested
// format made it onto the clipboard.
func writeText(text string, extra []namedDword) (bool, error) {
	words, err := windows.UTF16FromString(text)
	if err != nil {
		return false, fmt.Errorf("clipboard text cannot contain a NUL character: %w", err)
	}
	complete := true
	resolved := make([]resolvedFormat, 0, len(extra))
	for _, f := range extra {
		id, err := registerFormat(f.name)
		if err != nil {
			complete = false
			continue
		}
		resolved = append(resolved, resolvedFormat{id: id, value: f.value})
	}

	err = withClipboard(openAttempts, openRetryDelay, func() error {
		if _, err := win32(procEmptyClipboard); err != nil {
			return fmt.Errorf("could not empty the clipboard: %w", err)
		}
		if err := setFormat(cfUnicodeText, utf16Bytes(words)); err != nil {
			return fmt.Errorf("could not set the clipboard text: %w", err)
		}
		for _, f := range resolved {
			if err := setFormat(f.id, dwordBytes(f.value)); err != nil {
				complete = false
			}
		}
		return nil
	})
	if err != nil {
		return false, err
	}
	return complete, nil
}

// readText returns the current CF_UNICODETEXT content. An empty string with a
// nil error means the clipboard holds no text, which is not a failure.
func readText(attempts int, delay time.Duration) (string, error) {
	var text string
	err := withClipboard(attempts, delay, func() error {
		h, present := win32Optional(procGetClipboardData, cfUnicodeText)
		if !present {
			return nil // the clipboard carries no text format
		}
		b, err := globalRead(h)
		if err != nil {
			return err
		}
		text = utf16FromBytes(b)
		return nil
	})
	if err != nil {
		return "", err
	}
	return text, nil
}

// withClipboard runs fn with the clipboard open.
//
// The goroutine is pinned to one OS thread for the whole open/use/close
// sequence: Windows tracks the clipboard per window, and a thread that opens it
// while another closes it can leave the sequence wedged. Only one process may
// own the clipboard at a time, so the open is retried while another application
// holds it, since that contention is normal rather than exceptional.
func withClipboard(attempts int, delay time.Duration, fn func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err := openClipboard(attempts, delay); err != nil {
		return err
	}
	defer closeClipboard()
	return fn()
}

func openClipboard(attempts int, delay time.Duration) error {
	var err error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			time.Sleep(delay)
		}
		// A null window handle makes this process, rather than one of its
		// windows, the clipboard owner; it is what a console app uses.
		if _, err = win32(procOpenClipboard, 0); err == nil {
			return nil
		}
	}
	return fmt.Errorf("could not open the clipboard after %d attempts: %w", attempts, err)
}

// closeClipboard releases the clipboard. A failure here leaves the sequence
// empty rather than open, and leaves nothing useful for the caller to do.
func closeClipboard() { ignore(procCloseClipboard) }

// setFormat stores data under a clipboard format. The Win32 API takes ownership
// of the global block on success, so a failure has to release it here.
func setFormat(format uint32, data []byte) error {
	h := allocGlobal(data)
	if h == 0 {
		return errors.New("could not allocate clipboard memory")
	}
	if _, err := win32(procSetClipboardData, uintptr(format), h); err != nil {
		freeGlobal(h)
		return err
	}
	return nil
}

// allocGlobal copies data into a moveable global memory block and returns its
// handle, or 0 when any step failed. data must not be empty.
func allocGlobal(data []byte) uintptr {
	h, err := win32(procGlobalAlloc, gmemMoveable, uintptr(len(data)))
	if err != nil {
		return 0
	}
	if err := globalWrite(h, data); err != nil {
		freeGlobal(h)
		return 0
	}
	return h
}

func freeGlobal(h uintptr) { ignore(procGlobalFree, h) }

// globalWrite copies data into the global block h. Note the argument order:
// WriteProcessMemory takes the destination before the source, while
// ReadProcessMemory takes the source first.
func globalWrite(h uintptr, data []byte) error {
	p, err := win32(procGlobalLock, h)
	if err != nil {
		return fmt.Errorf("could not lock clipboard memory: %w", err)
	}
	defer ignore(procGlobalUnlock, h)

	var written uintptr
	self, err := currentProcess()
	if err != nil {
		return err
	}
	if _, err := win32(procWriteProcess, self, p, pointerTo(data), uintptr(len(data)), pointerToValue(&written)); err != nil {
		return fmt.Errorf("could not fill clipboard memory: %w", err)
	}
	if written != uintptr(len(data)) {
		return fmt.Errorf("wrote %d of %d clipboard bytes", written, len(data))
	}
	return nil
}

// globalRead returns a copy of the contents of the global block h. The block is
// the source of the read, as opposed to its destination in globalWrite.
func globalRead(h uintptr) ([]byte, error) {
	size, err := win32(procGlobalSize, h)
	if err != nil {
		return nil, fmt.Errorf("could not size clipboard memory: %w", err)
	}
	p, err := win32(procGlobalLock, h)
	if err != nil {
		return nil, fmt.Errorf("could not lock clipboard memory: %w", err)
	}
	defer ignore(procGlobalUnlock, h)

	b := make([]byte, size)
	var read uintptr
	self, err := currentProcess()
	if err != nil {
		return nil, err
	}
	if _, err := win32(procReadProcess, self, p, pointerTo(b), size, pointerToValue(&read)); err != nil {
		return nil, fmt.Errorf("could not read clipboard memory: %w", err)
	}
	if read != size {
		return nil, fmt.Errorf("read %d of %d clipboard bytes", read, size)
	}
	return b, nil
}

// currentProcess returns the pseudo-handle of this process, which the
// Read/WriteProcessMemory calls below need.
func currentProcess() (uintptr, error) {
	h, err := win32(procGetProcess)
	if err != nil {
		return 0, fmt.Errorf("could not get the current process handle: %w", err)
	}
	return h, nil
}

// pointerTo returns the address of a Go buffer so it can be passed to a Win32
// call. It is only ever used as a call argument: the copies above all land in
// non-Go memory, so no Go pointer is retained past the call, and the reverse
// direction (turning a foreign address into an unsafe.Pointer) is avoided
// outright because go vet rejects it.
func pointerTo(b []byte) uintptr {
	return uintptr(unsafe.Pointer(unsafe.SliceData(b)))
}

// pointerToValue is pointerTo for the single out-parameter that
// ReadProcessMemory and WriteProcessMemory write back.
func pointerToValue(v *uintptr) uintptr {
	return uintptr(unsafe.Pointer(v))
}

// registerFormat maps a format name to the ID Windows assigned it, which is
// stable for the rest of the session once registered. A zero ID means Windows
// would not recognise the name, which for the history formats means this build
// cannot be told to skip them.
func registerFormat(name string) (uint32, error) {
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	id, err := win32(procRegisterClipboardFormat, uintptr(unsafe.Pointer(p)))
	if err != nil {
		return 0, fmt.Errorf("registering clipboard format %s: %w", name, err)
	}
	return uint32(id), nil
}

// win32 calls a procedure and reports a zero result as a failure, keeping the
// last error the API set. It is the form every call here wants except where a
// zero result is a documented answer: see win32Optional and ignore.
func win32(p *windows.LazyProc, args ...uintptr) (uintptr, error) {
	r, err := rawWin32(p, args...)
	if err == syscall.Errno(0) {
		err = nil
	}
	if r == 0 && err == nil {
		err = errors.New("the call reported no result")
	}
	return r, err
}

// win32Optional is win32 for the calls where a zero result is an answer rather
// than a failure: a clipboard that does not carry the requested format, and a
// format name Windows has never seen.
func win32Optional(p *windows.LazyProc, args ...uintptr) (uintptr, bool) {
	r, _ := rawWin32(p, args...)
	return r, r != 0
}

// ignore calls a procedure whose result carries nothing worth branching on,
// including GlobalUnlock and GlobalFree, which report success with a zero or
// NULL return.
func ignore(p *windows.LazyProc, args ...uintptr) { _, _ = rawWin32(p, args...) }

// rawWin32 is the unfiltered result of a call. Find runs first because
// LazyProc.Call panics on a procedure the DLL does not export, and a Windows
// build missing one of these is a reportable error, not a reason to take the
// process down. windows.Proc.Call hands back the last error as an error
// interface holding syscall.Errno, so a successful call arrives with a non-nil
// error wrapping a zero Errno; only the callers above know what a zero result
// means for their API.
func rawWin32(p *windows.LazyProc, args ...uintptr) (uintptr, error) {
	if err := p.Find(); err != nil {
		return 0, err
	}
	r, _, err := p.Call(args...)
	return r, err
}

// utf16Bytes returns the NUL-terminated UTF-16 encoding of words as the byte
// block CF_UNICODETEXT expects. words must not be empty.
func utf16Bytes(words []uint16) []byte {
	b := make([]byte, 2*len(words))
	for i, w := range words {
		binary.LittleEndian.PutUint16(b[2*i:], w)
	}
	return b
}

// utf16FromBytes decodes a NUL-terminated UTF-16 clipboard buffer, stopping at
// the terminator.
func utf16FromBytes(b []byte) string {
	words := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		w := binary.LittleEndian.Uint16(b[i:])
		if w == 0 {
			break
		}
		words = append(words, w)
	}
	return string(utf16.Decode(words))
}

// dwordBytes encodes v the way the clipboard-history formats are read: a
// little-endian DWORD.
func dwordBytes(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}
