package main

import (
	"encoding/json"
	"os"
	"syscall"
	"unsafe"

	"github.com/wailsapp/wails/v2/pkg/options"
	"golang.org/x/sys/windows"
)

// idSharedWithWailsSingleInstanceLock must match the UniqueId given to
// options.SingleInstanceLock in main.go.
const idSharedWithWailsSingleInstanceLock = "com.oxcafedead.passone"

// The Wails Windows frontend creates a hidden message-only window named
// wails-app-<UniqueId>-siw with class -sic and reuses WM_COPYDATA with
// dwData = 1542 to deliver SecondInstanceData to the primary instance.
const (
	wailsEventClass              = "wails-app-" + idSharedWithWailsSingleInstanceLock + "-sic"
	wailsEventWnd                = "wails-app-" + idSharedWithWailsSingleInstanceLock + "-siw"
	singleInstanceWmCopyDataData = 1542
)

var (
	user32           = syscall.NewLazyDLL("user32.dll")
	procFindWindowW  = user32.NewProc("FindWindowW")
	procSendMessageW = user32.NewProc("SendMessageW")
)

type copyDataStruct struct {
	dwData uintptr
	cbData uint32
	lpData uintptr
}

// The mutex name is a package variable so tests can isolate from a real
// running instance by using their own name.
var singleInstanceMutexName = "PassOne-single-instance"

// acquireSingleInstance serializes app instances. The creating instance takes
// ownership of the named mutex and holds it until the process ends; the second
// concurrent instance sees WAIT_TIMEOUT, returns false, and must notify the
// primary instance and exit. The check runs before systray/Wails start so no
// second tray icon is drawn.
//
// A mutex left by a crashed or force-killed previous run is abandoned: nobody
// owns it, so a zero-timeout wait returns WAIT_ABANDONED and gives us
// ownership, letting a stale mutex never block a clean relaunch.
//
// Ownership is held by the main goroutine, which lives for the whole process,
// and the handle is intentionally never closed; both keep the mutex alive and
// owned once acquired.
func acquireSingleInstance() bool {
	name, _ := windows.UTF16PtrFromString(singleInstanceMutexName)
	mutex, err := windows.CreateMutex(nil, false, name)
	if err != nil && err != windows.ERROR_ALREADY_EXISTS {
		// Unexpected failure: do not block startup.
		return true
	}
	if mutex == 0 {
		return true
	}
	const waitTimeoutCode = 0x00000102 // WAIT_TIMEOUT: owned by a live instance
	status, _ := windows.WaitForSingleObject(mutex, 0)
	if status == waitTimeoutCode {
		// A live instance owns the mutex.
		_ = windows.CloseHandle(mutex)
		return false
	}
	// WAIT_OBJECT_0 (fresh or free) or WAIT_ABANDONED (previous owner died):
	// we now own the mutex; keep the open handle, ownership lasts the process.
	return true
}

// activateExistingInstance asks the primary instance to show its window. The
// message is exactly the one Wails itself would send, so the listener ignores
// its source. Failed lookups are harmless: the primary instance still runs.
func activateExistingInstance() {
	className, _ := syscall.UTF16PtrFromString(wailsEventClass)
	windowName, _ := syscall.UTF16PtrFromString(wailsEventWnd)
	hwnd, _, _ := procFindWindowW.Call(
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(windowName)),
	)
	if hwnd == 0 {
		return
	}

	data := options.SecondInstanceData{Args: os.Args[1:]}
	if wd, err := os.Getwd(); err == nil {
		data.WorkingDirectory = wd
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return
	}

	utf16, _ := syscall.UTF16FromString(string(raw))
	cds := copyDataStruct{
		dwData: singleInstanceWmCopyDataData,
		cbData: uint32(len(utf16)*2 + 1),
		lpData: uintptr(unsafe.Pointer(&utf16[0])),
	}
	_, _, _ = procSendMessageW.Call(hwnd, 0x004A, 0, uintptr(unsafe.Pointer(&cds)))
}
