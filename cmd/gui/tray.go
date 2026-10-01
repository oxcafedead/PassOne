package main

import (
	"context"
	"sync"

	"github.com/getlantern/systray"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

var (
	// appMu guards the two values below. Wails writes them from its own
	// callbacks and the tray reads them from the menu goroutine, so the nil
	// checks that follow are only a real guard if the pair is copied out
	// atomically — a context.Context is two words, and a torn read of it is a
	// type pointer paired with someone else's data pointer.
	appMu      sync.RWMutex
	appCtx     context.Context
	appBinding *App

	quitRequested = make(chan struct{})
)

func setAppContext(ctx context.Context) {
	appMu.Lock()
	appCtx = ctx
	appMu.Unlock()
}

func globalCtx() context.Context {
	appMu.RLock()
	defer appMu.RUnlock()
	return appCtx
}

func setAppBinding(a *App) {
	appMu.Lock()
	appBinding = a
	appMu.Unlock()
}

// trayApp returns the bound App, or nil before the bindings exist.
func trayApp() *App {
	appMu.RLock()
	defer appMu.RUnlock()
	return appBinding
}

// requestQuit records that the user asked to quit exactly once. The main
// goroutine watches it so it can force a clean process exit even if Wails or
// the webview fail to tear down synchronously.
func requestQuit() {
	select {
	case <-quitRequested:
	default:
		close(quitRequested)
	}
}

// trayReady builds the system tray icon and menu.
func trayReady() {
	systray.SetIcon(trayIconData)
	systray.SetTooltip("PassOne - password store")

	openItem := systray.AddMenuItem("Open PassOne", "Show the PassOne window")
	lockItem := systray.AddMenuItem("Lock", "Drop keys from memory")
	updateItem := systray.AddMenuItem("Check for updates", "Ask GitHub for a newer PassOne release")
	systray.AddSeparator()
	quitItem := systray.AddMenuItem("Quit PassOne", "Exit PassOne")

	go func() {
		for {
			select {
			case <-openItem.ClickedCh:
				if ctx := globalCtx(); ctx != nil {
					runtime.WindowShow(ctx)
				}
			case <-lockItem.ClickedCh:
				if a := trayApp(); a != nil {
					a.Lock()
				}
			case <-updateItem.ClickedCh:
				requestUpdateCheck()
			case <-quitItem.ClickedCh:
				requestQuit()
				if ctx := globalCtx(); ctx != nil {
					runtime.Quit(ctx)
				}
				return
			}
		}
	}()
}

// requestUpdateCheck asks the frontend to run an update check, bringing the
// window up first so the answer is visible when PassOne was sitting in the tray.
//
// The tray asks rather than calling the checker itself so that one place
// decides what a check says and one toast says it: the frontend already runs the
// same check silently at startup, and it is the only thing that knows how to put
// a message on screen.
//
// The ask travels as an event, so it lands only if the page is already
// listening. That leaves one window — a tray click in the moments before the
// page has mounted — where the request is dropped, and the startup check that
// follows the page load is what answers instead. It answers when there is
// something to report, so the one case that goes quiet is a manual check of a
// current build in the first second after launch.
func requestUpdateCheck() {
	ctx := globalCtx()
	if ctx == nil {
		return
	}
	runtime.WindowShow(ctx)
	runtime.EventsEmit(ctx, "passone:check-updates", nil)
}

func trayExit() {
	// Cleanup hook; systray cleans up after Run returns.
}
