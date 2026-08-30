package main

import (
	"context"

	"github.com/getlantern/systray"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

var (
	appCtx        context.Context
	appBinding    *App
	quitRequested = make(chan struct{})
)

func setAppContext(ctx context.Context) { appCtx = ctx }

func globalCtx() context.Context { return appCtx }

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
				if appBinding != nil {
					appBinding.Lock()
				}
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

func trayExit() {
	// Cleanup hook; systray cleans up after Run returns.
}
