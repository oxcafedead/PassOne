package main

import (
	"context"
	"embed"
	"log"
	"os"

	"github.com/getlantern/systray"
	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/oxcafedead/passone/internal/ui"
)

//go:embed all:frontend/dist
var assets embed.FS

//go:embed build/windows/icon.ico
var trayIconData []byte

func main() {
	// Enforce a single instance before anything (tray, window) is created so
	// a second launch never draws an extra tray icon. The primary instance is
	// asked to show its window, then this process exits.
	if !acquireSingleInstance() {
		activateExistingInstance()
		os.Exit(0)
	}

	gui, err := ui.New()
	if err != nil {
		log.Fatalf("PassOne: %v", err)
	}
	bindApp := NewApp(gui)
	appBinding = bindApp

	// systray runs on its own goroutine; Wails must run on the main goroutine
	// on Windows or the window is created hidden.
	systrayDone := make(chan struct{})
	go func() {
		defer close(systrayDone)
		systray.Run(trayReady, trayExit)
	}()

	if err := wails.Run(&options.App{
		Title:            "PassOne",
		Width:            900,
		Height:           620,
		MinWidth:         720,
		MinHeight:        480,
		HideWindowOnClose: true,
		BackgroundColour:  &options.RGBA{R: 18, G: 20, B: 26, A: 1},
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		// Backstop for second-launch races: if the primary instance gets the
		// WM_COPYDATA before our own guard or through wails itself, re-show it.
		SingleInstanceLock: &options.SingleInstanceLock{
			UniqueId: idSharedWithWailsSingleInstanceLock,
			OnSecondInstanceLaunch: func(_ options.SecondInstanceData) {
				if ctx := globalCtx(); ctx != nil {
					runtime.WindowShow(ctx)
				}
			},
		},
		OnStartup: func(ctx context.Context) {
			setAppContext(ctx)
		},
		OnBeforeClose: func(ctx context.Context) (prevent bool) {
			// The tray owns the process lifetime. Closing the window hides
			// it (HideWindowOnClose); quitting happens from the tray.
			setAppContext(ctx)
			return false
		},
		Bind: []interface{}{
			bindApp,
		},
	}); err != nil {
		log.Printf("PassOne UI: %v", err)
	}

	// Wails app ended: tear down the tray (idempotent if already quitting).
	systray.Quit()
	<-systrayDone
}