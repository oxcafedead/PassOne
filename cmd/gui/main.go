package main

import (
	"context"
	"embed"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/getlantern/golog"
	"github.com/getlantern/systray"
	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/runtime"
	"golang.org/x/sys/windows/registry"

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

	// systray logs through upper-level getlantern/golog, whose error output
	// defaults to os.Stderr (invisible in a GUI app). Mirror it into our data
	// directory so tray init failures are diagnosable.
	if d, derr := os.Create(filepath.Join(gui.DataDir(), "passone.log")); derr == nil {
		golog.SetOutputs(d, d)
	}

	// systray runs on its own goroutine; Wails must run on the main goroutine
	// on Windows or the window is created hidden.
	systrayDone := make(chan struct{})
	go func() {
		defer close(systrayDone)
		systray.Run(trayReady, trayExit)
	}()

	// Watchdog: once Quit is requested, Wails must tear the webview down and
	// let the main goroutine return. If that hangs, force a clean exit so the
	// process never lingers with a locked binary and a held single-instance
	// mutex (which would otherwise leave the tray dead on the next launch).
	go func() {
		<-quitRequested
		time.Sleep(5 * time.Second)
		os.Exit(0)
	}()

	background := &options.RGBA{R: 18, G: 20, B: 26, A: 1}
	if windowsUsesLightTheme() {
		background = &options.RGBA{R: 242, G: 243, B: 246, A: 1}
	}

	if err := wails.Run(&options.App{
		Title:             "PassOne",
		Width:             900,
		Height:            620,
		MinWidth:          720,
		MinHeight:         480,
		HideWindowOnClose: true,
		BackgroundColour:  background,
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
			gui.SetContext(ctx)
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

// windowsUsesLightTheme reports the Windows light/dark app theme from the
// registry; it controls the window chrome behind the webview at startup. The
// page itself tracks the system theme live via prefers-color-scheme.
func windowsUsesLightTheme() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Themes\Personalize`, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer func() { _ = k.Close() }()
	v, _, err := k.GetIntegerValue(`AppsUseLightTheme`)
	return err == nil && v == 1
}
