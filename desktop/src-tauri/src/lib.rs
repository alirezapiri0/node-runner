//! Node Runner desktop application.
//!
//! # Startup order, which matters
//!
//! 1. Process hardening, before any vault work. This widens the working-set
//!    quota (so page locking is not refused under pressure) and suppresses WER
//!    crash dialogs, because a minidump taken while the payload is decrypted
//!    contains key material in the clear.
//! 2. State construction, which reads only non-secret configuration.
//! 3. Tray, poller and auto-lock.
//!
//! # Idle to tray
//!
//! Closing the window **destroys** it rather than hiding it. That distinction is
//! the whole footprint story: a hidden window keeps its WebView2 host processes
//! resident, while destroying it releases them, and the app drops to
//! backend-only memory with a tray icon still running. The dashboard is rebuilt
//! on demand from the tray.
//!
//! Because there is then no window for most of the app's life, the run loop must
//! refuse to exit when the last window closes -- otherwise closing the dashboard
//! would kill the poller. It is allowed to exit only when the tray's Quit item
//! asks for it.

pub mod commands;
pub mod drive;
pub mod gh;
pub mod state;
pub mod util;

use std::sync::atomic::Ordering;
use std::time::Duration;

use tauri::menu::{MenuBuilder, MenuItemBuilder};
use tauri::tray::TrayIconBuilder;
use tauri::{Manager, RunEvent, WebviewUrl, WebviewWindowBuilder, WindowEvent};

use state::AppState;

pub const WINDOW_LABEL: &str = "main";
const TRAY_ID: &str = "node-runner";

pub fn run() {
    // Step 1: harden before touching anything sensitive.
    if let Err(err) = nrvault::harden_process() {
        // Not fatal: hardening is defence in depth, and refusing to start would
        // be worse than starting without it.
        eprintln!("[node-runner] process hardening incomplete: {err}");
    }

    let state = match AppState::new() {
        Ok(state) => state,
        Err(err) => {
            eprintln!("[node-runner] cannot start: {err}");
            return;
        }
    };

    state.log(format!(
        "node-runner {} starting (data directory: {})",
        env!("CARGO_PKG_VERSION"),
        nrvault::VaultStore::default_dir().display()
    ));
    state.log(if nrvault::swap_protection_available() {
        "secret pages will be pinned against swap".to_string()
    } else {
        "warning: this platform cannot pin secret pages against swap".to_string()
    });
    if state.kill_switch.load(Ordering::Relaxed) {
        state.log("warning: the stop switch is engaged from a previous session");
    }

    let app = match tauri::Builder::default()
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            commands::vault_status,
            commands::vault_calibrate,
            commands::vault_init,
            commands::vault_unlock,
            commands::vault_unlock_os,
            commands::vault_lock,
            commands::vault_list_secrets,
            commands::vault_set_secret,
            commands::vault_delete_secret,
            commands::vault_rotate,
            commands::vault_clear_alerts,
            commands::vault_destroy,
            commands::config_get,
            commands::config_set,
            commands::node_status,
            commands::node_set_kill_switch,
            commands::node_dispatch,
            commands::secrets_inject,
            commands::drive_ledger,
            commands::drive_heartbeat,
            commands::logs_tail,
            commands::logs_clear,
            commands::app_info,
        ])
        .setup(|app| {
            install_tray(app.handle())?;
            gh::poller::spawn(app.handle().clone());
            spawn_auto_lock(app.handle().clone());
            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                // Keep the app alive; the tray is now the only UI.
                api.prevent_close();
                // Destroy rather than hide: this is what releases the WebView2
                // host processes and is the entire point of the footprint design.
                if let Err(err) = window.destroy() {
                    eprintln!("[node-runner] could not release the dashboard window: {err}");
                }
            }
        })
        .build(tauri::generate_context!())
    {
        Ok(app) => app,
        Err(err) => {
            eprintln!("[node-runner] failed to build the application: {err}");
            return;
        }
    };

    app.run(|handle, event| {
        if let RunEvent::ExitRequested { api, code, .. } = event {
            // `code` is `None` when the exit was triggered by the last window
            // closing, and `Some(_)` when the tray asked to quit. Only the latter
            // should be honoured.
            if code.is_none() {
                let quitting = handle.state::<AppState>().quitting.load(Ordering::Relaxed);
                if !quitting {
                    api.prevent_exit();
                } else {
                    if let Ok(mut session) = handle.state::<AppState>().session.lock() {
                        session.lock();
                    }
                }
            }
        }
    });
}

/// Build the tray icon and its menu.
fn install_tray(app: &tauri::AppHandle) -> tauri::Result<()> {
    let show = MenuItemBuilder::with_id("show", "Show dashboard").build(app)?;
    let lock = MenuItemBuilder::with_id("lock", "Lock vault").build(app)?;
    let quit = MenuItemBuilder::with_id("quit", "Quit").build(app)?;
    let menu = MenuBuilder::new(app)
        .items(&[&show, &lock, &quit])
        .build()?;

    let mut builder = TrayIconBuilder::with_id(TRAY_ID)
        .tooltip("Node Runner")
        .menu(&menu)
        .on_menu_event(|app, event| match event.id().as_ref() {
            "show" => show_dashboard(app),
            "lock" => {
                let state = app.state::<AppState>();
                if let Ok(mut session) = state.session.lock() {
                    session.lock();
                }
                // Drop the cached Drive token along with the unlock it came from.
                state.forget_drive();
                state.log("vault locked from the tray");
            }
            "quit" => {
                let state = app.state::<AppState>();
                state.quitting.store(true, Ordering::Relaxed);
                // Lock before exiting so the payload is zeroized deterministically
                // rather than by process teardown.
                if let Ok(mut session) = state.session.lock() {
                    session.lock();
                }
                app.exit(0);
            }
            _ => {}
        });

    // An icon is nice but not essential; a missing icon file must not stop the
    // app, since the tray is the only way to reach the dashboard once it closes.
    if let Some(icon) = app.default_window_icon().cloned() {
        builder = builder.icon(icon);
    }

    builder.build(app)?;
    Ok(())
}

/// Show the dashboard, recreating the window if it was destroyed.
fn show_dashboard(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window(WINDOW_LABEL) {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
        return;
    }

    // The window is rebuilt from scratch, so everything `tauri.conf.json` set for
    // the original must be restated here. The label is what the capability file
    // grants permissions to, so it must stay "main".
    match WebviewWindowBuilder::new(app, WINDOW_LABEL, WebviewUrl::App("index.html".into()))
        .title("Node Runner")
        .inner_size(1080.0, 760.0)
        .min_inner_size(880.0, 560.0)
        .resizable(true)
        .center()
        .build()
    {
        Ok(window) => {
            let _ = window.set_focus();
        }
        Err(err) => eprintln!("[node-runner] could not build the dashboard window: {err}"),
    }
}

/// Lock the vault after a period of inactivity.
///
/// The threshold is configuration, never "off": a vault that stays unlocked
/// indefinitely because nobody moved the mouse is the most likely way an
/// unattended desktop leaks its credentials.
fn spawn_auto_lock(app: tauri::AppHandle) {
    tauri::async_runtime::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;

            let state = app.state::<AppState>();
            let limit_secs = state.config_snapshot().auto_lock_minutes.saturating_mul(60);

            let idle_secs = state
                .session
                .lock()
                .ok()
                .and_then(|session| session.idle_for())
                .map(|idle| idle.as_secs());

            if let Some(idle_secs) = idle_secs {
                if idle_secs >= limit_secs {
                    if let Ok(mut session) = state.session.lock() {
                        session.lock();
                    }
                    state.forget_drive();
                    state.log(format!(
                        "vault auto-locked after {idle_secs}s of inactivity"
                    ));
                }
            }
        }
    });
}
