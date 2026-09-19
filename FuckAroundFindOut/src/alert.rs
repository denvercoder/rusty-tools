//! OS-level breach alert.
//!
//! On Windows, pops a native modal message box (`MessageBoxW`) so the warning
//! shows on the desktop even if no terminal is focused. On every other OS this
//! is a no-op — there, the alarm is the console output and (when launched that
//! way) the dashboard's in-page modal instead.
//!
//! The box is modal and blocks the thread that calls it until dismissed, so
//! callers should invoke `popup` on a dedicated thread and guard against
//! stacking multiple boxes (see the `popup_open` flag in `main`).

/// Show a modal breach popup. Blocks until the user dismisses it.
#[cfg(windows)]
pub fn popup(title: &str, body: &str) {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    // A minimal, hand-rolled binding to the one Win32 call we need, rather than
    // pulling a full bindings crate (`windows-sys`) — which also needs MinGW's
    // `dlltool` to build on the GNU toolchain. `user32` is a standard system
    // import library present in both the MSVC and GNU toolchains, so this links
    // everywhere with no extra tooling.
    #[link(name = "user32")]
    unsafe extern "system" {
        fn MessageBoxW(
            hwnd: *mut core::ffi::c_void,
            text: *const u16,
            caption: *const u16,
            utype: u32,
        ) -> i32;
    }

    const MB_OK: u32 = 0x0000_0000;
    const MB_ICONERROR: u32 = 0x0000_0010;
    const MB_SETFOREGROUND: u32 = 0x0001_0000;
    const MB_TOPMOST: u32 = 0x0004_0000;

    // Win32 wants null-terminated UTF-16.
    fn wide(s: &str) -> Vec<u16> {
        OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
    }

    let caption = wide(title);
    let text = wide(body);

    // SAFETY: both pointers are valid, null-terminated UTF-16 buffers that
    // outlive the (synchronous, modal) call; a null HWND means "no owner".
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            text.as_ptr(),
            caption.as_ptr(),
            MB_OK | MB_ICONERROR | MB_SETFOREGROUND | MB_TOPMOST,
        );
    }
}

/// No native popup on non-Windows platforms — the console/dashboard alarm
/// covers it there.
#[cfg(not(windows))]
pub fn popup(_title: &str, _body: &str) {}
