//! Owns the process-wide injection engine session for the lifetime of the
//! elevated UI or broker process.

use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use libloading::Library;
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::System::Diagnostics::Debug::OutputDebugStringW;
use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows_sys::Win32::System::Threading::GetCurrentProcessId;

const PROCESS_SCAN_INTERVAL: Duration = Duration::from_secs(1);

type StartSession = unsafe extern "C" fn() -> *mut c_void;
type HandleNewProcesses = unsafe extern "C" fn(*mut c_void) -> i32;
type RecordSessionUsers = unsafe extern "C" fn(*mut c_void) -> i32;
type RecordSessionLogon = unsafe extern "C" fn(*mut c_void, u32) -> i32;
type RemoveSessionUser = unsafe extern "C" fn(*mut c_void, u32) -> i32;
type HandleNewLogonSession = unsafe extern "C" fn(u32) -> i32;
type EndSession = unsafe extern "C" fn(*mut c_void) -> i32;

/// Keeps the worker alive until its owner exits, then ends the engine session on
/// the same thread that created it.
pub struct EngineRuntime {
    stop: Sender<()>,
    worker: Option<JoinHandle<()>>,
}

impl EngineRuntime {
    pub fn start(engine_path: PathBuf, session_id: Option<u32>) -> Result<Self, String> {
        let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
        let (stop, stop_receiver) = mpsc::channel();
        let session_id = match session_id {
            Some(session_id) => session_id,
            None => current_session_id()?,
        };
        let worker = thread::Builder::new()
            .name("UniWind injection engine".to_owned())
            .spawn(move || run_engine(engine_path, session_id, stop_receiver, ready_sender))
            .map_err(|error| format!("could not create the engine worker: {error}"))?;

        match ready_receiver.recv() {
            Ok(Ok(())) => Ok(EngineRuntime {
                stop,
                worker: Some(worker),
            }),
            Ok(Err(error)) => {
                let _ = worker.join();
                Err(error)
            }
            Err(error) => {
                let _ = worker.join();
                Err(format!("the engine worker stopped during startup: {error}"))
            }
        }
    }
}

impl Drop for EngineRuntime {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if let Some(worker) = self.worker.take() {
            if worker.join().is_err() {
                report_engine_error("the engine worker panicked while stopping");
            }
        }
    }
}

fn run_engine(
    engine_path: PathBuf,
    session_id: u32,
    stop: Receiver<()>,
    ready: mpsc::SyncSender<Result<(), String>>,
) {
    let session = match EngineSession::start(&engine_path) {
        Ok(session) => session,
        Err(error) => {
            let _ = ready.send(Err(error));
            return;
        }
    };

    if let Err(error) = session
        .record_current_session_users()
        .and_then(|()| session.handle_logon(session_id))
        .and_then(|()| session.handle_new_processes())
    {
        let _ = ready.send(Err(error));
        return;
    }

    if ready.send(Ok(())).is_err() {
        return;
    }

    loop {
        match stop.recv_timeout(PROCESS_SCAN_INTERVAL) {
            Ok(()) | Err(RecvTimeoutError::Disconnected) => return,
            Err(RecvTimeoutError::Timeout) => {
                if let Err(error) = session.handle_new_processes() {
                    report_engine_error(&error);
                    return;
                }
            }
        }
    }
}

pub(crate) struct EngineSession {
    _library: Library,
    session: *mut c_void,
    handle_new_processes: HandleNewProcesses,
    record_session_users: RecordSessionUsers,
    record_session_logon: RecordSessionLogon,
    remove_session_user: RemoveSessionUser,
    handle_new_logon_session: HandleNewLogonSession,
    end_session: EndSession,
}

impl EngineSession {
    pub(crate) fn start(engine_path: &Path) -> Result<Self, String> {
        let dll_path = engine_path.join("64").join("windhawk.dll");
        // SAFETY: this path comes from the core's resolved installation config,
        // and the library is kept loaded for the full lifetime of its session.
        let library = unsafe { Library::new(&dll_path) }
            .map_err(|error| format!("could not load {}: {error}", dll_path.display()))?;

        // SAFETY: the C++ engine exports these names with the declared lifecycle
        // signatures on the x64 Windows build shipped with this application.
        let start = unsafe {
            *library
                .get::<StartSession>(b"GlobalHookSessionStart\0")
                .map_err(|error| format!("the engine start export is unavailable: {error}"))?
        };
        // SAFETY: this export is declared in the engine's _exports.def with this
        // x64 Windows signature.
        let handle_new_processes = unsafe {
            *library
                .get::<HandleNewProcesses>(b"GlobalHookSessionHandleNewProcesses\0")
                .map_err(|error| {
                    format!("the engine process-scan export is unavailable: {error}")
                })?
        };
        // SAFETY: this export is declared in the engine's _exports.def with this
        // x64 Windows signature.
        let record_session_users = unsafe {
            *library
                .get::<RecordSessionUsers>(b"GlobalHookSessionRecordSessionUsers\0")
                .map_err(|error| {
                    format!("the engine session-user export is unavailable: {error}")
                })?
        };
        // SAFETY: this export is declared in the engine's _exports.def with this
        // x64 Windows signature.
        let handle_new_logon_session = unsafe {
            *library
                .get::<HandleNewLogonSession>(b"HandleNewLogonSession\0")
                .map_err(|error| {
                    format!("the engine logon-session export is unavailable: {error}")
                })?
        };
        // SAFETY: this export is declared in the engine's _exports.def with this
        // x64 Windows signature.
        let record_session_logon = unsafe {
            *library
                .get::<RecordSessionLogon>(b"GlobalHookSessionRecordSessionLogon\0")
                .map_err(|error| {
                    format!("the engine session-logon export is unavailable: {error}")
                })?
        };
        // SAFETY: this export is declared in the engine's _exports.def with this
        // x64 Windows signature.
        let remove_session_user = unsafe {
            *library
                .get::<RemoveSessionUser>(b"GlobalHookSessionRemoveSessionUser\0")
                .map_err(|error| {
                    format!("the engine session-user removal export is unavailable: {error}")
                })?
        };
        // SAFETY: this export is declared in the engine's _exports.def with this
        // x64 Windows signature.
        let end_session = unsafe {
            *library
                .get::<EndSession>(b"GlobalHookSessionEnd\0")
                .map_err(|error| format!("the engine end export is unavailable: {error}"))?
        };

        // SAFETY: the engine start routine takes no arguments and returns the
        // opaque session handle consumed by the other two exports.
        let session = unsafe { start() };
        if session.is_null() {
            return Err(format!(
                "the engine returned no session while loading {}",
                dll_path.display()
            ));
        }

        Ok(EngineSession {
            _library: library,
            session,
            handle_new_processes,
            record_session_users,
            record_session_logon,
            remove_session_user,
            handle_new_logon_session,
            end_session,
        })
    }

    pub(crate) fn record_current_session_users(&self) -> Result<(), String> {
        // SAFETY: the session handle was created by this engine instance and is
        // used only on its owning worker thread.
        if unsafe { (self.record_session_users)(self.session) } == 0 {
            return Err("the engine failed to record active Windows sessions".to_owned());
        }
        Ok(())
    }

    pub(crate) fn handle_logon(&self, session_id: u32) -> Result<(), String> {
        // SAFETY: the engine exports this function to start tool mods for an
        // already logged-on Windows session.
        if unsafe { (self.handle_new_logon_session)(session_id) } == 0 {
            return Err(format!(
                "the engine failed to initialize Windows session {session_id}"
            ));
        }
        Ok(())
    }

    pub(crate) fn record_session_logon(&self, session_id: u32) -> Result<(), String> {
        // SAFETY: the session handle was created by this engine instance and is
        // used only on its owning worker thread.
        if unsafe { (self.record_session_logon)(self.session, session_id) } == 0 {
            return Err(format!(
                "the engine failed to record the logon for Windows session {session_id}"
            ));
        }
        Ok(())
    }

    pub(crate) fn remove_session_user(&self, session_id: u32) -> Result<(), String> {
        // SAFETY: the session handle was created by this engine instance and is
        // used only on its owning worker thread.
        if unsafe { (self.remove_session_user)(self.session, session_id) } == 0 {
            return Err(format!(
                "the engine failed to remove the user for Windows session {session_id}"
            ));
        }
        Ok(())
    }

    pub(crate) fn handle_new_processes(&self) -> Result<(), String> {
        // SAFETY: the session handle was created by this engine instance and is
        // used only on its owning worker thread.
        if unsafe { (self.handle_new_processes)(self.session) } == 0 {
            return Err("the engine failed while scanning for new processes".to_owned());
        }
        Ok(())
    }
}

fn current_session_id() -> Result<u32, String> {
    let mut session_id = 0;
    // SAFETY: GetCurrentProcessId has no preconditions and session_id is a
    // valid output slot for ProcessIdToSessionId.
    let process_id = unsafe { GetCurrentProcessId() };
    // SAFETY: process_id names this process and session_id is writable.
    if unsafe { ProcessIdToSessionId(process_id, &mut session_id) } == 0 {
        return Err(format!(
            "could not resolve this process's Windows session (error {})",
            // SAFETY: GetLastError has no preconditions.
            unsafe { GetLastError() }
        ));
    }
    Ok(session_id)
}

impl Drop for EngineSession {
    fn drop(&mut self) {
        // SAFETY: this handle remains valid until GlobalHookSessionEnd consumes it.
        if unsafe { (self.end_session)(self.session) } == 0 {
            report_engine_error("the engine failed to end its session cleanly");
        }
    }
}

pub(crate) fn report_engine_error(message: &str) {
    let message = format!("[WH] UniWind injection engine: {message}\n\0");
    let message: Vec<u16> = message.encode_utf16().collect();
    // SAFETY: message is NUL-terminated UTF-16 and remains alive for the call.
    unsafe { OutputDebugStringW(message.as_ptr()) };
}

#[cfg(test)]
mod tests {
    use super::EngineRuntime;

    #[test]
    fn missing_engine_dll_is_reported_without_starting_a_session() {
        let engine_path = std::env::temp_dir()
            .join(format!("UniWind-engine-test-{}", std::process::id()))
            .join("missing");

        let error = match EngineRuntime::start(engine_path, Some(0)) {
            Ok(_) => panic!("a missing engine unexpectedly started"),
            Err(error) => error,
        };

        assert!(error.contains("windhawk.dll"));
    }
}
