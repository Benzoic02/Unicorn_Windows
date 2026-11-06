//! Persistent Windows service host for the injection engine.

use std::ffi::c_void;
use std::fs;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::slice;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_INVALID_PARAMETER, ERROR_SERVICE_ALREADY_RUNNING,
    ERROR_SERVICE_DOES_NOT_EXIST, ERROR_SERVICE_MARKED_FOR_DELETE, ERROR_SERVICE_NOT_ACTIVE,
    HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Storage::FileSystem::DELETE;
use windows_sys::Win32::System::RemoteDesktop::{
    WTSActive, WTSConnected, WTSDisconnected, WTSEnumerateSessionsW, WTSFreeMemory,
    WTSSESSION_NOTIFICATION, WTS_SESSION_INFOW,
};
use windows_sys::Win32::System::Services::{
    ChangeServiceConfig2W, CloseServiceHandle, ControlService, CreateServiceW, DeleteService,
    OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, RegisterServiceCtrlHandlerExW,
    SetServiceStatus, StartServiceCtrlDispatcherW, StartServiceW, SC_ACTION, SC_ACTION_RESTART,
    SC_MANAGER_CONNECT, SC_MANAGER_CREATE_SERVICE, SC_STATUS_PROCESS_INFO,
    SERVICE_ACCEPT_SESSIONCHANGE, SERVICE_ACCEPT_STOP, SERVICE_AUTO_START, SERVICE_CHANGE_CONFIG,
    SERVICE_CONFIG_FAILURE_ACTIONS, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
    SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_SESSIONCHANGE, SERVICE_CONTROL_STOP,
    SERVICE_ERROR_NORMAL, SERVICE_FAILURE_ACTIONSW, SERVICE_FAILURE_ACTIONS_FLAG,
    SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START, SERVICE_START_PENDING, SERVICE_STATUS,
    SERVICE_STATUS_HANDLE, SERVICE_STATUS_PROCESS, SERVICE_STOP, SERVICE_STOPPED,
    SERVICE_STOP_PENDING, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, Sleep, WaitForSingleObject, PROCESS_SYNCHRONIZE,
};
use windows_sys::Win32::System::WindowsProgramming::GetPrivateProfileStringW;
use windows_sys::Win32::UI::Shell::{SHGetFolderPathW, CSIDL_PROGRAM_FILES, SHGFP_TYPE_CURRENT};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    MessageBoxW, MB_ICONERROR, MB_ICONINFORMATION, MB_OK, WTS_SESSION_LOGOFF, WTS_SESSION_LOGON,
};

use crate::broker::engine::{report_engine_error, EngineSession};

const SERVICE_NAME: &str = "UniWindEngineService";
const SERVICE_DISPLAY_NAME: &str = "UniWind Injection Engine";
const SERVICE_EXECUTABLE: &str = "windhawk-ui.exe";
const ENGINE_SERVICE_FLAG: &str = "--engine-service";
const SERVICE_FOLDER: &str = "UniWind";
const SETTINGS_FILE_KEY: &str = "SettingsPath";
const SCAN_INTERVAL: Duration = Duration::from_secs(1);
const ENGINE_RETRY_INTERVAL: Duration = Duration::from_secs(5);

enum ServiceEvent {
    Stop,
    Logon(u32),
    Logoff(u32),
}

struct ServiceContext {
    status_handle: SERVICE_STATUS_HANDLE,
    events: Sender<ServiceEvent>,
}

struct ServiceHandle(windows_sys::Win32::System::Services::SC_HANDLE);

struct ProcessHandle(HANDLE);

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this RAII wrapper owns a valid process handle.
            unsafe { CloseHandle(self.0) };
        }
    }
}

impl Drop for ServiceHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this RAII wrapper owns a valid SCM or service handle.
            unsafe { CloseServiceHandle(self.0) };
        }
    }
}

/// Dispatches management commands before the Tauri UI starts.
pub fn run_command(args: &[String]) -> Option<u8> {
    let (result, success_message) = match args.first().map(String::as_str) {
        Some("--install-engine-service") => (
            install_service(),
            "UniWind's persistent engine service was installed and started.",
        ),
        Some("--uninstall-engine-service") => (
            uninstall_service(),
            "UniWind's persistent engine service was stopped and removed.",
        ),
        Some(ENGINE_SERVICE_FLAG) => return Some(run_service()),
        _ => return None,
    };

    match result {
        Ok(()) => {
            show_message(success_message, false);
            Some(0)
        }
        Err(error) => {
            show_message(&error, true);
            Some(1)
        }
    }
}

/// Returns whether the persistent service is already hosting the engine.
pub fn is_service_running() -> Result<bool, String> {
    let manager = open_manager(SC_MANAGER_CONNECT)?;
    let service_name = wide(SERVICE_NAME);
    // SAFETY: manager is valid and service_name is NUL-terminated.
    let service = unsafe { OpenServiceW(manager.0, service_name.as_ptr(), SERVICE_QUERY_STATUS) };
    if service.is_null() {
        let error = unsafe { GetLastError() };
        if error == ERROR_SERVICE_DOES_NOT_EXIST || error == ERROR_SERVICE_MARKED_FOR_DELETE {
            return Ok(false);
        }
        return Err(format!(
            "could not query the UniWind engine service (Windows error {error})"
        ));
    }
    let service = ServiceHandle(service);
    let status = query_service_status(service.0)?;
    Ok(matches!(
        status.dwCurrentState,
        SERVICE_RUNNING | SERVICE_START_PENDING | SERVICE_STOP_PENDING
    ))
}

fn install_service() -> Result<(), String> {
    if crate::broker::needs_broker() {
        return Err(
            "Installing the persistent engine service requires an elevated PowerShell window. \
             Run PowerShell as Administrator and retry."
                .to_owned(),
        );
    }
    ensure_service_absent()?;

    let source_executable =
        std::env::current_exe().map_err(|error| format!("could not locate UniWind: {error}"))?;
    let source_root = source_executable
        .parent()
        .ok_or_else(|| "could not locate the UniWind installation folder".to_owned())?;
    let source_config = source_root.join("windhawk.ini");
    let portable = read_profile_int("Storage", "Portable", &source_config, 0)?;
    if portable == 0 {
        return Err(
            "The persistent service currently requires the portable UniWind installation."
                .to_owned(),
        );
    }

    let app_data_path = resolve_config_path(source_root, "Storage", "AppDataPath", &source_config)?;
    if !app_data_path.is_dir() {
        return Err(format!(
            "The configured UniWind data folder does not exist: {}",
            app_data_path.display()
        ));
    }
    let source_engine_path =
        resolve_config_path(source_root, "Storage", "EnginePath", &source_config)?;
    let source_engine_config = source_engine_path.join("engine.ini");
    let engine_data_path = resolve_config_path(
        &source_engine_path,
        "Storage",
        "AppDataPath",
        &source_engine_config,
    )?;
    if !source_engine_path.join("64").join("windhawk.dll").is_file() {
        return Err(format!(
            "The x64 injection engine is missing from {}",
            source_engine_path.display()
        ));
    }

    let program_files = program_files_directory()?;
    let install_root = program_files.join(SERVICE_FOLDER);
    if install_root.exists() {
        return Err(format!(
            "{} already exists. Uninstall the existing service before reinstalling.",
            install_root.display()
        ));
    }

    let service_executable = install_root.join(SERVICE_EXECUTABLE);
    let engine_destination = install_root.join("Engine");
    let prepare_files = || {
        fs::create_dir_all(&engine_destination)
            .map_err(|error| format!("could not create the protected service folder: {error}"))?;
        fs::copy(&source_executable, &service_executable).map_err(|error| {
            format!("could not copy the service executable into Program Files: {error}")
        })?;
        copy_directory(&source_engine_path, &engine_destination)?;
        write_utf16_ini(
            &engine_destination.join("engine.ini"),
            &format!(
                "[Storage]\r\nPortable=1\r\nAppDataPath={}\r\n",
                engine_data_path.display()
            ),
        )?;
        write_utf16_ini(
            &install_root.join("service.ini"),
            &format!(
                "[Service]\r\n{}={}\r\n",
                SETTINGS_FILE_KEY,
                app_data_path.join("settings.ini").display()
            ),
        )
    };
    if let Err(error) = prepare_files() {
        return Err(remove_install_files(&install_root, error));
    }

    let manager = match open_manager(SC_MANAGER_CREATE_SERVICE) {
        Ok(manager) => manager,
        Err(error) => return Err(remove_install_files(&install_root, error)),
    };
    let service_name = wide(SERVICE_NAME);
    let display_name = wide(SERVICE_DISPLAY_NAME);
    let binary_path = wide(&format!(
        "\"{}\" {ENGINE_SERVICE_FLAG}",
        service_executable.display()
    ));
    // SAFETY: all strings are NUL-terminated and remain alive for the call;
    // null account/password select the LocalSystem service account.
    let service = unsafe {
        CreateServiceW(
            manager.0,
            service_name.as_ptr(),
            display_name.as_ptr(),
            SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP | SERVICE_CHANGE_CONFIG | DELETE,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            binary_path.as_ptr(),
            null(),
            null_mut(),
            null(),
            null(),
            null(),
        )
    };
    if service.is_null() {
        let error = last_error("could not register the UniWind engine service");
        return Err(remove_install_files(&install_root, error));
    }
    let service = ServiceHandle(service);

    if let Err(error) = configure_recovery(service.0) {
        let cleanup = delete_new_service(service.0);
        drop(service);
        return Err(finish_failed_install(&install_root, error, cleanup));
    }

    // SAFETY: service is a valid handle and the service takes no startup args.
    if unsafe { StartServiceW(service.0, 0, null()) } == 0 {
        let error = unsafe { GetLastError() };
        if error != ERROR_SERVICE_ALREADY_RUNNING {
            let error = format!(
                "the service was registered but could not be started (Windows error {error})"
            );
            let cleanup = delete_new_service(service.0);
            drop(service);
            return Err(finish_failed_install(&install_root, error, cleanup));
        }
    }
    if let Err(error) = wait_until_running(service.0, Duration::from_secs(30)) {
        let rollback = rollback_service(service.0);
        drop(service);
        return Err(finish_failed_install(&install_root, error, rollback));
    }
    Ok(())
}

fn uninstall_service() -> Result<(), String> {
    if crate::broker::needs_broker() {
        return Err(
            "Removing the persistent engine service requires an elevated PowerShell window. \
             Run PowerShell as Administrator and retry."
                .to_owned(),
        );
    }

    let manager = open_manager(SC_MANAGER_CONNECT)?;
    let service_name = wide(SERVICE_NAME);
    // SAFETY: manager is valid and service_name is NUL-terminated.
    let service = unsafe {
        OpenServiceW(
            manager.0,
            service_name.as_ptr(),
            SERVICE_QUERY_STATUS | SERVICE_STOP | DELETE,
        )
    };
    if service.is_null() {
        let error = unsafe { GetLastError() };
        if error == ERROR_SERVICE_DOES_NOT_EXIST {
            return Ok(());
        }
        return Err(format!(
            "could not open the UniWind engine service for removal (Windows error {error})"
        ));
    }
    let service = ServiceHandle(service);
    let status = query_service_status(service.0)?;
    let process = if status.dwCurrentState == SERVICE_STOPPED {
        None
    } else {
        open_service_process(status.dwProcessId)?
    };
    if status.dwCurrentState != SERVICE_STOPPED {
        let mut service_status = SERVICE_STATUS::default();
        // SAFETY: service is valid and service_status is a writable output slot.
        if unsafe { ControlService(service.0, SERVICE_CONTROL_STOP, &mut service_status) } == 0 {
            let error = unsafe { GetLastError() };
            if error != windows_sys::Win32::Foundation::ERROR_SERVICE_NOT_ACTIVE {
                return Err(format!(
                    "could not stop the UniWind engine service (Windows error {error})"
                ));
            }
        }
        wait_until_stopped(service.0, Duration::from_secs(60))?;
    }
    if let Some(process) = process {
        wait_for_process_exit(process.0, Duration::from_secs(60))?;
    }
    // SAFETY: service is valid and has been stopped.
    if unsafe { DeleteService(service.0) } == 0 {
        return Err(last_error("could not remove the UniWind engine service"));
    }
    drop(service);

    let install_root = program_files_directory()?.join(SERVICE_FOLDER);
    if install_root.exists() {
        fs::remove_dir_all(&install_root)
            .map_err(|error| format!("service removed, but files could not be deleted: {error}"))?;
    }
    Ok(())
}

fn run_service() -> u8 {
    let service_name = wide(SERVICE_NAME);
    let mut table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: service_name.as_ptr().cast_mut(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW::default(),
    ];
    // SAFETY: the dispatch table and its service name remain alive until the
    // dispatcher returns; service_main is a valid system-ABI entry point.
    if unsafe { StartServiceCtrlDispatcherW(table.as_mut_ptr()) } == 0 {
        report_engine_error(&last_error(
            "could not connect to the Windows service manager",
        ));
        return 1;
    }
    0
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut windows_sys::core::PWSTR) {
    let (sender, receiver) = mpsc::channel();
    let context = Box::leak(Box::new(ServiceContext {
        status_handle: null_mut(),
        events: sender,
    }));
    let context_ptr = (context as *mut ServiceContext).cast::<c_void>();
    let service_name = wide(SERVICE_NAME);
    // SAFETY: service_name remains alive through registration. The context is
    // intentionally leaked until process exit so an in-flight SCM callback can
    // never observe freed memory while the service is stopping.
    let status_handle = unsafe {
        RegisterServiceCtrlHandlerExW(
            service_name.as_ptr(),
            Some(service_control_handler),
            context_ptr,
        )
    };
    if status_handle.is_null() {
        report_engine_error(&last_error(
            "could not register the service control handler",
        ));
        return;
    }
    context.status_handle = status_handle;
    set_service_status(status_handle, SERVICE_START_PENDING, 0, 30_000, 0);

    let result = service_loop(receiver, status_handle);
    let (exit_code, message) = match result {
        Ok(()) => (0, None),
        Err(error) => (1, Some(error)),
    };
    if let Some(message) = message {
        report_engine_error(&message);
    }
    set_service_status(status_handle, SERVICE_STOPPED, exit_code, 0, 0);
}

unsafe extern "system" fn service_control_handler(
    control: u32,
    event_type: u32,
    event_data: *mut c_void,
    context: *mut c_void,
) -> u32 {
    if context.is_null() {
        return 0;
    }
    // SAFETY: service_main keeps this boxed context alive until the dispatcher
    // has stopped invoking the registered handler.
    let context = unsafe { &*(context.cast::<ServiceContext>()) };
    match control {
        SERVICE_CONTROL_STOP => {
            set_service_status(context.status_handle, SERVICE_STOP_PENDING, 0, 30_000, 1);
            let _ = context.events.send(ServiceEvent::Stop);
        }
        SERVICE_CONTROL_SESSIONCHANGE => {
            if event_data.is_null() {
                return 0;
            }
            // SAFETY: the SCM supplies a WTSSESSION_NOTIFICATION for session
            // change controls, valid for the duration of this callback.
            let notification = unsafe { &*(event_data.cast::<WTSSESSION_NOTIFICATION>()) };
            let event = match event_type {
                WTS_SESSION_LOGON => Some(ServiceEvent::Logon(notification.dwSessionId)),
                WTS_SESSION_LOGOFF => Some(ServiceEvent::Logoff(notification.dwSessionId)),
                _ => None,
            };
            if let Some(event) = event {
                let _ = context.events.send(event);
            }
        }
        SERVICE_CONTROL_INTERROGATE => {}
        _ => {}
    }
    0
}

fn service_loop(
    receiver: Receiver<ServiceEvent>,
    status_handle: SERVICE_STATUS_HANDLE,
) -> Result<(), String> {
    let install_root = std::env::current_exe()
        .map_err(|error| format!("could not locate the installed service: {error}"))?
        .parent()
        .ok_or_else(|| "could not locate the installed service folder".to_owned())?
        .to_path_buf();
    let engine_path = install_root.join("Engine");
    let config_path = install_root.join("service.ini");
    let settings_path = PathBuf::from(read_profile_string(
        "Service",
        SETTINGS_FILE_KEY,
        &config_path,
    )?);
    if settings_path.as_os_str().is_empty() {
        return Err(format!(
            "the service configuration does not specify {SETTINGS_FILE_KEY}"
        ));
    }

    set_service_status(
        status_handle,
        SERVICE_RUNNING,
        0,
        0,
        SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SESSIONCHANGE,
    );

    let mut engine: Option<EngineSession> = None;
    let mut retry_engine_at = Instant::now();

    loop {
        let event = match receiver.recv_timeout(SCAN_INTERVAL) {
            Ok(event) => Some(event),
            Err(RecvTimeoutError::Disconnected) => return Ok(()),
            Err(RecvTimeoutError::Timeout) => None,
        };
        if matches!(&event, Some(ServiceEvent::Stop)) {
            return Ok(());
        }

        let safe_mode = read_profile_int("Settings", "SafeMode", &settings_path, 0)? != 0;
        if safe_mode {
            if engine.take().is_some() {
                report_engine_error("Safe Mode enabled; the persistent engine session was stopped");
            }
            retry_engine_at = Instant::now() + ENGINE_RETRY_INTERVAL;
            continue;
        }

        let mut engine_started = false;
        if engine.is_none() && Instant::now() >= retry_engine_at {
            match start_engine_for_logged_on_sessions(&engine_path) {
                Ok(started) => {
                    engine = Some(started);
                    engine_started = true;
                }
                Err(error) => {
                    report_engine_error(&error);
                    retry_engine_at = Instant::now() + ENGINE_RETRY_INTERVAL;
                }
            }
        }

        if !engine_started {
            if let (Some(engine), Some(event)) = (engine.as_ref(), event) {
                if let Err(error) = process_session_event(engine, event) {
                    report_engine_error(&error);
                }
            }
        }
        if !engine_started {
            if let Some(active_engine) = engine.as_ref() {
                if let Err(error) = active_engine.handle_new_processes() {
                    report_engine_error(&error);
                    engine.take();
                    retry_engine_at = Instant::now() + ENGINE_RETRY_INTERVAL;
                }
            }
        }
    }
}

fn start_engine_for_logged_on_sessions(engine_path: &Path) -> Result<EngineSession, String> {
    let engine = EngineSession::start(engine_path)?;
    engine.record_current_session_users()?;
    for session_id in logged_on_sessions()? {
        engine.handle_logon(session_id)?;
    }
    engine.handle_new_processes()?;
    Ok(engine)
}

fn logged_on_sessions() -> Result<Vec<u32>, String> {
    let mut sessions: *mut WTS_SESSION_INFOW = null_mut();
    let mut count = 0;
    // SAFETY: the output pointers are writable and a null server handle selects
    // the local machine. The returned array is released with WTSFreeMemory.
    if unsafe { WTSEnumerateSessionsW(null_mut(), 0, 1, &mut sessions, &mut count) } == 0 {
        return Err(last_error("could not enumerate logged-on Windows sessions"));
    }
    if sessions.is_null() {
        if count == 0 {
            return Ok(Vec::new());
        }
        return Err("Windows returned an invalid session list".to_owned());
    }
    if count == 0 {
        // SAFETY: WTSEnumerateSessionsW allocated this empty result.
        unsafe { WTSFreeMemory(sessions.cast()) };
        return Ok(Vec::new());
    }

    // SAFETY: WTSEnumerateSessionsW returned count entries in the allocated array.
    let session_info = unsafe { slice::from_raw_parts(sessions, count as usize) };
    let ids = session_info
        .iter()
        .filter(|session| {
            session.SessionId != 0
                && (session.State == WTSActive
                    || session.State == WTSConnected
                    || session.State == WTSDisconnected)
        })
        .map(|session| session.SessionId)
        .collect();
    // SAFETY: sessions was allocated by WTSEnumerateSessionsW.
    unsafe { WTSFreeMemory(sessions.cast()) };
    Ok(ids)
}

fn process_session_event(engine: &EngineSession, event: ServiceEvent) -> Result<(), String> {
    match event {
        ServiceEvent::Logon(session_id) => {
            engine.record_session_logon(session_id)?;
            if logged_on_sessions()?.contains(&session_id) {
                engine.handle_logon(session_id)?;
            }
        }
        ServiceEvent::Logoff(session_id) => {
            engine.record_current_session_users()?;
            engine.remove_session_user(session_id)?;
        }
        ServiceEvent::Stop => {}
    }
    Ok(())
}

fn query_service_status(
    service: windows_sys::Win32::System::Services::SC_HANDLE,
) -> Result<SERVICE_STATUS_PROCESS, String> {
    let mut status = SERVICE_STATUS_PROCESS::default();
    let mut bytes_needed = 0;
    // SAFETY: service is valid and status provides a writable buffer of its size.
    if unsafe {
        QueryServiceStatusEx(
            service,
            SC_STATUS_PROCESS_INFO,
            (&mut status as *mut SERVICE_STATUS_PROCESS).cast(),
            std::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32,
            &mut bytes_needed,
        )
    } == 0
    {
        return Err(last_error(
            "could not read the UniWind engine service status",
        ));
    }
    Ok(status)
}

fn ensure_service_absent() -> Result<(), String> {
    let manager = open_manager(SC_MANAGER_CONNECT)?;
    let service_name = wide(SERVICE_NAME);
    // SAFETY: manager is valid and service_name is NUL-terminated.
    let service = unsafe { OpenServiceW(manager.0, service_name.as_ptr(), SERVICE_QUERY_STATUS) };
    if service.is_null() {
        let error = unsafe { GetLastError() };
        if error == ERROR_SERVICE_DOES_NOT_EXIST || error == ERROR_SERVICE_MARKED_FOR_DELETE {
            return Ok(());
        }
        return Err(format!(
            "could not check for an existing UniWind engine service (Windows error {error})"
        ));
    }
    // SAFETY: the service handle was successfully opened.
    unsafe { CloseServiceHandle(service) };
    Err(
        "The UniWind engine service is already registered. Remove it before reinstalling."
            .to_owned(),
    )
}

fn configure_recovery(
    service: windows_sys::Win32::System::Services::SC_HANDLE,
) -> Result<(), String> {
    let mut actions = [SC_ACTION {
        Type: SC_ACTION_RESTART,
        Delay: 5_000,
    }];
    let failure_actions = SERVICE_FAILURE_ACTIONSW {
        dwResetPeriod: 86_400,
        lpRebootMsg: null_mut(),
        lpCommand: null_mut(),
        cActions: actions.len() as u32,
        lpsaActions: actions.as_mut_ptr(),
    };
    // SAFETY: service is valid and both structures remain alive for the call;
    // the single restart action is retained by the SCM.
    if unsafe {
        ChangeServiceConfig2W(
            service,
            SERVICE_CONFIG_FAILURE_ACTIONS,
            (&failure_actions as *const SERVICE_FAILURE_ACTIONSW).cast(),
        )
    } == 0
    {
        return Err(last_error("could not configure automatic service recovery"));
    }

    let failure_actions_flag = SERVICE_FAILURE_ACTIONS_FLAG {
        fFailureActionsOnNonCrashFailures: 1,
    };
    // SAFETY: service and the configuration structure are valid for this call.
    if unsafe {
        ChangeServiceConfig2W(
            service,
            SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
            (&failure_actions_flag as *const SERVICE_FAILURE_ACTIONS_FLAG).cast(),
        )
    } == 0
    {
        return Err(last_error(
            "could not configure service recovery for failed exits",
        ));
    }
    Ok(())
}

fn rollback_service(
    service: windows_sys::Win32::System::Services::SC_HANDLE,
) -> Result<(), String> {
    let status = query_service_status(service)?;
    let process = if status.dwCurrentState == SERVICE_STOPPED {
        None
    } else {
        open_service_process(status.dwProcessId)?
    };
    if status.dwCurrentState != SERVICE_STOPPED {
        let mut service_status = SERVICE_STATUS::default();
        // SAFETY: service is valid and service_status is writable.
        if unsafe { ControlService(service, SERVICE_CONTROL_STOP, &mut service_status) } == 0 {
            let error = unsafe { GetLastError() };
            if error != ERROR_SERVICE_NOT_ACTIVE {
                return Err(format!(
                    "could not stop the partially installed service (Windows error {error})"
                ));
            }
        }
        wait_until_stopped(service, Duration::from_secs(60))?;
    }
    if let Some(process) = process {
        wait_for_process_exit(process.0, Duration::from_secs(60))?;
    }
    delete_new_service(service)
}

fn open_service_process(process_id: u32) -> Result<Option<ProcessHandle>, String> {
    if process_id == 0 {
        return Ok(None);
    }
    // SAFETY: opening a process for SYNCHRONIZE does not mutate it.
    let process = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, process_id) };
    if process.is_null() {
        let error = unsafe { GetLastError() };
        if error == ERROR_INVALID_PARAMETER {
            return Ok(None);
        }
        return Err(format!(
            "could not wait for the engine service process to exit (Windows error {error})"
        ));
    }
    Ok(Some(ProcessHandle(process)))
}

fn wait_for_process_exit(process: HANDLE, timeout: Duration) -> Result<(), String> {
    // SAFETY: process is an open process handle and the wait has a finite timeout.
    match unsafe { WaitForSingleObject(process, timeout.as_millis() as u32) } {
        WAIT_OBJECT_0 => Ok(()),
        WAIT_TIMEOUT => {
            Err("timed out while waiting for the engine service process to exit".to_owned())
        }
        _ => Err(last_error(
            "could not wait for the engine service process to exit",
        )),
    }
}

fn delete_new_service(
    service: windows_sys::Win32::System::Services::SC_HANDLE,
) -> Result<(), String> {
    // SAFETY: service is a valid handle with DELETE access.
    if unsafe { DeleteService(service) } == 0 {
        return Err(last_error(
            "could not remove the partially installed service",
        ));
    }
    Ok(())
}

fn remove_install_files(install_root: &Path, error: String) -> String {
    if !install_root.exists() {
        return error;
    }
    match fs::remove_dir_all(install_root) {
        Ok(()) => error,
        Err(cleanup_error) => format!(
            "{error}; temporary service files could not be removed from {}: {cleanup_error}",
            install_root.display()
        ),
    }
}

fn finish_failed_install(
    install_root: &Path,
    error: String,
    rollback: Result<(), String>,
) -> String {
    match rollback {
        Ok(()) => remove_install_files(install_root, error),
        Err(rollback_error) => format!(
            "{error}; service rollback failed: {rollback_error}. Files were left in {} so a running service is not disturbed.",
            install_root.display()
        ),
    }
}

fn wait_until_running(
    service: windows_sys::Win32::System::Services::SC_HANDLE,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        let status = query_service_status(service)?;
        if status.dwCurrentState == SERVICE_RUNNING {
            return Ok(());
        }
        if status.dwCurrentState == SERVICE_STOPPED {
            return Err(format!(
                "the service stopped during startup (Windows error {})",
                status.dwWin32ExitCode
            ));
        }
        if Instant::now() >= deadline {
            return Err("timed out while waiting for the engine service to start".to_owned());
        }
        // SAFETY: Sleep has no preconditions.
        unsafe { Sleep(250) };
    }
}

fn wait_until_stopped(
    service: windows_sys::Win32::System::Services::SC_HANDLE,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        let status = query_service_status(service)?;
        if status.dwCurrentState == SERVICE_STOPPED {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("timed out while waiting for the engine service to stop".to_owned());
        }
        // SAFETY: Sleep has no preconditions.
        unsafe { Sleep(250) };
    }
}

fn set_service_status(
    handle: SERVICE_STATUS_HANDLE,
    state: u32,
    exit_code: u32,
    wait_hint: u32,
    accepted_controls: u32,
) {
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: accepted_controls,
        dwWin32ExitCode: exit_code,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: if state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING {
            1
        } else {
            0
        },
        dwWaitHint: wait_hint,
    };
    // SAFETY: handle was returned by RegisterServiceCtrlHandlerExW and status
    // remains alive until the API returns.
    if unsafe { SetServiceStatus(handle, &status) } == 0 {
        report_engine_error(&last_error("could not update the Windows service status"));
    }
}

fn open_manager(access: u32) -> Result<ServiceHandle, String> {
    // SAFETY: null machine/database names select the local SCM.
    let manager = unsafe { OpenSCManagerW(null(), null(), access) };
    if manager.is_null() {
        return Err(last_error("could not open the Windows service manager"));
    }
    Ok(ServiceHandle(manager))
}

fn resolve_config_path(
    base: &Path,
    section: &str,
    key: &str,
    config_path: &Path,
) -> Result<PathBuf, String> {
    let raw = read_profile_string(section, key, config_path)?;
    if raw.is_empty() {
        return Err(format!(
            "{} does not define [{section}] {key}",
            config_path.display()
        ));
    }
    let expanded = expand_environment(&raw)?;
    let path = PathBuf::from(expanded);
    Ok(if path.is_absolute() {
        path
    } else {
        base.join(path)
    })
}

fn expand_environment(value: &str) -> Result<String, String> {
    let source = wide(value);
    let mut buffer = vec![0u16; 32_768];
    // SAFETY: source and buffer are valid UTF-16 buffers; the call writes at
    // most buffer.len() code units.
    let length = unsafe {
        windows_sys::Win32::System::Environment::ExpandEnvironmentStringsW(
            source.as_ptr(),
            buffer.as_mut_ptr(),
            buffer.len() as u32,
        )
    };
    if length == 0 || length as usize > buffer.len() {
        return Err(last_error("could not expand a configured Windows path"));
    }
    Ok(String::from_utf16_lossy(&buffer[..length as usize - 1]))
}

fn read_profile_string(section: &str, key: &str, file: &Path) -> Result<String, String> {
    let file_display = file.display().to_string();
    let section = wide(section);
    let key = wide(key);
    let file = wide(&file.to_string_lossy());
    let default = [0u16];
    let mut buffer = vec![0u16; 32_768];
    // SAFETY: all strings are NUL-terminated and buffer is writable.
    let length = unsafe {
        GetPrivateProfileStringW(
            section.as_ptr(),
            key.as_ptr(),
            default.as_ptr(),
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            file.as_ptr(),
        )
    } as usize;
    if length >= buffer.len() - 1 {
        return Err(format!("a setting in {file_display} is too long"));
    }
    Ok(String::from_utf16_lossy(&buffer[..length]))
}

fn read_profile_int(section: &str, key: &str, file: &Path, default: i32) -> Result<i32, String> {
    match fs::metadata(file) {
        Ok(metadata) if metadata.is_file() => {}
        Ok(_) => {
            return Err(format!(
                "the settings path is not a file: {}",
                file.display()
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(default),
        Err(error) => {
            return Err(format!(
                "could not inspect the settings file {}: {error}",
                file.display()
            ));
        }
    }

    let value = read_profile_string(section, key, file)?;
    if value.is_empty() {
        return Ok(default);
    }
    value.trim().parse::<i32>().map_err(|error| {
        format!(
            "the setting [{section}] {key} in {} is not a valid integer: {error}",
            file.display()
        )
    })
}

fn program_files_directory() -> Result<PathBuf, String> {
    let mut buffer = vec![0u16; 32_768];
    // SAFETY: buffer is writable and large enough for a Windows path.
    let result = unsafe {
        SHGetFolderPathW(
            null_mut(),
            CSIDL_PROGRAM_FILES as i32,
            null_mut(),
            SHGFP_TYPE_CURRENT as u32,
            buffer.as_mut_ptr(),
        )
    };
    if result < 0 {
        return Err(format!(
            "could not resolve Program Files (HRESULT 0x{:08X})",
            result as u32
        ));
    }
    let length = buffer
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(buffer.len());
    Ok(PathBuf::from(String::from_utf16_lossy(&buffer[..length])))
}

fn copy_directory(source: &Path, destination: &Path) -> Result<(), String> {
    for entry in fs::read_dir(source).map_err(|error| {
        format!(
            "could not read engine files from {}: {error}",
            source.display()
        )
    })? {
        let entry = entry.map_err(|error| format!("could not enumerate engine files: {error}"))?;
        let file_type = entry
            .file_type()
            .map_err(|error| format!("could not inspect {}: {error}", entry.path().display()))?;
        let target = destination.join(entry.file_name());
        if file_type.is_symlink() {
            return Err(format!(
                "refusing to install a symbolic link from {}",
                entry.path().display()
            ));
        }
        if file_type.is_dir() {
            fs::create_dir(&target)
                .map_err(|error| format!("could not create {}: {error}", target.display()))?;
            copy_directory(&entry.path(), &target)?;
        } else if file_type.is_file() {
            fs::copy(entry.path(), &target)
                .map_err(|error| format!("could not copy {}: {error}", entry.path().display()))?;
        } else {
            return Err(format!(
                "unsupported engine file type: {}",
                entry.path().display()
            ));
        }
    }
    Ok(())
}

fn write_utf16_ini(path: &Path, contents: &str) -> Result<(), String> {
    let mut bytes = vec![0xFF, 0xFE];
    for unit in contents.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    fs::write(path, bytes).map_err(|error| format!("could not write {}: {error}", path.display()))
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

fn last_error(action: &str) -> String {
    // SAFETY: GetLastError has no preconditions.
    let error = unsafe { GetLastError() };
    format!("{action} (Windows error {error})")
}

fn show_message(message: &str, error: bool) {
    let title = wide("UniWind");
    let message = wide(message);
    // SAFETY: both strings are NUL-terminated and remain alive for the call.
    unsafe {
        MessageBoxW(
            null_mut(),
            message.as_ptr(),
            title.as_ptr(),
            MB_OK
                | if error {
                    MB_ICONERROR
                } else {
                    MB_ICONINFORMATION
                },
        )
    };
}

#[cfg(test)]
mod tests {
    use super::{read_profile_int, resolve_config_path, write_utf16_ini};

    #[test]
    fn reads_safe_mode_from_the_utf16_portable_settings_file() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let settings_path = directory.path().join("settings.ini");
        write_utf16_ini(&settings_path, "[Settings]\r\nSafeMode=1\r\n").expect("write settings");

        assert_eq!(
            read_profile_int("Settings", "SafeMode", &settings_path, 0).expect("read SafeMode"),
            1
        );
    }

    #[test]
    fn resolves_relative_engine_data_paths_from_the_engine_folder() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let engine_path = directory.path().join("Engine");
        std::fs::create_dir(&engine_path).expect("create engine folder");
        let config_path = engine_path.join("engine.ini");
        write_utf16_ini(
            &config_path,
            "[Storage]\r\nAppDataPath=..\\AppData\\Engine\r\n",
        )
        .expect("write engine configuration");

        assert_eq!(
            resolve_config_path(&engine_path, "Storage", "AppDataPath", &config_path)
                .expect("resolve engine data path"),
            engine_path.join("..").join("AppData").join("Engine")
        );
    }
}
