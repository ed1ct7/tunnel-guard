mod wfp;
pub(crate) use wfp::group_network;

use crate::{
    core_rules::load_generated,
    progress::{parse_progress, Progress, ProgressStage, PROGRESS_FILE},
    settings::{client_path, load_settings, lock_config, storage, ProtectionBackend},
    status::{core_routes_tunnel, now_ms, Action, GuardState, Status, StatusWarning},
    Result,
};
use std::{
    env,
    ffi::OsStr,
    fs, io,
    os::windows::{ffi::OsStrExt, process::CommandExt},
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    },
    time::Duration,
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, HWND, INVALID_HANDLE_VALUE, WAIT_ABANDONED, WAIT_OBJECT_0},
    System::{
        Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        },
        Threading::{
            CreateMutexW, GetExitCodeProcess, OpenProcess, QueryFullProcessImageNameW,
            ReleaseMutex, WaitForSingleObject, CREATE_NO_WINDOW, INFINITE, PROCESS_NAME_WIN32,
            PROCESS_QUERY_LIMITED_INFORMATION,
        },
    },
    UI::{
        Shell::{
            IsUserAnAdmin, ShellExecuteExW, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS,
            SHELLEXECUTEINFOW,
        },
        WindowsAndMessaging::SW_SHOWNORMAL,
    },
};

static CHANGE: Mutex<()> = Mutex::new(());
const SCRIPT: &str = include_str!("firewall.ps1");
const PROGRESS_POLL: Duration = Duration::from_millis(250);

fn powershell(action: &str) -> Result<Output> {
    run_script(action, None, &[])
}

/// Variables that make PowerShell or .NET load code from elsewhere. The
/// script runs elevated, so it must not inherit them from the user's session.
fn loads_foreign_code(name: &str) -> bool {
    let name = name.to_ascii_uppercase();
    ["COR_", "CORECLR_", "COMPLUS_", "DOTNET_"]
        .iter()
        .any(|prefix| name.starts_with(prefix))
        || matches!(
            name.as_str(),
            "PSEXECUTIONPOLICYPREFERENCE" | "__PSLOCKDOWNPOLICY" | "PSMODULEPATH"
        )
}

fn run_script(action: &str, progress: Option<&Path>, extra: &[(&str, &OsStr)]) -> Result<Output> {
    let system_root = PathBuf::from(env::var_os("SystemRoot").ok_or("SystemRoot не найден.")?);
    let system = system_root.join("System32");
    let shell = system.join("WindowsPowerShell").join("v1.0");
    let executable = shell.join("powershell.exe");
    let command = format!("& {{\n{SCRIPT}\n}} -Action $env:TUNNEL_GUARD_ACTION -SettingsPath $env:TUNNEL_GUARD_SETTINGS -ProgressPath $env:TUNNEL_GUARD_PROGRESS");
    let mut process = Command::new(executable);
    for (name, _) in env::vars_os() {
        if name.to_str().is_some_and(loads_foreign_code) {
            process.env_remove(name);
        }
    }
    let path = env::join_paths([
        system.clone(),
        system_root.clone(),
        system.join("Wbem"),
        shell.clone(),
    ])
    .map_err(|error| error.to_string())?;
    process
        .args(["-NoProfile", "-NonInteractive", "-Command", &command])
        // Only the built-in modules: a user-writable module path would let an
        // unelevated process plant NetTCPIP or NetSecurity for the worker.
        .env("PSModulePath", shell.join("Modules"))
        .env("PATH", path)
        .env("TUNNEL_GUARD_ACTION", action)
        .env("TUNNEL_GUARD_SETTINGS", storage()?.join("settings.json"));
    match progress {
        Some(path) => process.env("TUNNEL_GUARD_PROGRESS", path),
        None => process.env_remove("TUNNEL_GUARD_PROGRESS"),
    };
    for (key, value) in extra {
        process.env(key, value);
    }
    process
        .env_remove("TUNNEL_GUARD_CONTROLLER_PORT")
        .env_remove("TUNNEL_GUARD_CONTROLLER_SECRET")
        .env_remove("TUNNEL_GUARD_WFP_WORKER")
        .env_remove(wfp::CORE_ENV)
        .env_remove(wfp::ADAPTER_ENV)
        .env_remove(wfp::CORE_PID_ENV);
    if matches!(action, "WfpEnable" | "WfpUpgrade" | "WfpDisable") {
        process.env(
            "TUNNEL_GUARD_WFP_WORKER",
            env::current_exe().map_err(|error| error.to_string())?,
        );
    }
    if matches!(
        action,
        "Rules" | "Targets" | "Preflight" | "Enable" | "WfpEnable" | "WfpUpgrade"
    ) {
        if let Some((port, secret)) = configured_controller() {
            process.env("TUNNEL_GUARD_CONTROLLER_PORT", port.to_string());
            if let Some(secret) = secret {
                process.env("TUNNEL_GUARD_CONTROLLER_SECRET", secret);
            }
        }
    }
    process
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|error| error.to_string())
}

fn configured_controller() -> Option<(u16, Option<String>)> {
    let settings = load_settings().ok()?;
    let client = client_path(&settings).ok()?;
    let config = load_generated(client.parent()?, settings.proxy_port).ok()?;
    Some((config.controller_port()?, config.secret()))
}

fn group_policy_status() -> Result<Status> {
    let output = powershell("Status")?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().into());
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|_| "Не удалось прочитать фактический статус Windows.".into())
}

/// Whether the live Mihomo has left the routing the guard was verified with.
/// An unreachable controller is not reported: the adapter state covers it.
fn core_routing_changed(adapter: &str) -> bool {
    let Some((port, secret)) = configured_controller() else {
        return false;
    };
    crate::http::get_json(port, "/configs", secret.as_deref())
        .is_ok_and(|configs| !core_routes_tunnel(&configs, adapter))
}

pub fn status() -> Result<Status> {
    let mut status = group_policy_status()?;
    let settings = load_settings()?;
    let wfp = wfp::status(status.adapter_up.then_some(settings.adapter.as_str()))?;
    match (wfp.state, status.state) {
        (GuardState::Off, GuardState::On | GuardState::Partial | GuardState::LegacyActive) => {
            status.active_backend = Some(ProtectionBackend::GroupPolicy);
        }
        (GuardState::Off, _) => {}
        (state, GuardState::Off | GuardState::LegacyInactive) => {
            status.state = state;
            status.active_backend = Some(ProtectionBackend::Wfp);
            status.adapter_up &= wfp.tunnel_matches;
            if state == GuardState::On && wfp.foreign_hard_permit {
                status.warnings.push(StatusWarning::ForeignHardPermit);
            }
            if state == GuardState::On && wfp.outdated {
                status.warnings.push(StatusWarning::OutdatedPolicy);
            }
        }
        _ => {
            // Concurrent policies may override one another. Require recovery.
            status.state = GuardState::Partial;
        }
    }
    if status.state == GuardState::On
        && status.adapter_up
        && core_routing_changed(&settings.adapter)
    {
        status.warnings.insert(0, StatusWarning::CoreRouting);
    }
    Ok(status)
}

pub fn active_rules() -> Result<serde_json::Value> {
    read_controller("Rules")
}

pub fn targets() -> Result<Vec<String>> {
    #[derive(serde::Deserialize)]
    struct Response {
        targets: Vec<String>,
    }
    serde_json::from_value::<Response>(read_controller("Targets")?)
        .map(|response| response.targets)
        .map_err(|_| "Не удалось прочитать список VPN-маршрутов.".into())
}

fn read_controller(action: &str) -> Result<serde_json::Value> {
    let output = powershell(action)?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().into());
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|_| "Не удалось прочитать список активных правил.".into())
}

/// Read-only system facts for the diagnosis (adapter, listeners, v2rayN).
/// `adapter` must already be validated (no wildcard characters).
pub fn diagnose_facts(
    adapter: Option<&str>,
    proxy_port: Option<u16>,
    controller_port: Option<u16>,
) -> Result<serde_json::Value> {
    let port = |port: Option<u16>| port.map(|port| port.to_string()).unwrap_or_default();
    let (proxy_port, controller_port) = (port(proxy_port), port(controller_port));
    let output = run_script(
        "Diagnose",
        None,
        &[
            (
                "TUNNEL_GUARD_DIAG_ADAPTER",
                OsStr::new(adapter.unwrap_or_default()),
            ),
            ("TUNNEL_GUARD_DIAG_PORT", OsStr::new(&proxy_port)),
            ("TUNNEL_GUARD_DIAG_CONTROLLER", OsStr::new(&controller_port)),
        ],
    )?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().into());
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|_| "Не удалось прочитать состояние системы.".into())
}

/// Full image paths of running processes named `image` (e.g. "v2rayN.exe").
/// `None` for a process whose path cannot be queried.
pub fn running_images(image: &str) -> Vec<Option<PathBuf>> {
    let mut found = Vec::new();
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE || snapshot.is_null() {
            return found;
        }
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        let mut more = Process32FirstW(snapshot, &mut entry) != 0;
        while more {
            let length = entry
                .szExeFile
                .iter()
                .position(|&unit| unit == 0)
                .unwrap_or(entry.szExeFile.len());
            let name = String::from_utf16_lossy(&entry.szExeFile[..length]);
            if name.eq_ignore_ascii_case(image) {
                found.push(process_path(entry.th32ProcessID));
            }
            more = Process32NextW(snapshot, &mut entry) != 0;
        }
        CloseHandle(snapshot);
    }
    found
}

unsafe fn process_path(pid: u32) -> Option<PathBuf> {
    let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
    if process.is_null() {
        return None;
    }
    let mut buffer = vec![0u16; 32768];
    let mut size = buffer.len() as u32;
    let ok =
        QueryFullProcessImageNameW(process, PROCESS_NAME_WIN32, buffer.as_mut_ptr(), &mut size);
    CloseHandle(process);
    (ok != 0).then(|| {
        use std::os::windows::ffi::OsStringExt;
        PathBuf::from(std::ffi::OsString::from_wide(&buffer[..size as usize]))
    })
}

/// Entry point of the GUI's elevated `--firewall-worker`: like `worker`, and
/// additionally lets the script report stages to the progress file.
pub fn elevated_worker(args: &[String]) -> i32 {
    let progress = storage().ok().map(|dir| dir.join(PROGRESS_FILE));
    run_worker(args, progress.as_deref())
}

pub fn worker(args: &[String]) -> i32 {
    run_worker(args, None)
}

pub fn wfp_worker(args: &[String]) -> i32 {
    wfp::run(args)
}

struct PolicyLock(HANDLE);

impl PolicyLock {
    fn acquire() -> Option<Self> {
        let name = wide(OsStr::new("Global\\TunnelGuardFirewallPolicy"));
        let handle = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
        if handle.is_null() {
            return None;
        }
        if matches!(
            unsafe { WaitForSingleObject(handle, 0) },
            WAIT_OBJECT_0 | WAIT_ABANDONED
        ) {
            return Some(Self(handle));
        }
        unsafe { CloseHandle(handle) };
        None
    }
}

impl Drop for PolicyLock {
    fn drop(&mut self) {
        unsafe {
            ReleaseMutex(self.0);
            CloseHandle(self.0);
        }
    }
}

fn run_worker(args: &[String], progress: Option<&Path>) -> i32 {
    let [action] = args else { return 20 };
    if !matches!(action.as_str(), "Enable" | "Disable" | "CleanLegacy") {
        return 20;
    }
    if !is_admin() {
        return 22;
    }
    let Ok(_config_lock) = lock_config() else {
        return 28;
    };
    let Some(_policy_lock) = PolicyLock::acquire() else {
        return 28;
    };
    let Ok(wfp) = wfp::status(None) else {
        return 31;
    };
    let action = match (action.as_str(), wfp.state) {
        ("Enable", GuardState::On) => match group_policy_status().map(|status| status.state) {
            // Enabling an outdated set replaces it in place, without a gap.
            Ok(GuardState::Off | GuardState::LegacyInactive) if wfp.outdated => "WfpUpgrade",
            Ok(GuardState::Off | GuardState::LegacyInactive) => return 0,
            _ => return 26,
        },
        ("Enable" | "CleanLegacy", GuardState::Partial | GuardState::On) => return 26,
        ("Disable", GuardState::Partial | GuardState::On) => "WfpDisable",
        ("Enable", _) => match load_settings() {
            Ok(settings) if settings.protection_backend == ProtectionBackend::Wfp => "WfpEnable",
            Ok(_) => "Enable",
            Err(_) => return 29,
        },
        (action, _) => action,
    };
    let Ok(output) = run_script(action, progress, &[]) else {
        return 21;
    };
    if output.status.success() {
        return 0;
    }
    failure_code(&output.stderr) as i32
}

fn failure_code(stderr: &[u8]) -> u32 {
    let message = String::from_utf8_lossy(stderr);
    match message
        .lines()
        .find_map(|line| line.trim().strip_prefix("TG_STAGE:"))
    {
        Some("ADMIN") => 22,
        Some("TUN") => 23,
        Some("CONFLICT") => 24,
        Some("VERIFY") => 25,
        Some("RESTORE") => 26,
        Some("SETTINGS") => 29,
        Some("POLICY") => 30,
        Some("WFP") => 31,
        _ => 27,
    }
}

pub(crate) type Report<'a> = &'a (dyn Fn(Progress) + Sync);

/// The worker's progress file for one operation. Best effort throughout:
/// nothing here can change the result of the operation.
struct ProgressFile {
    path: Option<PathBuf>,
    action: Action,
    since: u64,
}

impl ProgressFile {
    fn start(action: Action) -> Self {
        let file = Self {
            path: storage().ok().map(|dir| dir.join(PROGRESS_FILE)),
            action,
            since: now_ms(),
        };
        file.remove();
        file
    }

    fn remove(&self) {
        if let Some(path) = &self.path {
            let _ = fs::remove_file(path);
            let _ = fs::remove_file(path.with_extension("json.tmp"));
        }
    }

    fn emit(&self, report: Report, stage: ProgressStage) {
        let progress = Progress {
            action: self.action,
            stage,
            at: now_ms(),
        };
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| report(progress)));
    }

    fn poll(&self, report: Report, last: &mut Option<Progress>) {
        let Some(path) = &self.path else { return };
        let Ok(raw) = fs::read(path) else { return };
        if let Some(progress) = parse_progress(&raw, self.action, self.since) {
            if *last != Some(progress) {
                *last = Some(progress);
                report(progress);
            }
        }
    }

    /// Run `wait` on this thread while a watcher forwards new stages.
    fn watch<T>(&self, report: Report, wait: impl FnOnce() -> T) -> T {
        let stop = AtomicBool::new(false);
        let last = Mutex::new(None);
        let result = std::thread::scope(|scope| {
            let watcher = std::thread::Builder::new().spawn_scoped(scope, || {
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    while !stop.load(Ordering::SeqCst) {
                        if let Ok(mut last) = last.lock() {
                            self.poll(report, &mut last);
                        }
                        std::thread::sleep(PROGRESS_POLL);
                    }
                }));
            });
            let result = wait();
            stop.store(true, Ordering::SeqCst);
            if let Ok(watcher) = watcher {
                let _ = watcher.join();
            }
            result
        });
        // Catch the last stage written just before the worker exited.
        if let Ok(mut last) = last.lock() {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                self.poll(report, &mut last)
            }));
        }
        result
    }
}

impl Drop for ProgressFile {
    fn drop(&mut self) {
        self.remove();
    }
}

/// Run one protection change through UAC. `report` receives `guard-progress`
/// stages, ending with `done` or `failed` once the operation has started.
pub fn elevate(action: Action, parent: isize, report: Report) -> Result<()> {
    let _operation = CHANGE
        .try_lock()
        .map_err(|_| "Другая операция уже выполняется.")?;
    let progress = ProgressFile::start(action);
    let result = run_elevated(action, parent, report, &progress);
    progress.emit(
        report,
        if result.is_ok() {
            ProgressStage::Done
        } else {
            ProgressStage::Failed
        },
    );
    result
}

fn run_elevated(
    action: Action,
    parent: isize,
    report: Report,
    progress: &ProgressFile,
) -> Result<()> {
    if matches!(action, Action::Enable) {
        progress.emit(report, ProgressStage::Preflight);
        let check = powershell("Preflight")?;
        if !check.status.success() {
            return worker_result(failure_code(&check.stderr));
        }
    }
    progress.emit(report, ProgressStage::Elevate);
    let parameters = format!("--firewall-worker {}", action.name());
    let code = elevated_result(parent, &parameters, |process| {
        progress.watch(report, || unsafe { WaitForSingleObject(process, INFINITE) })
    })?;
    worker_result(code)
}

pub(crate) fn is_admin() -> bool {
    unsafe { IsUserAnAdmin() != 0 }
}

pub(crate) fn elevate_network_worker(
    parent: isize,
    id: &str,
    blocked: bool,
    fingerprint: Option<&str>,
) -> Result<()> {
    let parameters = if blocked {
        let fingerprint = fingerprint.ok_or("Отсутствует проверенный список путей группы.")?;
        format!("--process-network-worker block {id} {fingerprint}")
    } else {
        format!("--process-network-worker unblock {id}")
    };
    let code = elevated_result(parent, &parameters, |process| unsafe {
        WaitForSingleObject(process, INFINITE)
    })?;
    if code == 0 {
        Ok(())
    } else {
        Err(
            "Не удалось изменить доступ группы к сети. Проверь, что все указанные .exe существуют."
                .into(),
        )
    }
}

fn elevated_result(
    parent: isize,
    parameters: &str,
    wait: impl FnOnce(HANDLE) -> u32,
) -> Result<u32> {
    let executable = wide(
        env::current_exe()
            .map_err(|error| error.to_string())?
            .as_os_str(),
    );
    let verb = wide(OsStr::new("runas"));
    let parameters = wide(OsStr::new(parameters));
    let mut request = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOASYNC | SEE_MASK_NOCLOSEPROCESS,
        hwnd: parent as HWND,
        lpVerb: verb.as_ptr(),
        lpFile: executable.as_ptr(),
        lpParameters: parameters.as_ptr(),
        nShow: SW_SHOWNORMAL,
        ..Default::default()
    };
    unsafe {
        if ShellExecuteExW(&mut request) == 0 || request.hProcess.is_null() {
            let error = io::Error::last_os_error();
            return Err(if error.raw_os_error() == Some(1223) {
                "Запрос администратора отменён. Правила остались прежними.".into()
            } else {
                format!("Windows не запустила запрос администратора. {error}")
            });
        }
        let process = request.hProcess;
        let wait = wait(process);
        let mut code = 0;
        let read = GetExitCodeProcess(request.hProcess, &mut code);
        CloseHandle(request.hProcess);
        if wait != 0 || read == 0 {
            return Err("Не удалось получить результат изменения правил.".into());
        }
        Ok(code)
    }
}

pub fn worker_result(code: u32) -> Result<()> {
    match code {
        0 => Ok(()),
        22 => Err("Для изменения защиты запусти guardctl из консоли с правами администратора.".into()),
        23 => Err("Туннель Mihomo ещё не готов. Подключи профиль в v2rayN, включи Enable TUN в режиме Rule и повтори. Если ошибка осталась, проверь имя адаптера и порт во вкладке «Подключение».".into()),
        24 => Err("В локальной групповой политике уже есть исходящие правила. Существующая политика сохранена.".into()),
        25 => Err("Проверка связи не прошла. Проверь соединение через VPN и фактическое состояние защиты.".into()),
        26 => Err("Не удалось восстановить прежнюю политику. Проверь резервную копию правил.".into()),
        28 => Err("Tunnel Guard уже меняет настройки. Повтори после завершения операции.".into()),
        29 => Err("Проверь путь к v2rayN, имя TUN-адаптера и порт прокси во вкладке «Подключение».".into()),
        30 => Err("Windows не применила ожидаемую политику брандмауэра. Проверь фактический статус защиты в панели.".into()),
        31 => Err("Windows не подтвердила состояние фильтров WFP. Проверь фактический статус защиты в панели.".into()),
        _ => Err(format!("Windows не завершила изменение правил. Код {code}.")),
    }
}

fn wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failure_codes_follow_stage_marker() {
        assert_eq!(failure_code(b"TG_STAGE:TUN\r\nmessage"), 23);
        assert_eq!(failure_code(b"  TG_STAGE:POLICY  \n"), 30);
        assert_eq!(failure_code(b"no marker"), 27);
    }

    #[test]
    fn progress_file_watch_forwards_new_stages_and_cleans_up() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(PROGRESS_FILE);
        fs::write(&path, br#"{"action":"enable","stage":"tun","at":1}"#).unwrap();
        let file = ProgressFile {
            path: Some(path.clone()),
            action: Action::Enable,
            since: 0,
        };
        file.remove();
        assert!(!path.exists());
        let seen = Mutex::new(Vec::new());
        let report = |progress: Progress| seen.lock().unwrap().push(progress.stage);
        let value = file.watch(&report, || {
            for stage in ["settings", "tun", "tun", "apply"] {
                let json = format!(
                    r#"{{"action":"enable","stage":"{stage}","at":{}}}"#,
                    if stage == "apply" {
                        3
                    } else if stage == "tun" {
                        2
                    } else {
                        1
                    }
                );
                fs::write(&path, json).unwrap();
                std::thread::sleep(PROGRESS_POLL * 2);
            }
            // other action / garbage are ignored
            fs::write(&path, br#"{"action":"disable","stage":"restore","at":9}"#).unwrap();
            std::thread::sleep(PROGRESS_POLL * 2);
            7
        });
        assert_eq!(value, 7);
        assert_eq!(
            *seen.lock().unwrap(),
            vec![
                ProgressStage::Settings,
                ProgressStage::Tun,
                ProgressStage::Apply
            ]
        );
        drop(file);
        assert!(!path.exists());
    }

    #[test]
    fn watch_without_path_just_waits() {
        let file = ProgressFile {
            path: None,
            action: Action::Disable,
            since: 0,
        };
        let report = |_: Progress| panic!("no events expected");
        assert_eq!(file.watch(&report, || 5), 5);
    }
}
