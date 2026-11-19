use crate::{
    settings::{lock_config, storage},
    status::{Action, Status},
    Result,
};
use std::{
    env,
    ffi::OsStr,
    io,
    os::windows::{ffi::OsStrExt, process::CommandExt},
    path::PathBuf,
    process::{Command, Output},
    sync::Mutex,
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, HWND},
    System::Threading::{GetExitCodeProcess, WaitForSingleObject, CREATE_NO_WINDOW, INFINITE},
    UI::{
        Shell::{ShellExecuteExW, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW},
        WindowsAndMessaging::SW_SHOWNORMAL,
    },
};

static CHANGE: Mutex<()> = Mutex::new(());
const SCRIPT: &str = include_str!("firewall.ps1");

fn powershell(action: &str) -> Result<Output> {
    let executable = PathBuf::from(env::var_os("SystemRoot").ok_or("SystemRoot не найден.")?)
        .join("System32/WindowsPowerShell/v1.0/powershell.exe");
    let command = format!("& {{\n{SCRIPT}\n}} -Action $env:TUNNEL_GUARD_ACTION -SettingsPath $env:TUNNEL_GUARD_SETTINGS");
    Command::new(executable)
        .args(["-NoProfile", "-NonInteractive", "-Command", &command])
        .env("TUNNEL_GUARD_ACTION", action)
        .env("TUNNEL_GUARD_SETTINGS", storage()?.join("settings.json"))
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|error| error.to_string())
}

pub fn status() -> Result<Status> {
    let output = powershell("Status")?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().into());
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|_| "Не удалось прочитать фактический статус Windows.".into())
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

pub fn worker(args: &[String]) -> i32 {
    let [action] = args else { return 20 };
    if !matches!(action.as_str(), "Enable" | "Disable" | "CleanLegacy") {
        return 20;
    }
    let Ok(_config_lock) = lock_config() else {
        return 28;
    };
    let Ok(output) = powershell(action) else {
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
        _ => 27,
    }
}

pub fn elevate(action: Action, parent: isize) -> Result<()> {
    let _operation = CHANGE
        .try_lock()
        .map_err(|_| "Другая операция уже выполняется.")?;
    if matches!(action, Action::Enable) {
        let check = powershell("Preflight")?;
        if !check.status.success() {
            return worker_result(failure_code(&check.stderr));
        }
    }
    let executable = wide(
        env::current_exe()
            .map_err(|error| error.to_string())?
            .as_os_str(),
    );
    let verb = wide(OsStr::new("runas"));
    let parameters = wide(OsStr::new(&format!("--firewall-worker {}", action.name())));
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
        let wait = WaitForSingleObject(request.hProcess, INFINITE);
        let mut code = 0;
        let read = GetExitCodeProcess(request.hProcess, &mut code);
        CloseHandle(request.hProcess);
        if wait != 0 || read == 0 {
            return Err("Не удалось получить результат изменения правил.".into());
        }
        worker_result(code)
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
        _ => Err(format!("Windows не завершила изменение правил. Код {code}.")),
    }
}

fn wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}
