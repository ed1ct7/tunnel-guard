use serde::{Deserialize, Serialize};
use serde_yaml::{Mapping, Value};
use std::{
    env, fs,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
};
use tauri::{
    image::Image,
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Emitter, Manager, WindowEvent,
};
use tauri_plugin_dialog::DialogExt;

#[cfg(windows)]
#[path = "windows/mod.rs"]
mod windows;

pub(crate) type Result<T> = std::result::Result<T, String>;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Settings {
    pub client_path: String,
    pub adapter: String,
    pub proxy_port: u16,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            client_path: String::new(),
            adapter: "Mihomo".into(),
            proxy_port: 10808,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Status {
    state: String,
    adapter_up: bool,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Action {
    Enable,
    Disable,
    CleanLegacy,
}

impl Action {
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Enable => "Enable",
            Self::Disable => "Disable",
            Self::CleanLegacy => "CleanLegacy",
        }
    }
}

pub(super) fn storage() -> Result<PathBuf> {
    let base = if cfg!(windows) {
        env::var_os("LOCALAPPDATA").map(PathBuf::from)
    } else {
        env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
    }
    .ok_or("Не удалось определить папку настроек.")?;
    let dir = base.join("TunnelGuard");
    fs::create_dir_all(&dir).map_err(|error| error.to_string())?;
    Ok(dir)
}

pub(crate) fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or("Не найдена папка файла.")?;
    let mut file = tempfile::NamedTempFile::new_in(parent).map_err(|error| error.to_string())?;
    file.write_all(data).map_err(|error| error.to_string())?;
    file.persist(path).map_err(|error| error.to_string())?;
    Ok(())
}

pub(super) fn lock_config() -> Result<fs::File> {
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(storage()?.join("configuration.lock"))
        .map_err(|error| error.to_string())?;
    lock.try_lock().map_err(|_| {
        "Tunnel Guard уже меняет настройки. Повтори после завершения операции.".to_string()
    })?;
    Ok(lock)
}

#[tauri::command]
pub(crate) fn load_settings() -> Result<Settings> {
    let path = storage()?.join("settings.json");
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|_| "Файл настроек повреждён.".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Settings::default()),
        Err(error) => Err(error.to_string()),
    }
}

fn client_path(settings: &Settings) -> Result<PathBuf> {
    let path = PathBuf::from(&settings.client_path);
    let expected = if cfg!(windows) {
        "v2rayN.exe"
    } else {
        "v2rayN"
    };
    if !path.is_absolute()
        || !path.is_file()
        || !path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.eq_ignore_ascii_case(expected))
    {
        return Err(format!("Выбери существующий исполняемый файл {expected}."));
    }
    Ok(path)
}

#[tauri::command]
async fn save_settings(settings: Settings, original: Settings) -> Result<()> {
    tauri::async_runtime::spawn_blocking(move || {
        edit_settings(Some(original), |_| settings).map(|_| ())
    })
    .await
    .map_err(|error| error.to_string())?
}

pub(crate) fn edit_settings(
    expected: Option<Settings>,
    update: impl FnOnce(Settings) -> Settings,
) -> Result<Settings> {
    let _guard = lock_config()?;
    let current = load_settings()?;
    if expected.is_some_and(|value| value != current) {
        return Err("Подключение изменилось в другой программе. Перечитай настройки.".into());
    }
    let settings = update(current.clone());
    if settings == current {
        return Ok(current);
    }
    #[cfg(windows)]
    if !matches!(windows::status()?.state.as_str(), "Off" | "LegacyInactive") {
        return Err("Сначала выключи защиту.".into());
    }
    client_path(&settings)?;
    if settings.adapter.trim().is_empty()
        || settings.adapter.contains(['*', '?', '[', ']'])
        || settings.adapter.chars().any(char::is_control)
        || settings.proxy_port == 0
        || settings.proxy_port > 65529
    {
        return Err("Проверь имя TUN-адаптера и порт прокси.".into());
    }
    let bytes = serde_json::to_vec_pretty(&settings).map_err(|error| error.to_string())?;
    atomic_write(&storage()?.join("settings.json"), &bytes)?;
    Ok(settings)
}

#[tauri::command]
async fn pick_exe(app: AppHandle) -> Result<Option<String>> {
    let file = tauri::async_runtime::spawn_blocking(move || {
        let dialog = app.dialog().file();
        let dialog = if cfg!(windows) {
            dialog.add_filter("Программы", &["exe"])
        } else {
            dialog
        };
        dialog.blocking_pick_file()
    })
    .await
    .map_err(|error| error.to_string())?;
    file.map(|path| {
        path.into_path()
            .map(|path| path.to_string_lossy().into_owned())
            .map_err(|error| error.to_string())
    })
    .transpose()
}

#[tauri::command]
pub(crate) fn open_client() -> Result<()> {
    let executable = client_path(&load_settings()?)?;
    Command::new(&executable)
        .current_dir(executable.parent().ok_or("Папка v2rayN не найдена.")?)
        .spawn()
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn mixin(settings: &Settings) -> Result<(PathBuf, Vec<u8>, Mapping)> {
    let client = client_path(settings)?;
    let path = client
        .parent()
        .ok_or("Папка v2rayN не найдена.")?
        .join("guiConfigs/Mixin.yaml");
    let raw = fs::read(&path).map_err(|_| "В выбранной папке нет guiConfigs/Mixin.yaml.")?;
    let content = std::str::from_utf8(&raw).map_err(|_| "Mixin.yaml должен быть в UTF-8.")?;
    let parsed: Value = serde_yaml::from_str(content.trim_start_matches('\u{feff}'))
        .map_err(|_| "Не удалось прочитать структуру Mixin.yaml.")?;
    match parsed {
        Value::Mapping(root) => Ok((path, raw, root)),
        Value::Null => Ok((path, raw, Mapping::new())),
        _ => Err("Корень Mixin.yaml должен содержать таблицу.".into()),
    }
}

fn read_rules(root: &Mapping) -> Result<Vec<String>> {
    let Some(value) = root.get("prepend-rules") else {
        return Ok(Vec::new());
    };
    value
        .as_sequence()
        .ok_or("prepend-rules должен быть списком.")?
        .iter()
        .map(|rule| {
            rule.as_str()
                .map(str::to_owned)
                .ok_or("В prepend-rules допустимы строки.".into())
        })
        .collect()
}

#[tauri::command]
pub(crate) fn load_rules() -> Result<Vec<String>> {
    read_rules(&mixin(&load_settings()?)?.2)
}

pub(crate) const DIRECT_DEFAULT: &str = "MATCH,DIRECT";

fn specific_rule(rule: &str) -> Option<(&str, &str, &str)> {
    if rule.chars().any(char::is_control) {
        return None;
    }
    let mut parts = rule.split(',');
    let (Some(kind), Some(value), Some(target), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    if !matches!(kind, "DOMAIN-SUFFIX" | "PROCESS-NAME" | "PROCESS-PATH")
        || target.trim().is_empty()
    {
        return None;
    }
    Some((kind, value, target))
}

fn valid_rule_value(kind: &str, value: &str) -> bool {
    match kind {
        "DOMAIN-SUFFIX" => {
            value.contains('.')
                && !value.contains('*')
                && matches!(url::Host::parse(value), Ok(url::Host::Domain(_)))
        }
        "PROCESS-NAME" => {
            value.to_ascii_lowercase().ends_with(".exe")
                && !value.contains(['/', '\\', ':', '*', '?', '<', '>', '"', '|'])
        }
        "PROCESS-PATH" => {
            value.to_ascii_lowercase().ends_with(".exe")
                && Path::new(value).is_absolute()
                && Path::new(value).is_file()
        }
        _ => false,
    }
}

pub(crate) fn upsert_rule(mut rules: Vec<String>, rule: String) -> Vec<String> {
    let Some((kind, value, _)) = specific_rule(&rule) else {
        rules.push(rule);
        return rules;
    };
    if let Some(existing) = rules.iter().position(|entry| {
        matches!(specific_rule(entry),
        Some((other_kind, other_value, _)) if kind == other_kind && value.eq_ignore_ascii_case(other_value))
    }) {
        rules[existing] = rule;
    } else {
        let position = rules
            .iter()
            .position(|entry| entry == DIRECT_DEFAULT)
            .unwrap_or(rules.len());
        rules.insert(position, rule);
    }
    rules
}

#[tauri::command]
async fn save_rules(rules: Vec<String>, original: Vec<String>, settings: Settings) -> Result<()> {
    tauri::async_runtime::spawn_blocking(move || {
        edit_rules(Some(settings), Some(original), |_| rules).map(|_| ())
    })
    .await
    .map_err(|error| error.to_string())?
}

pub(crate) fn edit_rules(
    expected_settings: Option<Settings>,
    expected_rules: Option<Vec<String>>,
    update: impl FnOnce(Vec<String>) -> Vec<String>,
) -> Result<Vec<String>> {
    let _guard = lock_config()?;
    let settings = load_settings()?;
    if expected_settings.is_some_and(|expected| expected != settings) {
        return Err("Подключение изменилось в другой программе. Перечитай правила.".into());
    }
    let (path, raw, mut root) = mixin(&settings)?;
    let current = read_rules(&root)?;
    if expected_rules.is_some_and(|expected| expected != current) {
        return Err("Список изменился в другой программе. Обнови правила и повтори.".into());
    }
    let rules = update(current.clone());
    if rules == current {
        return Ok(current);
    }
    let reverse = rules.last().is_some_and(|rule| rule == DIRECT_DEFAULT);
    if rules.iter().filter(|rule| *rule == DIRECT_DEFAULT).count() != usize::from(reverse) {
        return Err("Маршрут по умолчанию должен быть единственным и стоять последним.".into());
    }
    if reverse
        && rules
            .iter()
            .any(|rule| rule.starts_with("MATCH,") && rule != DIRECT_DEFAULT)
    {
        return Err("В пользовательском списке уже установлен другой маршрут по умолчанию.".into());
    }
    let vpn_routes: Vec<_> = rules
        .iter()
        .filter_map(|rule| specific_rule(rule))
        .filter(|(_, _, target)| *target != "DIRECT")
        .map(|(_, _, target)| target)
        .collect();
    if reverse && vpn_routes.is_empty() {
        return Err("Сначала добавь хотя бы один сайт или программу с маршрутом через VPN.".into());
    }
    let mut check_targets = if reverse && !current.contains(&DIRECT_DEFAULT.to_owned()) {
        vpn_routes
    } else {
        Vec::new()
    };
    for rule in rules
        .iter()
        .filter(|rule| *rule != DIRECT_DEFAULT && !current.contains(rule))
    {
        let Some((kind, value, target)) = specific_rule(rule) else {
            return Err("Проверь формат правила маршрутизации.".into());
        };
        if !valid_rule_value(kind, value) {
            return Err("Укажи домен без URL, имя процесса или путь к существующему .exe.".into());
        }
        if target != "DIRECT" {
            check_targets.push(target);
        }
    }
    if !check_targets.is_empty() {
        let available = read_vpn_targets()?;
        if check_targets
            .iter()
            .any(|target| !available.iter().any(|name| name == *target))
        {
            return Err("Выбранный маршрут отсутствует в запущенном Mihomo.".into());
        }
    }
    let config = path.with_file_name("guiNConfig.json");
    let config: serde_json::Value =
        serde_json::from_slice(&fs::read(config).map_err(|_| "Не найдены настройки v2rayN.")?)
            .map_err(|_| "Не удалось прочитать настройки v2rayN.")?;
    let config = config.as_object().ok_or("Некорректные настройки v2rayN.")?;
    let enabled = config
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("ClashUIItem"))
        .and_then(|(_, value)| value.as_object())
        .is_some_and(|entry| {
            entry.iter().any(|(key, value)| {
                key.eq_ignore_ascii_case("EnableMixinContent") && value.as_bool() == Some(true)
            })
        });
    if !enabled {
        return Err("Включи Enable Mixin Content в настройках Mihomo в v2rayN.".into());
    }
    root.insert(
        Value::String("prepend-rules".into()),
        Value::Sequence(rules.iter().cloned().map(Value::String).collect()),
    );
    let next = serde_yaml::to_string(&root).map_err(|_| "Не удалось записать правила.")?;
    if fs::read(&path).map_err(|error| error.to_string())? != raw {
        return Err("Mixin.yaml изменился в другой программе. Обнови список и повтори.".into());
    }
    atomic_write(&path.with_file_name("Mixin.yaml.tunnelguard.bak"), &raw)?;
    atomic_write(&path, next.as_bytes())?;
    Ok(rules)
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ConfigSnapshot {
    pub settings: Settings,
    pub rules: Option<Vec<String>>,
}

#[tauri::command]
pub(crate) fn config_snapshot() -> Result<ConfigSnapshot> {
    let settings = load_settings()?;
    let rules = mixin(&settings)
        .and_then(|(_, _, root)| read_rules(&root))
        .ok();
    Ok(ConfigSnapshot { settings, rules })
}

#[tauri::command]
fn recover_routing_draft() -> Result<Option<Vec<String>>> {
    #[derive(Deserialize)]
    struct Draft {
        original: ConfigSnapshot,
        rules: Vec<String>,
    }
    let path = storage()?.join("routing-draft.json");
    let input = match fs::read(&path) {
        Ok(input) => input,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };
    let draft: Draft = serde_json::from_slice(&input).map_err(|error| error.to_string())?;
    if config_snapshot()? != draft.original {
        return Err(
            "Сохранённые правила изменились. Черновик оставлен в routing-draft.json.".into(),
        );
    }
    fs::rename(&path, path.with_extension("recovered.json")).map_err(|error| error.to_string())?;
    Ok(Some(draft.rules))
}

pub(crate) fn read_status() -> Result<Status> {
    #[cfg(windows)]
    return windows::status();
    #[cfg(not(windows))]
    Ok(Status {
        state: "Unsupported".into(),
        adapter_up: false,
    })
}

pub(crate) fn active_rules() -> Result<serde_json::Value> {
    #[cfg(windows)]
    return windows::active_rules();
    #[cfg(not(windows))]
    Err("Чтение правил активного Mihomo пока реализовано для Windows.".into())
}

pub(crate) fn read_vpn_targets() -> Result<Vec<String>> {
    #[cfg(windows)]
    return windows::targets();
    #[cfg(not(windows))]
    Err("Чтение маршрутов Mihomo пока реализовано для Windows.".into())
}

#[tauri::command]
async fn vpn_targets() -> Result<Vec<String>> {
    tauri::async_runtime::spawn_blocking(read_vpn_targets)
        .await
        .map_err(|error| error.to_string())?
}

pub(crate) fn apply_protection_headless(action: Action) -> Result<Status> {
    #[cfg(windows)]
    {
        windows::worker_result(windows::worker(&[action.name().to_owned()]) as u32)?;
        read_status()
    }
    #[cfg(not(windows))]
    {
        let _ = action;
        Err("Системный kill switch для этой ОС пока не реализован.".into())
    }
}

fn update_tray(app: &AppHandle, status: &Status) {
    let (icon, label) = match (status.state.as_str(), status.adapter_up) {
        ("On", true) => (
            include_bytes!("../icons/on.png").as_slice(),
            "Защита включена",
        ),
        ("On", false) => (
            include_bytes!("../icons/waiting.png").as_slice(),
            "Туннель отключён",
        ),
        ("Partial" | "LegacyActive", _) => (
            include_bytes!("../icons/waiting.png").as_slice(),
            "Проверь правила",
        ),
        ("Off" | "LegacyInactive", _) => (
            include_bytes!("../icons/off.png").as_slice(),
            "Защита выключена",
        ),
        _ => (
            include_bytes!("../icons/off.png").as_slice(),
            "Статус недоступен",
        ),
    };
    if let Some(tray) = app.tray_by_id("guard") {
        if let Ok(icon) = Image::from_bytes(icon) {
            let _ = tray.set_icon(Some(icon));
        }
        let _ = tray.set_tooltip(Some(format!("Tunnel Guard · {label}")));
    }
}

#[cfg(windows)]
fn monitor(app: AppHandle) {
    std::thread::spawn(move || {
        let mut last = None;
        loop {
            let status = windows::status().unwrap_or(Status {
                state: "Unknown".into(),
                adapter_up: false,
            });
            if last.as_ref() != Some(&status) {
                last = Some(status.clone());
                let target = app.clone();
                if app
                    .run_on_main_thread(move || {
                        update_tray(&target, &status);
                        let _ = target.emit("guard-state", status);
                    })
                    .is_err()
                {
                    return;
                }
            }
            std::thread::sleep(std::time::Duration::from_secs(8));
        }
    });
}

fn monitor_config(app: AppHandle) {
    std::thread::spawn(move || {
        let mut last = None;
        loop {
            if let Ok(snapshot) = config_snapshot() {
                if last.as_ref() != Some(&snapshot) {
                    last = Some(snapshot.clone());
                    if app.emit("guard-config", snapshot).is_err() {
                        return;
                    }
                }
            }
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
    });
}

#[tauri::command]
async fn guard_status(app: AppHandle) -> Result<Status> {
    #[cfg(windows)]
    let snapshot = tauri::async_runtime::spawn_blocking(windows::status)
        .await
        .map_err(|error| error.to_string())?;
    #[cfg(not(windows))]
    let snapshot = Ok(Status {
        state: "Unsupported".into(),
        adapter_up: false,
    });
    if let Ok(status) = &snapshot {
        update_tray(&app, status);
    }
    snapshot
}

#[tauri::command]
async fn change_protection(app: AppHandle, action: Action) -> Result<()> {
    #[cfg(windows)]
    {
        let window = app
            .get_webview_window("main")
            .ok_or("Окно Tunnel Guard недоступно.")?;
        let parent = window.hwnd().map_err(|error| error.to_string())?.0 as isize;
        tauri::async_runtime::spawn_blocking(move || windows::elevate(action, parent))
            .await
            .map_err(|error| error.to_string())?
    }
    #[cfg(not(windows))]
    {
        let _ = (app, action);
        Err("Системный kill switch для этой ОС пока не реализован.".into())
    }
}

pub fn worker_exit_code() -> Option<i32> {
    #[cfg(windows)]
    {
        let args: Vec<_> = env::args().collect();
        if args.get(1).map(String::as_str) == Some("--firewall-worker") {
            return Some(windows::worker(&args[2..]));
        }
    }
    None
}

fn reveal(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _, _| reveal(app)))
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            load_settings,
            save_settings,
            config_snapshot,
            recover_routing_draft,
            crate::process_groups::load_process_groups,
            crate::process_groups::save_process_groups,
            crate::process_groups::run_process_group,
            pick_exe,
            open_client,
            load_rules,
            save_rules,
            vpn_targets,
            guard_status,
            change_protection
        ])
        .setup(|app| {
            let open = MenuItem::with_id(app, "open", "Открыть Tunnel Guard", true, None::<&str>)?;
            let exit = MenuItem::with_id(app, "exit", "Закрыть панель", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&open, &exit])?;
            TrayIconBuilder::with_id("guard")
                .icon(Image::from_bytes(include_bytes!("../icons/off.png"))?)
                .tooltip("Tunnel Guard · проверяем состояние")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "open" => reveal(app),
                    "exit" => app.exit(0),
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        reveal(tray.app_handle());
                    }
                })
                .build(app)?;
            #[cfg(windows)]
            monitor(app.handle().clone());
            monitor_config(app.handle().clone());
            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .run(tauri::generate_context!())
        .expect("Tunnel Guard startup failed");
}
