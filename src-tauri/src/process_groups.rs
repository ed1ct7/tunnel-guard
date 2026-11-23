use crate::{
    settings::{atomic_write, lock_config, storage, storage_path},
    Result,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, HashSet},
    fs,
    path::Path,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum NetworkState {
    Off,
    Blocked,
    Partial,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Groups {
    pub groups: Vec<Group>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Group {
    id: String,
    title: String,
    #[serde(default)]
    selectors: Vec<Selector>,
    #[serde(default)]
    includes: Vec<String>,
    // Read settings written before network blocking became a separate action.
    #[serde(
        default,
        rename = "block_network_on_stop",
        deserialize_with = "discard_legacy_stop_setting",
        skip_serializing
    )]
    _legacy_stop_setting: (),
}

fn discard_legacy_stop_setting<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<(), D::Error> {
    bool::deserialize(deserializer).map(|_| ())
}

impl Group {
    fn network_paths(&self) -> Vec<String> {
        let mut seen = HashSet::new();
        self.selectors
            .iter()
            .filter_map(|selector| match selector {
                Selector::Path { value } if seen.insert(value.to_lowercase()) => {
                    Some(value.clone())
                }
                _ => None,
            })
            .collect()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Selector {
    Name { value: String },
    Path { value: String },
    PackageFamily { value: String },
    Argument { image: String, value: String },
    Service { value: String },
}

fn valid_name(value: &str) -> bool {
    value.to_ascii_lowercase().ends_with(".exe")
        && !value.contains(['\\', '/', ':', '*', '?', '"', '<', '>', '|'])
        && !value.chars().any(char::is_control)
}

fn valid_atom(value: &str, allowed_punctuation: &[u8]) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || allowed_punctuation.contains(&byte))
}

impl Selector {
    fn valid(&self) -> bool {
        match self {
            Self::Name { value } => valid_name(value),
            Self::Path { value } => {
                Path::new(value).is_absolute()
                    && Path::new(value)
                        .file_name()
                        .and_then(|part| part.to_str())
                        .is_some_and(valid_name)
            }
            Self::PackageFamily { value } => value.contains('_') && valid_atom(value, b"._-"),
            Self::Argument { image, value } => {
                valid_name(image)
                    && !value.trim().is_empty()
                    && !value.chars().any(char::is_control)
            }
            Self::Service { value } => valid_atom(value, b"._-$"),
        }
    }
}

impl Groups {
    fn group(&self, id: &str) -> Result<&Group> {
        self.groups
            .iter()
            .find(|group| group.id == id)
            .ok_or_else(|| format!("Группа «{id}» не найдена."))
    }

    fn resolve(&self, id: &str) -> Result<Vec<Selector>> {
        fn visit(
            groups: &Groups,
            id: &str,
            stack: &mut HashSet<String>,
            visited: &mut HashSet<String>,
            selectors: &mut Vec<Selector>,
        ) -> Result<()> {
            if visited.contains(id) {
                return Ok(());
            }
            if !stack.insert(id.to_owned()) {
                return Err(format!("Группа «{id}» включена сама в себя."));
            }
            let group = groups.group(id)?;
            selectors.extend(group.selectors.iter().cloned());
            for child in &group.includes {
                visit(groups, child, stack, visited, selectors)?;
            }
            stack.remove(id);
            visited.insert(id.to_owned());
            Ok(())
        }
        let mut selectors = Vec::new();
        visit(
            self,
            id,
            &mut HashSet::new(),
            &mut HashSet::new(),
            &mut selectors,
        )?;
        let mut seen = HashSet::new();
        selectors.retain(|selector| seen.insert(selector.clone()));
        if selectors.is_empty() {
            return Err(format!("В группе «{id}» нет условий поиска."));
        }
        Ok(selectors)
    }

    fn validate(&self) -> Result<()> {
        let mut ids = HashSet::new();
        for group in &self.groups {
            if !valid_atom(&group.id, b"_-")
                || group.title.trim().is_empty()
                || !ids.insert(&group.id)
            {
                return Err("У каждой группы должны быть уникальный ID и название.".into());
            }
            if group.selectors.iter().any(|selector| !selector.valid()) {
                return Err(format!(
                    "Проверь условия поиска в группе «{}».",
                    group.title
                ));
            }
        }
        for group in &self.groups {
            self.resolve(&group.id)?;
        }
        Ok(())
    }
}

#[tauri::command]
pub(crate) fn load_process_groups() -> Result<Groups> {
    let path = storage_path()?.join("process-groups.json");
    match fs::read(path) {
        Ok(raw) => {
            let raw = raw.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(&raw);
            let config: Groups = serde_json::from_slice(raw)
                .map_err(|error| format!("process-groups.json: {error}"))?;
            config.validate()?;
            Ok(config)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Groups { groups: vec![] }),
        Err(error) => Err(error.to_string()),
    }
}

#[tauri::command]
pub(crate) fn save_process_groups(config: Groups, original: Groups) -> Result<()> {
    let _lock = lock_config()?;
    if load_process_groups()? != original {
        return Err("Группы уже изменились в другой программе. Перечитай список.".into());
    }
    config.validate()?;
    #[cfg(windows)]
    for group in &original.groups {
        if config.group(&group.id).ok() != Some(group)
            && crate::windows::group_network::status(&group.id)? != NetworkState::Off
        {
            return Err(format!(
                "Сначала верни доступ к сети группе «{}».",
                group.title
            ));
        }
    }
    let bytes = serde_json::to_vec_pretty(&config).map_err(|error| error.to_string())?;
    atomic_write(&storage()?.join("process-groups.json"), &bytes)
}

fn current_config(original: Option<&Groups>) -> Result<Groups> {
    let current = load_process_groups()?;
    if original.is_some_and(|previous| previous != &current) {
        return Err("Группы изменились. Перечитай список и повтори действие.".into());
    }
    Ok(current)
}

pub(crate) fn execute(id: &str, stop: bool) -> Result<Value> {
    execute_with_config(id, stop, None)
}

fn execute_with_config(id: &str, stop: bool, original: Option<&Groups>) -> Result<Value> {
    let selectors = current_config(original)?.resolve(id)?;
    #[cfg(windows)]
    return run_windows(&selectors, stop);
    #[cfg(not(windows))]
    {
        let _ = (selectors, stop);
        Err("Группы процессов пока поддерживаются только на Windows.".into())
    }
}

#[tauri::command]
pub(crate) async fn run_process_group(id: String, stop: bool, original: Groups) -> Result<Value> {
    tauri::async_runtime::spawn_blocking(move || execute_with_config(&id, stop, Some(&original)))
        .await
        .map_err(|error| error.to_string())?
}

fn window_parent(window: tauri::WebviewWindow) -> Result<Option<isize>> {
    #[cfg(windows)]
    return Ok(Some(
        window.hwnd().map_err(|error| error.to_string())?.0 as isize,
    ));
    #[cfg(not(windows))]
    {
        let _ = window;
        Ok(None)
    }
}

#[cfg(windows)]
fn check_network_paths(paths: &[String]) -> Result<()> {
    use std::io::ErrorKind;

    if paths.is_empty() {
        return Err("Добавь в группу хотя бы один полный путь к .exe.".into());
    }
    for path in paths {
        match fs::metadata(path) {
            Ok(metadata) if metadata.is_file() => continue,
            Err(error) if error.kind() == ErrorKind::PermissionDenied => continue,
            Err(error) if error.kind() != ErrorKind::NotFound => {
                return Err(format!("Не удалось проверить путь «{path}». {error}"));
            }
            _ => return Err(format!("Файл «{path}» не найден. Обнови путь в группе.")),
        }
    }
    Ok(())
}

#[cfg(windows)]
fn fingerprint(paths: &[String]) -> Result<String> {
    use sha2::{Digest, Sha256};
    let bytes = serde_json::to_vec(paths).map_err(|error| error.to_string())?;
    Ok(Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

#[cfg(windows)]
fn change_network(
    id: &str,
    blocked: bool,
    expected: Option<&str>,
    parent: Option<isize>,
) -> Result<()> {
    use crate::windows::{elevate_network_worker, group_network, is_admin};
    if !valid_atom(id, b"_-") {
        return Err("Некорректный ID группы.".into());
    }
    if !is_admin() {
        let parent = parent.ok_or("Для изменения доступа к сети нужны права администратора.")?;
        elevate_network_worker(parent, id, blocked, expected)?;
        let target = if blocked {
            NetworkState::Blocked
        } else {
            NetworkState::Off
        };
        if group_network::status(id)? != target {
            return Err("Tunnel Guard не смог подтвердить состояние сетевой блокировки.".into());
        }
        return Ok(());
    }
    let _lock = lock_config()?;
    if blocked {
        let config = load_process_groups()?;
        let paths = config.group(id)?.network_paths();
        if let Some(expected) = expected {
            if expected != fingerprint(&paths)? {
                return Err("Пути группы изменились. Перечитай список и повтори действие.".into());
            }
        }
        check_network_paths(&paths)?;
        group_network::block(id, &paths)
    } else {
        group_network::unblock(id)
    }
}

#[cfg(windows)]
pub(crate) fn group_network_worker(args: &[String]) -> i32 {
    let result = match args {
        [operation, id, expected] if operation == "block" => {
            change_network(id, true, Some(expected), None)
        }
        [operation, id] if operation == "unblock" => change_network(id, false, None, None),
        _ => return 20,
    };
    match result {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("{error}");
            36
        }
    }
}

pub(crate) fn network_access(id: &str, blocked: Option<bool>) -> Result<NetworkState> {
    if !valid_atom(id, b"_-") {
        return Err("Некорректный ID группы.".into());
    }
    #[cfg(windows)]
    {
        if let Some(blocked) = blocked {
            change_network(id, blocked, None, None)?;
        }
        crate::windows::group_network::status(id)
    }
    #[cfg(not(windows))]
    {
        let _ = blocked;
        Err("Блокировка сети для групп поддерживается только на Windows.".into())
    }
}

#[tauri::command]
pub(crate) async fn process_network_states() -> Result<BTreeMap<String, NetworkState>> {
    tauri::async_runtime::spawn_blocking(|| {
        load_process_groups()?
            .groups
            .into_iter()
            .map(|group| {
                let state = network_access(&group.id, None)?;
                Ok((group.id, state))
            })
            .collect()
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
pub(crate) async fn set_process_network(
    window: tauri::WebviewWindow,
    id: String,
    blocked: bool,
    original: Groups,
) -> Result<()> {
    let parent = window_parent(window)?;
    #[cfg(windows)]
    return tauri::async_runtime::spawn_blocking(move || {
        if blocked {
            let config = current_config(Some(&original))?;
            let paths = config.group(&id)?.network_paths();
            check_network_paths(&paths)?;
            change_network(&id, true, Some(&fingerprint(&paths)?), parent)
        } else {
            change_network(&id, false, None, parent)
        }
    })
    .await
    .map_err(|error| error.to_string())?;
    #[cfg(not(windows))]
    {
        let _ = (id, blocked, original, parent);
        Err("Блокировка сети для групп поддерживается только на Windows.".into())
    }
}

#[cfg(windows)]
fn run_windows(selectors: &[Selector], stop: bool) -> Result<Value> {
    use std::{
        io::Write,
        os::windows::process::CommandExt,
        process::{Command, Stdio},
    };
    use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;
    let executable = crate::windows::system_directory()?
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe");
    let script = include_str!("windows/process-groups.ps1");
    let request = serde_json::to_vec(&serde_json::json!({ "selectors": selectors, "stop": stop }))
        .map_err(|error| error.to_string())?;
    let mut child = Command::new(executable)
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| error.to_string())?;
    child
        .stdin
        .take()
        .ok_or("Не удалось запустить поиск процессов.")?
        .write_all(&request)
        .map_err(|error| error.to_string())?;
    let output = child
        .wait_with_output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().into());
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|_| "Не удалось прочитать результат поиска процессов.".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(value: &str) -> Selector {
        Selector::Name {
            value: value.into(),
        }
    }

    fn group(id: &str, selectors: Vec<Selector>, includes: &[&str]) -> Group {
        Group {
            id: id.into(),
            title: format!("Title {id}"),
            selectors,
            includes: includes.iter().map(|item| (*item).to_owned()).collect(),
            _legacy_stop_setting: (),
        }
    }

    #[test]
    fn names_must_be_bare_exe() {
        assert!(valid_name("app.exe"));
        assert!(valid_name("APP.EXE"));
        for bad in [
            "app", "a/b.exe", r"a\b.exe", "c:a.exe", "a*.exe", "a?.exe", "a|b.exe", "a\n.exe", "",
        ] {
            assert!(!valid_name(bad), "{bad:?}");
        }
    }

    #[test]
    fn atoms_respect_allowed_punctuation() {
        assert!(valid_atom("my-group_1", b"_-"));
        assert!(!valid_atom("", b"_-"));
        assert!(!valid_atom("a b", b"_-"));
        assert!(!valid_atom("a.b", b"_-"));
        assert!(valid_atom("a.b", b"._-"));
    }

    #[test]
    fn selector_validation() {
        assert!(name("a.exe").valid());
        assert!(!name("a").valid());
        let path = |value: &str| Selector::Path {
            value: value.into(),
        };
        assert!(!path("a.exe").valid());
        let dir = tempfile::tempdir().unwrap();
        assert!(path(&dir.path().join("a.exe").to_string_lossy()).valid());
        assert!(!path(&dir.path().join("a.txt").to_string_lossy()).valid());
        let family = |value: &str| Selector::PackageFamily {
            value: value.into(),
        };
        assert!(family("Vendor.App_abc123").valid());
        assert!(!family("NoUnderscore").valid());
        assert!(!family("Bad Name_x").valid());
        let service = |value: &str| Selector::Service {
            value: value.into(),
        };
        assert!(service("Spooler").valid());
        assert!(service("svc$1").valid());
        assert!(!service("bad name").valid());
        let argument = |image: &str, value: &str| Selector::Argument {
            image: image.into(),
            value: value.into(),
        };
        assert!(argument("node.exe", "--port=1").valid());
        assert!(!argument("node", "--port=1").valid());
        assert!(!argument("node.exe", "  ").valid());
        assert!(!argument("node.exe", "a\nb").valid());
    }

    #[test]
    fn network_targets_only_explicit_paths_in_the_group() {
        let parent = group("parent", vec![name("app.exe")], &["child"]);
        let child = group(
            "child",
            vec![Selector::Path {
                value: std::env::temp_dir()
                    .join("app.exe")
                    .to_string_lossy()
                    .into_owned(),
            }],
            &[],
        );
        let config = Groups {
            groups: vec![parent, child],
        };
        assert!(config.validate().is_ok());
        assert!(config.groups[0].network_paths().is_empty());
        assert_eq!(config.groups[1].network_paths().len(), 1);
    }

    #[test]
    fn groups_validation() {
        let ok = Groups {
            groups: vec![group("a", vec![name("a.exe")], &[])],
        };
        assert!(ok.validate().is_ok());
        let empty = Groups { groups: vec![] };
        assert!(empty.validate().is_ok());

        let unique = "У каждой группы должны быть уникальный ID и название.";
        let dup = Groups {
            groups: vec![
                group("a", vec![name("a.exe")], &[]),
                group("a", vec![name("b.exe")], &[]),
            ],
        };
        assert_eq!(dup.validate().unwrap_err(), unique);
        let bad_id = Groups {
            groups: vec![group("a b", vec![name("a.exe")], &[])],
        };
        assert_eq!(bad_id.validate().unwrap_err(), unique);
        let mut untitled = group("a", vec![name("a.exe")], &[]);
        untitled.title = "  ".into();
        assert_eq!(
            Groups {
                groups: vec![untitled]
            }
            .validate()
            .unwrap_err(),
            unique
        );

        let bad_selector = Groups {
            groups: vec![group("a", vec![name("nope")], &[])],
        };
        assert_eq!(
            bad_selector.validate().unwrap_err(),
            "Проверь условия поиска в группе «Title a»."
        );
        let no_selectors = Groups {
            groups: vec![group("a", vec![], &[])],
        };
        assert_eq!(
            no_selectors.validate().unwrap_err(),
            "В группе «a» нет условий поиска."
        );
    }

    #[test]
    fn resolve_follows_includes_and_dedups() {
        let groups = Groups {
            groups: vec![
                group("top", vec![name("a.exe")], &["left", "right"]),
                group("left", vec![name("b.exe")], &["shared"]),
                group("right", vec![name("c.exe")], &["shared"]),
                group("shared", vec![name("a.exe"), name("d.exe")], &[]),
            ],
        };
        assert_eq!(
            groups.resolve("top").unwrap(),
            vec![name("a.exe"), name("b.exe"), name("d.exe"), name("c.exe")]
        );
        assert!(groups.validate().is_ok());
    }

    #[test]
    fn resolve_detects_cycles() {
        let groups = Groups {
            groups: vec![
                group("a", vec![name("a.exe")], &["b"]),
                group("b", vec![name("b.exe")], &["a"]),
            ],
        };
        assert_eq!(
            groups.resolve("a").unwrap_err(),
            "Группа «a» включена сама в себя."
        );
        assert!(groups.validate().is_err());
        let selfref = Groups {
            groups: vec![group("a", vec![name("a.exe")], &["a"])],
        };
        assert!(selfref.resolve("a").is_err());
    }

    #[test]
    fn resolve_reports_missing_ids() {
        let groups = Groups {
            groups: vec![group("a", vec![name("a.exe")], &["ghost"])],
        };
        assert_eq!(
            groups.resolve("a").unwrap_err(),
            "Группа «ghost» не найдена."
        );
        assert_eq!(
            groups.resolve("other").unwrap_err(),
            "Группа «other» не найдена."
        );
    }

    #[test]
    fn legacy_stop_setting_is_discarded() {
        let old = r#"{"groups":[{"id":"a","title":"A","selectors":[{"kind":"name","value":"a.exe"}],"block_network_on_stop":true}]}"#;
        let config: Groups = serde_json::from_str(old).unwrap();
        assert!(config.validate().is_ok());
        let serialized = serde_json::to_string(&config).unwrap();
        assert!(!serialized.contains("block_network_on_stop"));
        assert_eq!(config, serde_json::from_str::<Groups>(&serialized).unwrap());
    }

    #[test]
    fn config_rejects_unknown_fields() {
        assert!(serde_json::from_str::<Groups>(r#"{"groups":[],"x":1}"#).is_err());
        let ok: Groups = serde_json::from_str(
            r#"{"groups":[{"id":"a","title":"A","selectors":[{"kind":"name","value":"a.exe"}]}]}"#,
        )
        .unwrap();
        assert_eq!(ok.groups[0].selectors, vec![name("a.exe")]);
    }
}
