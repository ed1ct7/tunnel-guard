use crate::backend::{atomic_write, lock_config, storage, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::HashSet, fs, path::Path};

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
            let group = groups
                .groups
                .iter()
                .find(|group| group.id == id)
                .ok_or_else(|| format!("Группа «{id}» не найдена."))?;
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
    let path = storage()?.join("process-groups.json");
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
    let bytes = serde_json::to_vec_pretty(&config).map_err(|error| error.to_string())?;
    atomic_write(&storage()?.join("process-groups.json"), &bytes)
}

pub(crate) fn execute(id: &str, stop: bool) -> Result<Value> {
    execute_with_config(id, stop, None)
}

fn execute_with_config(id: &str, stop: bool, original: Option<Groups>) -> Result<Value> {
    let current = load_process_groups()?;
    if original.is_some_and(|previous| previous != current) {
        return Err("Группы изменились. Перечитай список и повтори действие.".into());
    }
    let selectors = current.resolve(id)?;
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
    tauri::async_runtime::spawn_blocking(move || execute_with_config(&id, stop, Some(original)))
        .await
        .map_err(|error| error.to_string())?
}

#[cfg(windows)]
fn run_windows(selectors: &[Selector], stop: bool) -> Result<Value> {
    use std::{
        env,
        io::Write,
        os::windows::process::CommandExt,
        path::PathBuf,
        process::{Command, Stdio},
    };
    use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;
    let executable = PathBuf::from(env::var_os("SystemRoot").ok_or("SystemRoot не найден.")?)
        .join("System32/WindowsPowerShell/v1.0/powershell.exe");
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
