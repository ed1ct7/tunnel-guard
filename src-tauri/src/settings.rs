use crate::{status::GuardState, Result};
use serde::{Deserialize, Serialize};
use std::{
    env, fs,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProtectionBackend {
    #[default]
    GroupPolicy,
    Wfp,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Settings {
    pub client_path: String,
    pub adapter: String,
    pub proxy_port: u16,
    #[serde(default)]
    pub protection_backend: ProtectionBackend,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            client_path: String::new(),
            adapter: "Mihomo".into(),
            proxy_port: 10808,
            protection_backend: ProtectionBackend::default(),
        }
    }
}

/// The per-user settings folder, without creating it.
pub(crate) fn storage_path() -> Result<PathBuf> {
    let base = if cfg!(windows) {
        env::var_os("LOCALAPPDATA").map(PathBuf::from)
    } else {
        env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
    }
    .ok_or("Не удалось определить папку настроек.")?;
    Ok(base.join("TunnelGuard"))
}

/// The per-user settings folder, created on first use. An elevated process
/// does not create it: the user owns the parent and could redirect the write.
pub(crate) fn storage() -> Result<PathBuf> {
    let dir = storage_path()?;
    #[cfg(windows)]
    if crate::windows::is_admin() {
        return Ok(dir);
    }
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

pub(crate) fn lock_config() -> Result<fs::File> {
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

pub(crate) fn load_settings() -> Result<Settings> {
    let path = storage_path()?.join("settings.json");
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|_| "Файл настроек повреждён.".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Settings::default()),
        Err(error) => Err(error.to_string()),
    }
}

pub(crate) fn client_path(settings: &Settings) -> Result<PathBuf> {
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

/// Adapter name and proxy port sanity check (no IO).
pub(crate) fn validate_connection(settings: &Settings) -> Result<()> {
    if settings.adapter.trim().is_empty()
        || settings.adapter.contains(['*', '?', '[', ']'])
        || settings.adapter.chars().any(char::is_control)
        || settings.proxy_port == 0
        || settings.proxy_port > 65529
    {
        return Err("Проверь имя TUN-адаптера и порт прокси.".into());
    }
    Ok(())
}

/// Settings may only be edited while the protection is not in force.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn state_allows_settings_edit(state: GuardState) -> bool {
    matches!(state, GuardState::Off | GuardState::LegacyInactive)
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
    if !state_allows_settings_edit(crate::status::read_status()?.state) {
        return Err("Сначала выключи защиту.".into());
    }
    client_path(&settings)?;
    validate_connection(&settings)?;
    let bytes = serde_json::to_vec_pretty(&settings).map_err(|error| error.to_string())?;
    atomic_write(&storage()?.join("settings.json"), &bytes)?;
    Ok(settings)
}

pub(crate) fn open_client() -> Result<()> {
    let executable = client_path(&load_settings()?)?;
    Command::new(&executable)
        .current_dir(executable.parent().ok_or("Папка v2rayN не найдена.")?)
        .spawn()
        .map_err(|error| error.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(adapter: &str, port: u16) -> Settings {
        Settings {
            client_path: String::new(),
            adapter: adapter.into(),
            proxy_port: port,
            ..Settings::default()
        }
    }

    #[test]
    fn default_connection_is_valid() {
        assert!(validate_connection(&Settings::default()).is_ok());
    }

    #[test]
    fn settings_saved_before_wfp_keep_group_policy() {
        let settings: Settings =
            serde_json::from_str(r#"{"client_path":"","adapter":"Meta","proxy_port":10808}"#)
                .unwrap();
        assert_eq!(settings.protection_backend, ProtectionBackend::GroupPolicy);
    }

    #[test]
    fn rejects_bad_adapter_names() {
        for adapter in ["", "   ", "Mi*homo", "a?b", "[x]", "tab\there", "nl\n"] {
            assert!(
                validate_connection(&settings(adapter, 10808)).is_err(),
                "{adapter:?}"
            );
        }
    }

    #[test]
    fn port_bounds() {
        assert!(validate_connection(&settings("Mihomo", 0)).is_err());
        assert!(validate_connection(&settings("Mihomo", 1)).is_ok());
        assert!(validate_connection(&settings("Mihomo", 65529)).is_ok());
        assert!(validate_connection(&settings("Mihomo", 65530)).is_err());
    }

    #[test]
    fn error_text_is_stable() {
        assert_eq!(
            validate_connection(&settings("", 1)).unwrap_err(),
            "Проверь имя TUN-адаптера и порт прокси."
        );
    }

    #[test]
    fn only_inactive_states_allow_edit() {
        assert!(state_allows_settings_edit(GuardState::Off));
        assert!(state_allows_settings_edit(GuardState::LegacyInactive));
        for state in [
            GuardState::On,
            GuardState::Partial,
            GuardState::LegacyActive,
            GuardState::Unsupported,
            GuardState::Unknown,
        ] {
            assert!(!state_allows_settings_edit(state), "{state:?}");
        }
    }

    #[test]
    fn client_path_rejects_relative_and_missing() {
        let mut value = Settings::default();
        assert!(client_path(&value).is_err());
        value.client_path = "v2rayN.exe".into();
        assert!(client_path(&value).is_err());
    }

    #[test]
    fn client_path_requires_exact_file_name() {
        let dir = tempfile::tempdir().unwrap();
        let expected = if cfg!(windows) {
            "v2rayN.exe"
        } else {
            "v2rayN"
        };
        let good = dir.path().join(expected);
        fs::write(&good, b"").unwrap();
        let other = dir.path().join("other.exe");
        fs::write(&other, b"").unwrap();
        let mut value = Settings {
            client_path: other.to_string_lossy().into_owned(),
            ..Settings::default()
        };
        assert!(client_path(&value).is_err());
        value.client_path = good.to_string_lossy().into_owned();
        assert_eq!(client_path(&value).unwrap(), good);
    }

    #[test]
    fn atomic_write_replaces_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.json");
        atomic_write(&path, b"one").unwrap();
        atomic_write(&path, b"two").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"two");
    }
}
