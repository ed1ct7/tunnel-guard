//! Read-only auto-detection of the v2rayN install and its connection
//! settings (`detect_client`). Nothing is written; the panel decides whether
//! to save the suggestion.

use crate::{
    rules,
    settings::{self, Settings},
    Result,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_yaml::Mapping;
use std::{
    collections::HashSet,
    env, fs,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ClientDetection {
    pub settings: Option<Settings>,
    /// Other v2rayN executables that were found.
    pub candidates: Vec<String>,
    pub note: Option<String>,
}

/// v2rayN's default socks inbound (`GetLocalPort` falls back to it).
const DEFAULT_PORT: u16 = 10808;
/// v2rayN's TUN template sets no `device`; Mihomo then names the Windows
/// adapter after its built-in `InterfaceName`, "Meta".
const DEFAULT_ADAPTER: &str = "Meta";
const SCAN_DEPTH: usize = 2;

fn exe_name() -> &'static str {
    if cfg!(windows) {
        "v2rayN.exe"
    } else {
        "v2rayN"
    }
}

fn field<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    value
        .as_object()?
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(key))
        .map(|(_, value)| value)
}

fn port_value(value: &Value) -> Option<u16> {
    let port = match value {
        Value::Number(number) => number.as_u64()?,
        Value::String(text) => text.trim().parse().ok()?,
        _ => return None,
    };
    u16::try_from(port).ok().filter(|port| *port != 0)
}

/// Proxy port from guiNConfig.json: the socks inbound (what v2rayN itself
/// uses for `mixed-port`), else the first inbound.
pub(crate) fn proxy_port_from(gui: &Value) -> Option<u16> {
    let inbound = field(gui, "Inbound")?.as_array()?;
    let socks = inbound.iter().find(|entry| {
        field(entry, "Protocol")
            .and_then(Value::as_str)
            .is_some_and(|protocol| protocol.eq_ignore_ascii_case("socks"))
    });
    socks
        .or_else(|| inbound.first())
        .and_then(|entry| field(entry, "LocalPort"))
        .and_then(port_value)
}

pub(crate) fn tun_enabled(gui: &Value) -> Option<bool> {
    field(gui, "TunModeItem")
        .and_then(|item| field(item, "EnableTun"))
        .and_then(Value::as_bool)
}

pub(crate) fn mixin_device(mixin: &Mapping) -> Option<String> {
    mixin
        .get("tun")?
        .as_mapping()?
        .get("device")?
        .as_str()
        .map(str::trim)
        .filter(|device| !device.is_empty())
        .map(str::to_owned)
}

/// Port and adapter for one install plus notes for whatever was assumed.
pub(crate) fn connection_from(
    gui: Option<&Value>,
    mixin: Option<&Mapping>,
) -> (u16, String, Vec<String>) {
    let mut notes = Vec::new();
    let port = match gui.and_then(proxy_port_from) {
        Some(port) => port,
        None => {
            notes.push(format!(
                "Порт прокси не найден в guiNConfig.json — взят {DEFAULT_PORT}."
            ));
            DEFAULT_PORT
        }
    };
    let mixin_enabled = gui.is_some_and(rules::mixin_content_enabled);
    let tun = gui.and_then(tun_enabled);
    if tun == Some(false) {
        notes.push("В v2rayN выключен Enable TUN.".into());
    }
    let device = mixin.and_then(mixin_device);
    let adapter = match device {
        // v2rayN copies Mixin's `tun:` only with Mixin content and TUN on.
        Some(device) if mixin_enabled && tun != Some(false) => device,
        Some(_) => {
            notes.push(format!(
                "tun.device из Mixin.yaml не применяется без Enable Mixin Content — адаптер {DEFAULT_ADAPTER}."
            ));
            DEFAULT_ADAPTER.into()
        }
        None => {
            notes.push(format!(
                "В Mixin.yaml нет tun.device — адаптер по умолчанию {DEFAULT_ADAPTER}."
            ));
            DEFAULT_ADAPTER.into()
        }
    };
    (port, adapter, notes)
}

fn read_gui(dir: &Path) -> Option<Value> {
    let raw = fs::read(dir.join("guiConfigs").join("guiNConfig.json")).ok()?;
    let raw = raw.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(&raw);
    serde_json::from_slice::<Value>(raw)
        .ok()
        .filter(Value::is_object)
}

fn read_mixin(dir: &Path) -> Option<Mapping> {
    let raw = fs::read(dir.join("guiConfigs").join("Mixin.yaml")).ok()?;
    rules::parse_mixin(&raw).ok()
}

fn is_client(path: &Path) -> bool {
    settings::client_path(&Settings {
        client_path: path.to_string_lossy().into_owned(),
        ..Settings::default()
    })
    .is_ok()
}

fn is_client_dir_name(name: &str) -> bool {
    name.get(..6)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("v2rayN"))
}

/// `v2rayN*` folders holding the executable, at most `SCAN_DEPTH` levels
/// below `root`. Links and junctions are not followed.
pub(crate) fn scan(root: &Path, depth: usize, found: &mut Vec<PathBuf>) {
    if depth == 0 {
        return;
    }
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if !kind.is_dir() || kind.is_symlink() {
            continue;
        }
        let path = entry.path();
        if entry.file_name().to_str().is_some_and(is_client_dir_name) {
            let exe = path.join(exe_name());
            if is_client(&exe) {
                found.push(exe);
                continue;
            }
        }
        scan(&path, depth - 1, found);
    }
}

fn scan_roots() -> Vec<PathBuf> {
    let var = |name: &str| env::var_os(name).map(PathBuf::from);
    let mut roots = Vec::new();
    roots.extend(var("LOCALAPPDATA"));
    if let Some(home) = var("USERPROFILE") {
        roots.push(home.join("Desktop"));
        roots.push(home.join("Downloads"));
        roots.push(home.clone());
    }
    roots.extend(var("ProgramFiles"));
    roots.push(PathBuf::from(r"C:\"));
    roots.push(PathBuf::from(r"D:\"));
    roots
}

fn scoop_client() -> Option<PathBuf> {
    let home = env::var_os("USERPROFILE")?;
    Some(
        PathBuf::from(home)
            .join(r"scoop\apps\v2rayN\current")
            .join(exe_name()),
    )
}

fn dedupe(paths: impl IntoIterator<Item = PathBuf>) -> Vec<PathBuf> {
    let mut seen = HashSet::new();
    paths
        .into_iter()
        .filter(|path| seen.insert(path.to_string_lossy().to_lowercase().replace('/', "\\")))
        .collect()
}

/// Pure-ish core: `running` are the image paths of running v2rayN processes
/// (`None` when a path could not be read), `current` the saved path.
pub(crate) fn detect_from(
    running: Vec<Option<PathBuf>>,
    current: Option<PathBuf>,
    extra: Vec<PathBuf>,
    roots: &[PathBuf],
) -> ClientDetection {
    let mut notes = Vec::new();
    if running.iter().any(Option::is_none) {
        notes.push("Путь к запущенному v2rayN не прочитать (запущен от администратора?).".into());
    }
    let running: Vec<PathBuf> = running
        .into_iter()
        .flatten()
        .filter(|path| is_client(path))
        .collect();
    let mut scanned = Vec::new();
    for root in roots {
        scan(root, SCAN_DEPTH, &mut scanned);
    }
    let found = dedupe(
        running
            .iter()
            .cloned()
            .chain(current.filter(|path| is_client(path)))
            .chain(extra.into_iter().filter(|path| is_client(path)))
            .chain(scanned),
    );
    let Some(chosen) = found.first().cloned() else {
        notes.push("v2rayN не найден — укажи путь к v2rayN.exe вручную.".into());
        return ClientDetection {
            settings: None,
            candidates: Vec::new(),
            note: Some(notes.join(" ")),
        };
    };
    if running.len() > 1 {
        notes.push("Запущено несколько v2rayN — выбран первый.".into());
    }
    let dir = chosen.parent().map(Path::to_path_buf).unwrap_or_default();
    let gui = read_gui(&dir);
    let mixin = read_mixin(&dir);
    let (proxy_port, adapter, connection_notes) = connection_from(gui.as_ref(), mixin.as_ref());
    notes.extend(connection_notes);
    ClientDetection {
        settings: Some(Settings {
            client_path: chosen.to_string_lossy().into_owned(),
            adapter,
            proxy_port,
        }),
        candidates: found[1..]
            .iter()
            .map(|path| path.to_string_lossy().into_owned())
            .collect(),
        note: (!notes.is_empty()).then(|| notes.join(" ")),
    }
}

pub(crate) fn detect_client() -> Result<ClientDetection> {
    #[cfg(windows)]
    let running = crate::windows::running_images(exe_name());
    #[cfg(not(windows))]
    let running = Vec::new();
    let current = settings::load_settings()
        .ok()
        .map(|settings| settings.client_path)
        .filter(|path| !path.trim().is_empty())
        .map(PathBuf::from);
    Ok(detect_from(
        running,
        current,
        scoop_client().into_iter().collect(),
        &scan_roots(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn install(root: &Path, name: &str, gui: Option<&str>, mixin: Option<&str>) -> PathBuf {
        let dir = root.join(name);
        fs::create_dir_all(dir.join("guiConfigs")).unwrap();
        fs::write(dir.join(exe_name()), b"").unwrap();
        if let Some(gui) = gui {
            fs::write(dir.join("guiConfigs/guiNConfig.json"), gui).unwrap();
        }
        if let Some(mixin) = mixin {
            fs::write(dir.join("guiConfigs/Mixin.yaml"), mixin).unwrap();
        }
        dir.join(exe_name())
    }

    fn mixin(raw: &str) -> Mapping {
        rules::parse_mixin(raw.as_bytes()).unwrap()
    }

    #[test]
    fn proxy_port_prefers_socks_inbound() {
        let gui = json!({"Inbound": [
            {"Protocol": "http", "LocalPort": 10809},
            {"Protocol": "socks", "LocalPort": 18761}
        ]});
        assert_eq!(proxy_port_from(&gui), Some(18761));
        let gui = json!({"inbound": [{"localPort": "20000"}]});
        assert_eq!(proxy_port_from(&gui), Some(20000));
        assert_eq!(proxy_port_from(&json!({"Inbound": []})), None);
        assert_eq!(
            proxy_port_from(&json!({"Inbound": [{"LocalPort": 0}]})),
            None
        );
        assert_eq!(
            proxy_port_from(&json!({"Inbound": [{"LocalPort": 70000}]})),
            None
        );
        assert_eq!(proxy_port_from(&json!({})), None);
    }

    #[test]
    fn adapter_from_mixin_only_when_v2rayn_applies_it() {
        let gui = json!({
            "Inbound": [{"Protocol": "socks", "LocalPort": 18761}],
            "ClashUIItem": {"EnableMixinContent": true},
            "TunModeItem": {"EnableTun": true}
        });
        let with_device = mixin("tun:\n  enable: true\n  device: MihomoTest\n");
        assert_eq!(
            connection_from(Some(&gui), Some(&with_device)),
            (18761, "MihomoTest".into(), vec![])
        );
        let (_, adapter, notes) = connection_from(Some(&gui), Some(&mixin("prepend-rules: []\n")));
        assert_eq!(adapter, "Meta");
        assert_eq!(notes.len(), 1);
        let disabled = json!({
            "Inbound": [{"Protocol": "socks", "LocalPort": 18761}],
            "ClashUIItem": {"EnableMixinContent": false}
        });
        let (_, adapter, notes) = connection_from(Some(&disabled), Some(&with_device));
        assert_eq!(adapter, "Meta");
        assert!(notes[0].contains("Enable Mixin Content"));
        let tun_off = json!({
            "Inbound": [{"Protocol": "socks", "LocalPort": 18761}],
            "ClashUIItem": {"EnableMixinContent": true},
            "TunModeItem": {"EnableTun": false}
        });
        let (_, adapter, notes) = connection_from(Some(&tun_off), Some(&with_device));
        assert_eq!(adapter, "Meta");
        assert!(notes.iter().any(|note| note.contains("Enable TUN")));
    }

    #[test]
    fn missing_configs_fall_back_to_defaults() {
        let (port, adapter, notes) = connection_from(None, None);
        assert_eq!((port, adapter.as_str()), (10808, "Meta"));
        assert_eq!(notes.len(), 2);
    }

    #[test]
    fn scan_finds_shallow_installs_only() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let top = install(root, "v2rayN-windows-64", None, None);
        let nested = install(root, "Tools/V2RAYN", None, None);
        install(root, "a/b/v2rayN", None, None); // too deep
        install(root, "other", None, None); // wrong folder name
        fs::create_dir_all(root.join("v2rayN-empty")).unwrap();
        let mut found = Vec::new();
        scan(root, SCAN_DEPTH, &mut found);
        found.sort();
        let mut expected = vec![top, nested];
        expected.sort();
        assert_eq!(found, expected);
        scan(&root.join("missing"), SCAN_DEPTH, &mut found);
        assert_eq!(found.len(), 2);
    }

    #[test]
    fn running_install_wins_and_others_are_candidates() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let scanned = install(root, "v2rayN-old", None, None);
        let running = install(
            &root.join("deep/er"),
            "v2rayN-live",
            Some(
                r#"{"Inbound":[{"Protocol":"socks","LocalPort":18761}],"ClashUIItem":{"EnableMixinContent":true},"TunModeItem":{"EnableTun":true}}"#,
            ),
            Some("tun:\n  device: MihomoTest\n"),
        );
        let current = install(root, "saved/v2rayN", None, None);
        let detection = detect_from(
            vec![Some(running.clone())],
            Some(current.clone()),
            vec![],
            &[root.to_path_buf()],
        );
        assert_eq!(
            detection.settings,
            Some(Settings {
                client_path: running.to_string_lossy().into_owned(),
                adapter: "MihomoTest".into(),
                proxy_port: 18761,
            })
        );
        assert_eq!(detection.note, None);
        let mut candidates = detection.candidates.clone();
        candidates.sort();
        let mut expected = vec![
            current.to_string_lossy().into_owned(),
            scanned.to_string_lossy().into_owned(),
        ];
        expected.sort();
        assert_eq!(candidates, expected);
    }

    #[test]
    fn duplicates_are_removed_case_insensitively() {
        let dir = tempfile::tempdir().unwrap();
        let exe = install(dir.path(), "v2rayN", None, None);
        let upper = PathBuf::from(exe.to_string_lossy().to_uppercase());
        let detection = detect_from(
            vec![Some(exe.clone())],
            Some(if upper.is_file() { upper } else { exe.clone() }),
            vec![],
            &[dir.path().to_path_buf()],
        );
        assert!(
            detection.candidates.is_empty(),
            "{:?}",
            detection.candidates
        );
        assert!(detection.settings.is_some());
    }

    #[test]
    fn unreadable_process_and_nothing_found() {
        let dir = tempfile::tempdir().unwrap();
        let detection = detect_from(
            vec![None],
            Some(dir.path().join("missing").join(exe_name())),
            vec![],
            &[dir.path().to_path_buf()],
        );
        assert_eq!(detection.settings, None);
        assert!(detection.candidates.is_empty());
        let note = detection.note.unwrap();
        assert!(
            note.contains("администратора") && note.contains("не найден"),
            "{note}"
        );
    }

    #[test]
    fn serializes_contract_shape() {
        let value = serde_json::to_value(ClientDetection {
            settings: None,
            candidates: vec!["x".into()],
            note: None,
        })
        .unwrap();
        assert_eq!(
            value,
            json!({"settings": null, "candidates": ["x"], "note": null})
        );
    }
}
