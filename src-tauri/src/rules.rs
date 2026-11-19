use crate::{
    settings::{atomic_write, client_path, load_settings, lock_config, storage, Settings},
    status::read_vpn_targets,
    Result,
};
use serde::{Deserialize, Serialize};
use serde_yaml::{Mapping, Value};
use std::{
    fs,
    path::{Path, PathBuf},
};

pub(crate) const DIRECT_DEFAULT: &str = "MATCH,DIRECT";

/// Parse Mixin.yaml bytes: UTF-8, optional BOM, root must be a mapping or empty.
pub(crate) fn parse_mixin(raw: &[u8]) -> Result<Mapping> {
    let content = std::str::from_utf8(raw).map_err(|_| "Mixin.yaml должен быть в UTF-8.")?;
    let parsed: Value = serde_yaml::from_str(content.trim_start_matches('\u{feff}'))
        .map_err(|_| "Не удалось прочитать структуру Mixin.yaml.")?;
    match parsed {
        Value::Mapping(root) => Ok(root),
        Value::Null => Ok(Mapping::new()),
        _ => Err("Корень Mixin.yaml должен содержать таблицу.".into()),
    }
}

fn mixin(settings: &Settings) -> Result<(PathBuf, Vec<u8>, Mapping)> {
    let client = client_path(settings)?;
    let path = client
        .parent()
        .ok_or("Папка v2rayN не найдена.")?
        .join("guiConfigs/Mixin.yaml");
    let raw = fs::read(&path).map_err(|_| "В выбранной папке нет guiConfigs/Mixin.yaml.")?;
    let root = parse_mixin(&raw)?;
    Ok((path, raw, root))
}

pub(crate) fn read_rules(root: &Mapping) -> Result<Vec<String>> {
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

pub(crate) fn load_rules() -> Result<Vec<String>> {
    read_rules(&mixin(&load_settings()?)?.2)
}

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

/// Validate a proposed rule list against the current one (no IO). Returns the
/// non-DIRECT targets that must exist in the running Mihomo.
pub(crate) fn validate_rule_list(current: &[String], next: &[String]) -> Result<Vec<String>> {
    let reverse = next.last().is_some_and(|rule| rule == DIRECT_DEFAULT);
    if next.iter().filter(|rule| *rule == DIRECT_DEFAULT).count() != usize::from(reverse) {
        return Err("Маршрут по умолчанию должен быть единственным и стоять последним.".into());
    }
    if reverse
        && next
            .iter()
            .any(|rule| rule.starts_with("MATCH,") && rule != DIRECT_DEFAULT)
    {
        return Err("В пользовательском списке уже установлен другой маршрут по умолчанию.".into());
    }
    let vpn_routes: Vec<_> = next
        .iter()
        .filter_map(|rule| specific_rule(rule))
        .filter(|(_, _, target)| *target != "DIRECT")
        .map(|(_, _, target)| target)
        .collect();
    if reverse && vpn_routes.is_empty() {
        return Err("Сначала добавь хотя бы один сайт или программу с маршрутом через VPN.".into());
    }
    let mut check_targets = if reverse && !current.iter().any(|rule| rule == DIRECT_DEFAULT) {
        vpn_routes
    } else {
        Vec::new()
    };
    for rule in next
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
    Ok(check_targets.into_iter().map(str::to_owned).collect())
}

/// True when ClashUIItem.EnableMixinContent is `true` (keys case-insensitive).
pub(crate) fn mixin_content_enabled(gui_config: &serde_json::Value) -> bool {
    gui_config
        .as_object()
        .and_then(|config| {
            config
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case("ClashUIItem"))
        })
        .and_then(|(_, value)| value.as_object())
        .is_some_and(|entry| {
            entry.iter().any(|(key, value)| {
                key.eq_ignore_ascii_case("EnableMixinContent") && value.as_bool() == Some(true)
            })
        })
}

/// Read `guiNConfig.json` next to the given Mixin.yaml path.
pub(crate) fn mixin_content_enabled_for(mixin_path: &Path) -> Result<bool> {
    let config = mixin_path.with_file_name("guiNConfig.json");
    let config: serde_json::Value =
        serde_json::from_slice(&fs::read(config).map_err(|_| "Не найдены настройки v2rayN.")?)
            .map_err(|_| "Не удалось прочитать настройки v2rayN.")?;
    if !config.is_object() {
        return Err("Некорректные настройки v2rayN.".into());
    }
    Ok(mixin_content_enabled(&config))
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
    let check_targets = validate_rule_list(&current, &rules)?;
    if !check_targets.is_empty() {
        let available = read_vpn_targets()?;
        if check_targets
            .iter()
            .any(|target| !available.iter().any(|name| name == target))
        {
            return Err("Выбранный маршрут отсутствует в запущенном Mihomo.".into());
        }
    }
    if !mixin_content_enabled_for(&path)? {
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

pub(crate) fn config_snapshot() -> Result<ConfigSnapshot> {
    let settings = load_settings()?;
    let rules = mixin(&settings)
        .and_then(|(_, _, root)| read_rules(&root))
        .ok();
    Ok(ConfigSnapshot { settings, rules })
}

pub(crate) fn recover_routing_draft() -> Result<Option<Vec<String>>> {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn v(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| (*item).to_owned()).collect()
    }

    #[test]
    fn specific_rule_parses_three_parts() {
        assert_eq!(
            specific_rule("DOMAIN-SUFFIX,example.com,Proxy"),
            Some(("DOMAIN-SUFFIX", "example.com", "Proxy"))
        );
        assert_eq!(
            specific_rule("PROCESS-NAME,a.exe,DIRECT"),
            Some(("PROCESS-NAME", "a.exe", "DIRECT"))
        );
    }

    #[test]
    fn specific_rule_rejects_malformed() {
        for rule in [
            "MATCH,DIRECT",
            "DOMAIN-SUFFIX,example.com",
            "DOMAIN-SUFFIX,example.com,Proxy,extra",
            "DOMAIN,example.com,Proxy",
            "DOMAIN-SUFFIX,example.com,  ",
            "DOMAIN-SUFFIX,exa\nmple.com,Proxy",
            "",
        ] {
            assert_eq!(specific_rule(rule), None, "{rule:?}");
        }
    }

    #[test]
    fn domain_values() {
        let ok = |value| valid_rule_value("DOMAIN-SUFFIX", value);
        assert!(ok("example.com"));
        assert!(ok("a.b.example.com"));
        assert!(!ok("localhost"));
        assert!(!ok("*.example.com"));
        assert!(!ok("https://example.com"));
        assert!(!ok("example.com/path"));
        assert!(!ok("192.168.0.1"));
        assert!(!ok(""));
    }

    #[test]
    fn process_name_values() {
        let ok = |value| valid_rule_value("PROCESS-NAME", value);
        assert!(ok("chrome.exe"));
        assert!(ok("Chrome.EXE"));
        assert!(!ok("chrome"));
        assert!(!ok("dir\\chrome.exe"));
        assert!(!ok("a/b.exe"));
        assert!(!ok("a*.exe"));
        assert!(!ok("c:chrome.exe"));
    }

    #[test]
    fn process_path_values() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("app.exe");
        fs::write(&exe, b"").unwrap();
        let txt = dir.path().join("app.txt");
        fs::write(&txt, b"").unwrap();
        let missing = dir.path().join("none.exe");
        let ok = |path: &Path| valid_rule_value("PROCESS-PATH", &path.to_string_lossy());
        assert!(ok(&exe));
        assert!(!ok(&txt));
        assert!(!ok(&missing));
        assert!(!valid_rule_value("PROCESS-PATH", "app.exe"));
    }

    #[test]
    fn unknown_kind_is_invalid() {
        assert!(!valid_rule_value("DOMAIN", "example.com"));
    }

    #[test]
    fn upsert_replaces_case_insensitively() {
        let rules = v(&[
            "DOMAIN-SUFFIX,Example.com,DIRECT",
            "PROCESS-NAME,a.exe,Proxy",
        ]);
        let next = upsert_rule(rules, "DOMAIN-SUFFIX,example.COM,Proxy".into());
        assert_eq!(
            next,
            v(&[
                "DOMAIN-SUFFIX,example.COM,Proxy",
                "PROCESS-NAME,a.exe,Proxy"
            ])
        );
    }

    #[test]
    fn upsert_same_value_different_kind_is_inserted() {
        let rules = v(&["PROCESS-NAME,a.exe,Proxy"]);
        let next = upsert_rule(rules, "PROCESS-PATH,a.exe,Proxy".into());
        assert_eq!(next.len(), 2);
    }

    #[test]
    fn upsert_inserts_before_default() {
        let rules = v(&["DOMAIN-SUFFIX,a.com,Proxy", "MATCH,DIRECT"]);
        let next = upsert_rule(rules, "DOMAIN-SUFFIX,b.com,Proxy".into());
        assert_eq!(
            next,
            v(&[
                "DOMAIN-SUFFIX,a.com,Proxy",
                "DOMAIN-SUFFIX,b.com,Proxy",
                "MATCH,DIRECT"
            ])
        );
    }

    #[test]
    fn upsert_appends_without_default_and_for_unparsed_rules() {
        let next = upsert_rule(
            v(&["DOMAIN-SUFFIX,a.com,Proxy"]),
            "DOMAIN-SUFFIX,b.com,P".into(),
        );
        assert_eq!(next.last().unwrap(), "DOMAIN-SUFFIX,b.com,P");
        let next = upsert_rule(v(&["MATCH,DIRECT"]), "GEOIP,RU,DIRECT".into());
        assert_eq!(next, v(&["MATCH,DIRECT", "GEOIP,RU,DIRECT"]));
    }

    #[test]
    fn list_happy_path_profile_mode() {
        let next = v(&["DOMAIN-SUFFIX,a.com,Proxy", "PROCESS-NAME,a.exe,DIRECT"]);
        assert_eq!(validate_rule_list(&[], &next).unwrap(), v(&["Proxy"]));
    }

    #[test]
    fn list_happy_path_vpn_only_checks_all_vpn_routes() {
        let current = v(&["DOMAIN-SUFFIX,a.com,Proxy"]);
        let next = v(&["DOMAIN-SUFFIX,a.com,Proxy", "MATCH,DIRECT"]);
        assert_eq!(validate_rule_list(&current, &next).unwrap(), v(&["Proxy"]));
    }

    #[test]
    fn list_already_vpn_only_checks_only_new_rules() {
        let current = v(&["DOMAIN-SUFFIX,a.com,Proxy", "MATCH,DIRECT"]);
        let next = v(&[
            "DOMAIN-SUFFIX,a.com,Proxy",
            "DOMAIN-SUFFIX,b.com,Other",
            "MATCH,DIRECT",
        ]);
        assert_eq!(validate_rule_list(&current, &next).unwrap(), v(&["Other"]));
    }

    #[test]
    fn list_removal_needs_no_checks() {
        let current = v(&["DOMAIN-SUFFIX,a.com,Proxy", "DOMAIN-SUFFIX,b.com,Proxy"]);
        let next = v(&["DOMAIN-SUFFIX,a.com,Proxy"]);
        assert!(validate_rule_list(&current, &next).unwrap().is_empty());
    }

    #[test]
    fn list_default_must_be_last_and_single() {
        let msg = "Маршрут по умолчанию должен быть единственным и стоять последним.";
        let first = v(&["MATCH,DIRECT", "DOMAIN-SUFFIX,a.com,Proxy"]);
        assert_eq!(validate_rule_list(&[], &first).unwrap_err(), msg);
        let twice = v(&["DOMAIN-SUFFIX,a.com,Proxy", "MATCH,DIRECT", "MATCH,DIRECT"]);
        assert_eq!(validate_rule_list(&[], &twice).unwrap_err(), msg);
    }

    #[test]
    fn list_rejects_other_match_in_vpn_only() {
        let next = v(&["MATCH,Proxy", "DOMAIN-SUFFIX,a.com,Proxy", "MATCH,DIRECT"]);
        assert_eq!(
            validate_rule_list(&[], &next).unwrap_err(),
            "В пользовательском списке уже установлен другой маршрут по умолчанию."
        );
    }

    #[test]
    fn list_vpn_only_needs_vpn_route() {
        let msg = "Сначала добавь хотя бы один сайт или программу с маршрутом через VPN.";
        assert_eq!(
            validate_rule_list(&[], &v(&["MATCH,DIRECT"])).unwrap_err(),
            msg
        );
        let only_direct = v(&["DOMAIN-SUFFIX,a.com,DIRECT", "MATCH,DIRECT"]);
        assert_eq!(validate_rule_list(&[], &only_direct).unwrap_err(), msg);
    }

    #[test]
    fn list_rejects_bad_format_and_value() {
        assert_eq!(
            validate_rule_list(&[], &v(&["GEOIP,RU,DIRECT"])).unwrap_err(),
            "Проверь формат правила маршрутизации."
        );
        assert_eq!(
            validate_rule_list(&[], &v(&["DOMAIN-SUFFIX,https://a.com,Proxy"])).unwrap_err(),
            "Укажи домен без URL, имя процесса или путь к существующему .exe."
        );
    }

    #[test]
    fn list_keeps_existing_unknown_rules() {
        let current = v(&["GEOIP,RU,DIRECT"]);
        let next = v(&["GEOIP,RU,DIRECT", "DOMAIN-SUFFIX,a.com,Proxy"]);
        assert_eq!(validate_rule_list(&current, &next).unwrap(), v(&["Proxy"]));
    }

    #[test]
    fn mixin_plain_mapping() {
        let root = parse_mixin(b"prepend-rules:\n  - a\n  - b\n").unwrap();
        assert_eq!(read_rules(&root).unwrap(), v(&["a", "b"]));
    }

    #[test]
    fn mixin_strips_bom() {
        let mut raw = vec![0xef, 0xbb, 0xbf];
        raw.extend_from_slice(b"prepend-rules:\n  - a\n");
        assert_eq!(read_rules(&parse_mixin(&raw).unwrap()).unwrap(), v(&["a"]));
    }

    #[test]
    fn mixin_empty_and_null() {
        assert!(parse_mixin(b"").unwrap().is_empty());
        assert!(parse_mixin(b"# only a comment\n").unwrap().is_empty());
        assert!(parse_mixin(b"~").unwrap().is_empty());
    }

    #[test]
    fn mixin_errors() {
        assert_eq!(
            parse_mixin(b"- a\n- b\n").unwrap_err(),
            "Корень Mixin.yaml должен содержать таблицу."
        );
        assert_eq!(
            parse_mixin(&[0xff, 0xfe, 0x00]).unwrap_err(),
            "Mixin.yaml должен быть в UTF-8."
        );
        assert_eq!(
            parse_mixin(b"a: [unclosed").unwrap_err(),
            "Не удалось прочитать структуру Mixin.yaml."
        );
    }

    #[test]
    fn rules_must_be_list_of_strings() {
        let root = parse_mixin(b"prepend-rules: nope\n").unwrap();
        assert_eq!(
            read_rules(&root).unwrap_err(),
            "prepend-rules должен быть списком."
        );
        let root = parse_mixin(b"prepend-rules:\n  - a\n  - 5\n").unwrap();
        assert_eq!(
            read_rules(&root).unwrap_err(),
            "В prepend-rules допустимы строки."
        );
        let root = parse_mixin(b"other: 1\n").unwrap();
        assert!(read_rules(&root).unwrap().is_empty());
    }

    #[test]
    fn mixin_content_flag() {
        let on = serde_json::json!({"ClashUIItem": {"EnableMixinContent": true}});
        assert!(mixin_content_enabled(&on));
        let mixed_case = serde_json::json!({"clashuiitem": {"enablemixincontent": true}});
        assert!(mixin_content_enabled(&mixed_case));
        let off = serde_json::json!({"ClashUIItem": {"EnableMixinContent": false}});
        assert!(!mixin_content_enabled(&off));
        let string = serde_json::json!({"ClashUIItem": {"EnableMixinContent": "true"}});
        assert!(!mixin_content_enabled(&string));
        let missing = serde_json::json!({"ClashUIItem": {}});
        assert!(!mixin_content_enabled(&missing));
        assert!(!mixin_content_enabled(&serde_json::json!({})));
        assert!(!mixin_content_enabled(&serde_json::json!([1])));
    }

    #[test]
    fn mixin_content_flag_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let mixin_path = dir.path().join("Mixin.yaml");
        assert_eq!(
            mixin_content_enabled_for(&mixin_path).unwrap_err(),
            "Не найдены настройки v2rayN."
        );
        let config = dir.path().join("guiNConfig.json");
        fs::write(&config, b"{bad").unwrap();
        assert_eq!(
            mixin_content_enabled_for(&mixin_path).unwrap_err(),
            "Не удалось прочитать настройки v2rayN."
        );
        fs::write(&config, b"[1]").unwrap();
        assert_eq!(
            mixin_content_enabled_for(&mixin_path).unwrap_err(),
            "Некорректные настройки v2rayN."
        );
        fs::write(&config, br#"{"ClashUIItem":{"EnableMixinContent":true}}"#).unwrap();
        assert!(mixin_content_enabled_for(&mixin_path).unwrap());
    }
}
