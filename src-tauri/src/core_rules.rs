//! Whether the running Mihomo uses the saved Mixin `prepend-rules`, and pushing
//! them into it without restarting v2rayN.
//!
//! v2rayN bakes `prepend-rules` into the `rules:` list of the config it
//! generates for Mihomo (`binConfigs/config.json`, YAML despite the name). That
//! file holds proxy credentials: it is never logged, printed or written, and
//! the reload payload built from it never leaves this process except in the
//! request body to 127.0.0.1.

use crate::{
    history::{self, HistoryEntry},
    http::{self, ControllerError},
    rules::{mixin, mixin_content_enabled_for, read_rules},
    settings::{client_path, load_settings, lock_config, Settings},
    Result,
};
use serde::Serialize;
use serde_yaml::{Mapping, Value};
use std::{
    fs,
    path::{Path, PathBuf},
};

/// Clock slack between Mixin.yaml / history timestamps and the generated file.
const SLACK_MS: u64 = 2000;
const GENERATED: [&str; 2] = ["binConfigs/config.json", "binConfigs/config.yaml"];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RulesState {
    Applied,
    Pending,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct CoreRulesState {
    pub state: RulesState,
    pub detail: Option<String>,
}

impl CoreRulesState {
    fn of(state: RulesState) -> Self {
        Self {
            state,
            detail: None,
        }
    }

    fn unknown(detail: impl Into<String>) -> Self {
        Self {
            state: RulesState::Unknown,
            detail: Some(detail.into()),
        }
    }
}

// ---------------------------------------------------------------- normalization

/// A rule reduced to what Mihomo reports in `GET /rules`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NormalRule {
    kind: String,
    payload: String,
    target: String,
}

/// Split on commas outside parentheses (logical rules carry commas inside).
fn split_top_level(rule: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let (mut depth, mut start) = (0i32, 0usize);
    for (index, character) in rule.char_indices() {
        match character {
            '(' => depth += 1,
            ')' => depth -= 1,
            ',' if depth <= 0 => {
                parts.push(&rule[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    parts.push(&rule[start..]);
    parts
}

/// `DOMAIN-SUFFIX` and Mihomo's `DomainSuffix` both become `DOMAINSUFFIX`.
pub(crate) fn kind_key(kind: &str) -> String {
    let key: String = kind
        .trim()
        .chars()
        .filter(|character| !matches!(character, '-' | '_'))
        .flat_map(char::to_uppercase)
        .collect();
    match key.as_str() {
        // Mihomo parses IP-CIDR6 as IPCIDR and SUB-RULE as SubRules.
        "IPCIDR6" => "IPCIDR".into(),
        "SUBRULE" => "SUBRULES".into(),
        _ => key,
    }
}

/// Normalise a config-side rule string. Trailing options such as
/// `no-resolve` are ignored; MATCH has an empty payload.
pub(crate) fn normalize_rule(rule: &str) -> NormalRule {
    let parts: Vec<&str> = split_top_level(rule).into_iter().map(str::trim).collect();
    let kind = kind_key(parts.first().copied().unwrap_or_default());
    let (payload, target) = if kind == "MATCH" {
        ("", parts.get(1).copied().unwrap_or_default())
    } else {
        (
            parts.get(1).copied().unwrap_or_default(),
            parts.get(2).copied().unwrap_or_default(),
        )
    };
    NormalRule {
        kind,
        payload: payload.to_lowercase(),
        target: target.to_lowercase(),
    }
}

/// Normalise one entry of Mihomo's `GET /rules` (`{type, payload, proxy}`).
pub(crate) fn normalize_runtime(entry: &serde_json::Value) -> Option<NormalRule> {
    let text = |key: &str| entry.get(key).and_then(serde_json::Value::as_str);
    let kind = kind_key(text("type")?);
    let payload = if kind == "MATCH" {
        ""
    } else {
        text("payload")?
    };
    Some(NormalRule {
        kind,
        payload: payload.trim().to_lowercase(),
        target: text("proxy")?.trim().to_lowercase(),
    })
}

pub(crate) fn runtime_rules(response: &serde_json::Value) -> Option<Vec<NormalRule>> {
    response
        .get("rules")?
        .as_array()?
        .iter()
        .map(normalize_runtime)
        .collect()
}

fn normalized(rules: &[String]) -> Vec<NormalRule> {
    rules.iter().map(|rule| normalize_rule(rule)).collect()
}

pub(crate) fn is_prefix(prefix: &[String], full: &[String]) -> bool {
    prefix.len() <= full.len() && normalized(prefix) == normalized(&full[..prefix.len()])
}

// ---------------------------------------------------------------- resolution

/// The prepend list v2rayN baked into the generated file (`P_file`).
///
/// 1. the newest history entry saved before the file was generated, if it is
///    a prefix of the file rules;
/// 2. else the saved list, if it is a prefix and Mixin.yaml is not newer than
///    the file;
/// 3. else the longest history entry that is a prefix;
/// 4. else unresolved. An empty list is a valid prefix.
pub(crate) fn resolve_baked(
    history: &[HistoryEntry],
    saved: &[String],
    saved_mtime: Option<u64>,
    file_mtime: u64,
    file_rules: &[String],
) -> Option<Vec<String>> {
    let limit = file_mtime.saturating_add(SLACK_MS);
    // max_by_key keeps the last of equal keys: later entries win ties.
    let newest_before = history
        .iter()
        .filter(|entry| entry.at <= limit)
        .max_by_key(|entry| entry.at);
    if let Some(entry) = newest_before {
        if is_prefix(&entry.rules, file_rules) {
            return Some(entry.rules.clone());
        }
    }
    if saved_mtime.is_some_and(|mtime| mtime <= limit) && is_prefix(saved, file_rules) {
        return Some(saved.to_vec());
    }
    history
        .iter()
        .filter(|entry| is_prefix(&entry.rules, file_rules))
        .max_by_key(|entry| (entry.rules.len(), entry.at))
        .map(|entry| entry.rules.clone())
}

/// `saved + file_rules[len(P_file)..]`, original strings.
pub(crate) fn expected_rules(
    saved: &[String],
    file_rules: &[String],
    baked_len: usize,
) -> Vec<String> {
    saved
        .iter()
        .chain(file_rules.iter().skip(baked_len))
        .cloned()
        .collect()
}

pub(crate) fn decide(runtime: &[NormalRule], expected: &[String]) -> RulesState {
    if runtime == normalized(expected).as_slice() {
        RulesState::Applied
    } else {
        RulesState::Pending
    }
}

// ---------------------------------------------------------------- generated config

/// The YAML mapping holds credentials: deliberately no `Debug`.
pub(crate) struct GeneratedConfig {
    /// Which candidate was chosen (read by tests).
    #[cfg_attr(not(test), allow(dead_code))]
    pub path: PathBuf,
    pub mtime: u64,
    root: Mapping,
}

fn scalar_string(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        _ => None,
    }
}

fn port_of(value: &Value) -> Option<u16> {
    scalar_string(value)?.trim().parse().ok()
}

pub(crate) fn parse_generated(raw: &[u8]) -> Option<Mapping> {
    let text = std::str::from_utf8(raw).ok()?;
    match serde_yaml::from_str(text.trim_start_matches('\u{feff}')).ok()? {
        Value::Mapping(root) => Some(root),
        _ => None,
    }
}

impl GeneratedConfig {
    pub(crate) fn from_root(path: PathBuf, mtime: u64, root: Mapping) -> Self {
        Self { path, mtime, root }
    }

    pub(crate) fn rules(&self) -> Result<Vec<String>> {
        let Some(rules) = self.root.get("rules") else {
            return Ok(Vec::new());
        };
        rules
            .as_sequence()
            .ok_or("В сгенерированном конфиге Mihomo rules не список.")?
            .iter()
            .map(|rule| {
                rule.as_str()
                    .map(str::to_owned)
                    .ok_or("В сгенерированном конфиге Mihomo есть нестроковые правила.".into())
            })
            .collect()
    }

    pub(crate) fn mixed_port(&self) -> Option<u16> {
        self.root.get("mixed-port").and_then(port_of)
    }

    /// Port of `external-controller` (`host:port`, host may be empty).
    pub(crate) fn controller_port(&self) -> Option<u16> {
        let address = scalar_string(self.root.get("external-controller")?)?;
        address.trim().rsplit_once(':')?.1.parse().ok()
    }

    pub(crate) fn secret(&self) -> Option<String> {
        self.root
            .get("secret")
            .and_then(scalar_string)
            .filter(|secret| !secret.is_empty())
    }

    fn tun(&self) -> Option<&Mapping> {
        self.root.get("tun")?.as_mapping()
    }

    pub(crate) fn tun_enable(&self) -> bool {
        self.tun()
            .and_then(|tun| tun.get("enable"))
            .and_then(Value::as_bool)
            .unwrap_or(false)
    }

    pub(crate) fn tun_device(&self) -> Option<String> {
        self.tun()
            .and_then(|tun| tun.get("device"))
            .and_then(scalar_string)
            .filter(|device| !device.is_empty())
    }

    fn matches(&self, proxy_port: u16) -> bool {
        self.controller_port() == proxy_port.checked_add(6) || self.mixed_port() == Some(proxy_port)
    }
}

/// Newest candidate that belongs to `proxy_port`.
pub(crate) fn pick_generated(
    candidates: Vec<GeneratedConfig>,
    proxy_port: u16,
) -> Option<GeneratedConfig> {
    candidates
        .into_iter()
        .filter(|candidate| candidate.matches(proxy_port))
        .max_by_key(|candidate| candidate.mtime)
}

pub(crate) fn load_generated(client_dir: &Path, proxy_port: u16) -> Result<GeneratedConfig> {
    let mut found = false;
    let mut candidates = Vec::new();
    for name in GENERATED {
        let path = client_dir.join(name);
        let Ok(raw) = fs::read(&path) else { continue };
        found = true;
        let (Some(root), Some(mtime)) = (parse_generated(&raw), history::file_mtime_ms(&path))
        else {
            continue;
        };
        candidates.push(GeneratedConfig::from_root(path, mtime, root));
    }
    if !found {
        return Err("Не найден сгенерированный конфиг Mihomo (binConfigs/config.json). Запусти профиль в v2rayN.".into());
    }
    pick_generated(candidates, proxy_port).ok_or_else(|| {
        format!("Сгенерированный конфиг Mihomo не распознан или не относится к порту {proxy_port}.")
    })
}

/// The generated mapping with ONLY `rules` replaced; key order and every other
/// value (including `tun:`) stay as parsed.
pub(crate) fn rebuild_payload(root: &Mapping, rules: &[String]) -> Result<String> {
    let mut next = root.clone();
    let slot = next
        .get_mut("rules")
        .ok_or("В сгенерированном конфиге Mihomo нет списка rules.")?;
    *slot = Value::Sequence(rules.iter().cloned().map(Value::String).collect());
    serde_yaml::to_string(&next).map_err(|_| "Не удалось собрать конфигурацию для Mihomo.".into())
}

/// Refuse to push a file that no longer describes the running core: a changed
/// port or TUN block would make Mihomo re-create the listener or the adapter.
pub(crate) fn stale_reason(
    file_mixed_port: Option<u16>,
    file_tun_enable: bool,
    file_tun_device: Option<&str>,
    runtime: &serde_json::Value,
) -> Option<String> {
    let runtime_port = runtime
        .get("mixed-port")
        .and_then(serde_json::Value::as_u64);
    if runtime_port != file_mixed_port.map(u64::from) {
        return Some("порт mixed-port отличается".into());
    }
    let tun = runtime.get("tun");
    let runtime_enable = tun
        .and_then(|tun| tun.get("enable"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    if runtime_enable != file_tun_enable {
        return Some("состояние TUN отличается".into());
    }
    // Without `device` in the file Mihomo picks the name itself and keeps the
    // file's (empty) value as its last TUN config, so only a named device can
    // be compared.
    if let Some(device) = file_tun_device {
        let runtime_device = tun
            .and_then(|tun| tun.get("device"))
            .and_then(serde_json::Value::as_str);
        if runtime_device != Some(device) {
            return Some("имя TUN-адаптера отличается".into());
        }
    }
    None
}

// ---------------------------------------------------------------- evaluation

struct Plan {
    port: u16,
    secret: Option<String>,
    generated: GeneratedConfig,
    expected: Vec<String>,
}

struct Evaluation {
    state: CoreRulesState,
    plan: Option<Plan>,
}

impl From<CoreRulesState> for Evaluation {
    fn from(state: CoreRulesState) -> Self {
        Self { state, plan: None }
    }
}

fn evaluate(settings: &Settings, history: &[HistoryEntry]) -> Evaluation {
    let client = match client_path(settings) {
        Ok(client) => client,
        Err(error) => return CoreRulesState::unknown(error).into(),
    };
    let Some(client_dir) = client.parent() else {
        return CoreRulesState::unknown("Папка v2rayN не найдена.").into();
    };
    let (mixin_path, _, mixin_root) = match mixin(settings) {
        Ok(found) => found,
        Err(error) => return CoreRulesState::unknown(error).into(),
    };
    let saved = match read_rules(&mixin_root) {
        Ok(saved) => saved,
        Err(error) => return CoreRulesState::unknown(error).into(),
    };
    match mixin_content_enabled_for(&mixin_path) {
        Ok(true) => {}
        Ok(false) => {
            return CoreRulesState::unknown(
                "В v2rayN выключен Enable Mixin Content: сохранённые правила не попадают в ядро.",
            )
            .into()
        }
        Err(error) => return CoreRulesState::unknown(error).into(),
    }
    let generated = load_generated(client_dir, settings.proxy_port);
    let fallback_port = settings.proxy_port.checked_add(6).unwrap_or(0);
    let port = generated
        .as_ref()
        .ok()
        .and_then(GeneratedConfig::controller_port)
        .unwrap_or(fallback_port);
    let secret = generated.as_ref().ok().and_then(GeneratedConfig::secret);
    let runtime = match http::get_json(port, "/rules", secret.as_deref()) {
        Ok(response) => match runtime_rules(&response) {
            Some(rules) => rules,
            None => return CoreRulesState::unknown(ControllerError::Invalid.message()).into(),
        },
        Err(error) => return CoreRulesState::unknown(error.message()).into(),
    };
    let generated = match generated {
        Ok(generated) => generated,
        Err(error) => return CoreRulesState::unknown(error).into(),
    };
    let file_rules = match generated.rules() {
        Ok(rules) => rules,
        Err(error) => return CoreRulesState::unknown(error).into(),
    };
    let Some(baked) = resolve_baked(
        history,
        &saved,
        history::file_mtime_ms(&mixin_path),
        generated.mtime,
        &file_rules,
    ) else {
        return CoreRulesState::unknown(
            "Не удалось понять, какие правила загружены в ядро: перезапусти ядро в v2rayN.",
        )
        .into();
    };
    let expected = expected_rules(&saved, &file_rules, baked.len());
    Evaluation {
        state: CoreRulesState::of(decide(&runtime, &expected)),
        plan: Some(Plan {
            port,
            secret,
            generated,
            expected,
        }),
    }
}

/// Read-only state for `core_rules_state` / `guardctl core state`.
pub(crate) fn state() -> Result<CoreRulesState> {
    Ok(evaluate(&load_settings()?, &history::load()).state)
}

fn reload_with(settings: &Settings, history: &[HistoryEntry]) -> Result<CoreRulesState> {
    let evaluation = evaluate(settings, history);
    let plan = match (evaluation.state.state, evaluation.plan) {
        (RulesState::Applied, _) => return Ok(evaluation.state),
        (RulesState::Pending, Some(plan)) => plan,
        _ => {
            return Err(format!(
                "Правила ядра сейчас не обновить. {}",
                evaluation.state.detail.unwrap_or_default()
            ))
        }
    };
    let runtime = http::get_json(plan.port, "/configs", plan.secret.as_deref())
        .map_err(|error| error.message())?;
    let device = plan.generated.tun_device();
    if let Some(reason) = stale_reason(
        plan.generated.mixed_port(),
        plan.generated.tun_enable(),
        device.as_deref(),
        &runtime,
    ) {
        return Err(format!(
            "Сгенерированный конфиг не совпадает с запущенным Mihomo ({reason}). Перезапусти ядро в v2rayN."
        ));
    }
    let payload = rebuild_payload(&plan.generated.root, &plan.expected)?;
    http::put_config_payload(plan.port, &payload, plan.secret.as_deref())
        .map_err(|error| format!("Mihomo не принял правила. {}.", error.message()))?;
    drop(payload);
    let after = evaluate(settings, history);
    if after.state.state == RulesState::Applied {
        Ok(after.state)
    } else {
        Err("Mihomo перезагрузил конфигурацию, но правила не совпали с сохранёнными. Перезапусти ядро в v2rayN.".into())
    }
}

/// Push the saved prepend-rules into the running Mihomo (`PUT /configs`,
/// no restart of v2rayN, no file written).
pub(crate) fn reload() -> Result<CoreRulesState> {
    let _guard = lock_config()?;
    let settings = load_settings()?;
    reload_with(&settings, &history::load())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{fake_controller, shared};

    fn v(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| (*item).to_owned()).collect()
    }

    fn entry(at: u64, rules: &[&str]) -> HistoryEntry {
        HistoryEntry {
            at,
            rules: v(rules),
        }
    }

    fn runtime(entries: &[(&str, &str, &str)]) -> Vec<NormalRule> {
        entries
            .iter()
            .map(|(kind, payload, proxy)| {
                normalize_runtime(
                    &serde_json::json!({"type": kind, "payload": payload, "proxy": proxy}),
                )
                .unwrap()
            })
            .collect()
    }

    // ------------------------------------------------ normalization

    #[test]
    fn config_and_runtime_names_meet() {
        for (config, kind, payload, proxy) in [
            (
                "DOMAIN-SUFFIX,Example.COM,Proxy",
                "DomainSuffix",
                "example.com",
                "proxy",
            ),
            (
                "IP-CIDR,1.2.3.0/24,DIRECT,no-resolve",
                "IPCIDR",
                "1.2.3.0/24",
                "DIRECT",
            ),
            ("IP-CIDR6,::1/128,DIRECT", "IPCIDR", "::1/128", "direct"),
            (
                "PROCESS-NAME,steam.exe,DIRECT",
                "ProcessName",
                "steam.exe",
                "DIRECT",
            ),
            ("GEOIP,RU,DIRECT", "GeoIP", "ru", "DIRECT"),
            (
                "SRC-IP-CIDR,10.0.0.0/8,DIRECT",
                "SrcIPCIDR",
                "10.0.0.0/8",
                "DIRECT",
            ),
            ("MATCH,Server-4", "Match", "", "server-4"),
        ] {
            assert_eq!(
                normalize_rule(config),
                runtime(&[(kind, payload, proxy)])[0],
                "{config}"
            );
        }
    }

    #[test]
    fn logical_rules_keep_inner_commas() {
        let rule = normalize_rule("AND,((DOMAIN,a.com),(NETWORK,UDP)),REJECT");
        assert_eq!(rule.kind, "AND");
        assert_eq!(rule.payload, "((domain,a.com),(network,udp))");
        assert_eq!(rule.target, "reject");
    }

    #[test]
    fn match_ignores_runtime_payload_and_trims() {
        assert_eq!(
            normalize_rule(" MATCH , DIRECT "),
            runtime(&[("Match", "ignored", "DIRECT")])[0]
        );
        assert_ne!(
            normalize_rule("DOMAIN,a.com,DIRECT"),
            normalize_rule("DOMAIN-SUFFIX,a.com,DIRECT")
        );
    }

    #[test]
    fn runtime_list_parsing() {
        let ok =
            serde_json::json!({"rules":[{"type":"Match","payload":"","proxy":"DIRECT","size":-1}]});
        assert_eq!(runtime_rules(&ok).unwrap().len(), 1);
        assert!(runtime_rules(&serde_json::json!({})).is_none());
        assert!(runtime_rules(&serde_json::json!({"rules":[{"type":1}]})).is_none());
    }

    #[test]
    fn prefix_is_normalized_and_empty_is_valid() {
        let full = v(&["DOMAIN-SUFFIX,a.com,DIRECT", "MATCH,Proxy"]);
        assert!(is_prefix(&[], &full));
        assert!(is_prefix(&v(&["domain-suffix,A.com,direct"]), &full));
        assert!(is_prefix(&full, &full));
        assert!(!is_prefix(&v(&["MATCH,Proxy"]), &full));
        assert!(!is_prefix(&v(&["a", "b", "c"]), &full));
    }

    // ------------------------------------------------ P_file resolution

    const FILE_AT: u64 = 1_000_000;

    #[test]
    fn newest_history_before_file_wins() {
        let file = v(&["DOMAIN-SUFFIX,old.com,DIRECT", "MATCH,Proxy"]);
        let history = [
            entry(10, &[]),
            entry(500, &["DOMAIN-SUFFIX,old.com,DIRECT"]),
            // saved later than the file: not what the file contains
            entry(FILE_AT + 60_000, &["DOMAIN-SUFFIX,new.com,DIRECT"]),
        ];
        let saved = v(&["DOMAIN-SUFFIX,new.com,DIRECT"]);
        assert_eq!(
            resolve_baked(&history, &saved, Some(FILE_AT + 60_000), FILE_AT, &file),
            Some(v(&["DOMAIN-SUFFIX,old.com,DIRECT"]))
        );
    }

    #[test]
    fn history_within_slack_counts_as_before() {
        let file = v(&["A,x,DIRECT", "MATCH,Proxy"]);
        let history = [entry(FILE_AT + SLACK_MS, &["A,x,DIRECT"])];
        assert_eq!(
            resolve_baked(&history, &[], None, FILE_AT, &file),
            Some(v(&["A,x,DIRECT"]))
        );
        let history = [entry(FILE_AT + SLACK_MS + 1, &["A,x,DIRECT"])];
        // Not "before", but still the longest prefix in history.
        assert_eq!(
            resolve_baked(&history, &[], None, FILE_AT, &file),
            Some(v(&["A,x,DIRECT"]))
        );
    }

    #[test]
    fn falls_back_to_saved_when_history_does_not_match() {
        let file = v(&["DOMAIN-SUFFIX,a.com,DIRECT", "MATCH,Proxy"]);
        let saved = v(&["DOMAIN-SUFFIX,a.com,DIRECT"]);
        assert_eq!(
            resolve_baked(&[], &saved, Some(FILE_AT - 1), FILE_AT, &file),
            Some(saved.clone())
        );
        // Newest-before entry exists but is not a prefix (edited by hand
        // while the panel was closed): saved still resolves.
        let history = [entry(5, &["DOMAIN-SUFFIX,other.com,DIRECT"])];
        assert_eq!(
            resolve_baked(&history, &saved, Some(FILE_AT), FILE_AT, &file),
            Some(saved.clone())
        );
        // Mixin newer than the file: saved is not trusted.
        assert_eq!(
            resolve_baked(&[], &saved, Some(FILE_AT + SLACK_MS + 1), FILE_AT, &file),
            None
        );
        assert_eq!(resolve_baked(&[], &saved, None, FILE_AT, &file), None);
    }

    #[test]
    fn longest_prefix_fallback() {
        let file = v(&["A,1,D", "A,2,D", "MATCH,P"]);
        let history = [
            entry(FILE_AT + 50_000, &["A,1,D"]),
            entry(FILE_AT + 60_000, &["A,1,D", "A,2,D"]),
            entry(FILE_AT + 70_000, &["A,9,D"]),
        ];
        assert_eq!(
            resolve_baked(
                &history,
                &v(&["A,9,D"]),
                Some(FILE_AT + 70_000),
                FILE_AT,
                &file
            ),
            Some(v(&["A,1,D", "A,2,D"]))
        );
    }

    #[test]
    fn unresolved_when_nothing_is_a_prefix() {
        let file = v(&["A,1,D", "MATCH,P"]);
        let history = [entry(1, &["B,1,D"]), entry(FILE_AT + 9_000, &["C,1,D"])];
        assert_eq!(
            resolve_baked(
                &history,
                &v(&["C,1,D"]),
                Some(FILE_AT + 9_000),
                FILE_AT,
                &file
            ),
            None
        );
        // ...but an empty entry in history always resolves.
        let history = [entry(1, &[]), entry(2, &["B,1,D"])];
        assert_eq!(
            resolve_baked(&history, &v(&["C,1,D"]), None, FILE_AT, &file),
            Some(Vec::new())
        );
    }

    // ------------------------------------------------ expected / decision

    #[test]
    fn expected_replaces_baked_prefix() {
        let file = v(&["OLD,1,D", "BASE,1,P", "MATCH,P"]);
        assert_eq!(
            expected_rules(&v(&["NEW,1,D", "NEW,2,D"]), &file, 1),
            v(&["NEW,1,D", "NEW,2,D", "BASE,1,P", "MATCH,P"])
        );
        assert_eq!(expected_rules(&[], &file, 0), file);
        assert_eq!(expected_rules(&v(&["X,1,D"]), &file, 3), v(&["X,1,D"]));
    }

    #[test]
    fn applied_pending_decision() {
        let expected = v(&["PROCESS-NAME,steam.exe,DIRECT", "MATCH,Server-4"]);
        let same = runtime(&[
            ("ProcessName", "steam.exe", "DIRECT"),
            ("Match", "", "Server-4"),
        ]);
        assert_eq!(decide(&same, &expected), RulesState::Applied);
        let older = runtime(&[("Match", "", "Server-4")]);
        assert_eq!(decide(&older, &expected), RulesState::Pending);
        let reordered = runtime(&[
            ("Match", "", "Server-4"),
            ("ProcessName", "steam.exe", "DIRECT"),
        ]);
        assert_eq!(decide(&reordered, &expected), RulesState::Pending);
        assert_eq!(decide(&[], &[]), RulesState::Applied);
    }

    #[test]
    fn state_serializes_contract_shape() {
        assert_eq!(
            serde_json::to_value(CoreRulesState::unknown("Mihomo не запущен")).unwrap(),
            serde_json::json!({"state": "unknown", "detail": "Mihomo не запущен"})
        );
        assert_eq!(
            serde_json::to_value(CoreRulesState::of(RulesState::Pending)).unwrap(),
            serde_json::json!({"state": "pending", "detail": null})
        );
    }

    // ------------------------------------------------ generated config + payload

    const GENERATED_YAML: &str = "mode: rule\r\nlog-level: warning\r\nallow-lan: false\r\nmixed-port: 18761\r\nipv6: true\r\ntun:\r\n  enable: true\r\n  stack: gvisor\r\n  device: TestTun\r\n  auto-route: true\r\n  inet6-address:\r\n  - fdfe:dcba:9876::1/126\r\n  dns-hijack:\r\n  - any:53\r\nproxies:\r\n- name: Server-4\r\n  type: wireguard\r\n  private-key: SECRET-KEY-DO-NOT-LOG\r\n  short-id: '0123'\r\nrules:\r\n- DOMAIN-SUFFIX,old.com,DIRECT\r\n- MATCH,Server-4\r\nfind-process-mode: strict\r\nexternal-controller: 127.0.0.1:18767\r\n";

    fn generated(raw: &str, mtime: u64) -> GeneratedConfig {
        GeneratedConfig::from_root(
            PathBuf::from("x"),
            mtime,
            parse_generated(raw.as_bytes()).unwrap(),
        )
    }

    #[test]
    fn reads_generated_fields() {
        let config = generated(GENERATED_YAML, 1);
        assert_eq!(
            config.rules().unwrap(),
            v(&["DOMAIN-SUFFIX,old.com,DIRECT", "MATCH,Server-4"])
        );
        assert_eq!(config.mixed_port(), Some(18761));
        assert_eq!(config.controller_port(), Some(18767));
        assert!(config.tun_enable());
        assert_eq!(config.tun_device().as_deref(), Some("TestTun"));
        assert_eq!(config.secret(), None);
        let with_secret = generated(&format!("{GENERATED_YAML}secret: abc\n"), 1);
        assert_eq!(with_secret.secret().as_deref(), Some("abc"));
        let numeric = generated("secret: 12345\nexternal-controller: ':9090'\n", 1);
        assert_eq!(numeric.secret().as_deref(), Some("12345"));
        assert_eq!(numeric.controller_port(), Some(9090));
        assert_eq!(generated("secret: ''\n", 1).secret(), None);
        let mut bom = vec![0xef, 0xbb, 0xbf];
        bom.extend_from_slice(b"rules: []\n");
        assert!(parse_generated(&bom).is_some());
        assert!(parse_generated(b"- a\n").is_none());
        assert!(parse_generated(&[0xff, 0xfe]).is_none());
    }

    #[test]
    fn picks_candidate_for_port() {
        let ours = generated("mixed-port: 100\nrules: []\n", 5);
        let by_controller = generated("external-controller: 127.0.0.1:106\n", 9);
        let other = generated("mixed-port: 200\nexternal-controller: 127.0.0.1:206\n", 99);
        let chosen = pick_generated(vec![ours, by_controller, other], 100).unwrap();
        assert_eq!(chosen.mtime, 9);
        assert!(pick_generated(vec![generated("mixed-port: 200\n", 1)], 100).is_none());
    }

    #[test]
    fn load_generated_reports_missing_and_foreign() {
        let dir = tempfile::tempdir().unwrap();
        let error = load_generated(dir.path(), 18761).err().unwrap();
        assert!(error.contains("Не найден"), "{error}");
        fs::create_dir_all(dir.path().join("binConfigs")).unwrap();
        fs::write(dir.path().join("binConfigs/config.json"), "mixed-port: 1\n").unwrap();
        let error = load_generated(dir.path(), 18761).err().unwrap();
        assert!(error.contains("18761"), "{error}");
        fs::write(dir.path().join("binConfigs/config.yaml"), GENERATED_YAML).unwrap();
        let chosen = load_generated(dir.path(), 18761).unwrap();
        assert!(chosen.path.ends_with("config.yaml"));
    }

    #[test]
    fn payload_replaces_only_rules() {
        let config = generated(GENERATED_YAML, 1);
        let expected = v(&[
            "DOMAIN-SUFFIX,new.com,DIRECT",
            "DOMAIN-SUFFIX,old.com,DIRECT",
            "MATCH,Server-4",
        ]);
        let payload = rebuild_payload(&config.root, &expected).unwrap();
        let rebuilt = parse_generated(payload.as_bytes()).unwrap();
        let keys = |root: &Mapping| -> Vec<String> {
            root.keys()
                .map(|key| key.as_str().unwrap().to_owned())
                .collect()
        };
        assert_eq!(keys(&rebuilt), keys(&config.root));
        for (key, value) in config.root.iter() {
            if key.as_str() == Some("rules") {
                assert_eq!(
                    rebuilt.get(key).unwrap(),
                    &Value::Sequence(expected.iter().cloned().map(Value::String).collect())
                );
            } else {
                assert_eq!(rebuilt.get(key), Some(value), "{key:?}");
            }
        }
        // Quoted numeric-looking strings stay strings.
        let proxies = rebuilt.get("proxies").unwrap().as_sequence().unwrap();
        assert_eq!(
            proxies[0].get("short-id"),
            Some(&Value::String("0123".into()))
        );
        assert!(rebuild_payload(&generated("mode: rule\n", 1).root, &expected).is_err());
    }

    #[test]
    fn stale_file_is_detected() {
        let runtime =
            serde_json::json!({"mixed-port": 18761, "tun": {"enable": true, "device": "TestTun"}});
        assert_eq!(
            stale_reason(Some(18761), true, Some("TestTun"), &runtime),
            None
        );
        assert!(stale_reason(Some(18762), true, Some("TestTun"), &runtime).is_some());
        assert!(stale_reason(Some(18761), false, Some("TestTun"), &runtime).is_some());
        assert!(stale_reason(Some(18761), true, Some("Other"), &runtime).is_some());
        // No device in the file: Mihomo named it itself ("Meta").
        let auto =
            serde_json::json!({"mixed-port": 18761, "tun": {"enable": true, "device": "Meta"}});
        assert_eq!(stale_reason(Some(18761), true, None, &auto), None);
        assert!(stale_reason(None, true, None, &auto).is_some());
    }

    // ------------------------------------------------ end-to-end with a fake controller

    struct Fixture {
        _dir: tempfile::TempDir,
        settings: Settings,
    }

    fn fixture(controller_port: u16, saved: &[&str], mixin_enabled: bool) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let client = dir.path().join(if cfg!(windows) {
            "v2rayN.exe"
        } else {
            "v2rayN"
        });
        fs::write(&client, b"").unwrap();
        fs::create_dir_all(dir.path().join("guiConfigs")).unwrap();
        fs::create_dir_all(dir.path().join("binConfigs")).unwrap();
        let mut mixin = String::from("prepend-rules:\n");
        for rule in saved {
            mixin.push_str(&format!("- {rule}\n"));
        }
        fs::write(dir.path().join("guiConfigs/Mixin.yaml"), mixin).unwrap();
        fs::write(
            dir.path().join("guiConfigs/guiNConfig.json"),
            format!(r#"{{"ClashUIItem":{{"EnableMixinContent":{mixin_enabled}}}}}"#),
        )
        .unwrap();
        let generated = GENERATED_YAML.replace("18767", &controller_port.to_string());
        fs::write(dir.path().join("binConfigs/config.json"), generated).unwrap();
        Fixture {
            settings: Settings {
                client_path: client.to_string_lossy().into_owned(),
                adapter: "TestTun".into(),
                proxy_port: 18761,
            },
            _dir: dir,
        }
    }

    fn rules_json(rules: &[(&str, &str, &str)]) -> String {
        let rules: Vec<_> = rules
            .iter()
            .map(|(kind, payload, proxy)| serde_json::json!({"type": kind, "payload": payload, "proxy": proxy, "size": -1}))
            .collect();
        serde_json::json!({ "rules": rules }).to_string()
    }

    const OLD_RUNTIME: &[(&str, &str, &str)] = &[
        ("DomainSuffix", "old.com", "DIRECT"),
        ("Match", "", "Server-4"),
    ];
    const NEW_RUNTIME: &[(&str, &str, &str)] = &[
        ("DomainSuffix", "new.com", "DIRECT"),
        ("Match", "", "Server-4"),
    ];

    #[test]
    fn unreachable_controller_is_unknown() {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let fx = fixture(port, &["DOMAIN-SUFFIX,old.com,DIRECT"], true);
        let state = evaluate(&fx.settings, &[]).state;
        assert_eq!(state, CoreRulesState::unknown("Mihomo не запущен"));
    }

    #[test]
    fn mixin_disabled_is_unknown_without_network() {
        let fx = fixture(1, &["DOMAIN-SUFFIX,old.com,DIRECT"], false);
        let state = evaluate(&fx.settings, &[]).state;
        assert_eq!(state.state, RulesState::Unknown);
        assert!(state.detail.unwrap().contains("Mixin"));
    }

    #[test]
    fn applied_when_runtime_matches_saved() {
        let (port, server) = fake_controller(1, |_, _, _| (200, rules_json(OLD_RUNTIME)));
        let fx = fixture(port, &["DOMAIN-SUFFIX,old.com,DIRECT"], true);
        assert_eq!(
            evaluate(&fx.settings, &[]).state,
            CoreRulesState::of(RulesState::Applied)
        );
        let seen = server.join().unwrap();
        assert_eq!(
            (seen[0].method.as_str(), seen[0].path.as_str()),
            ("GET", "/rules")
        );
    }

    #[test]
    fn edited_after_generation_is_pending_then_unresolved_without_history() {
        // Saved list differs from the baked one; the history knows the old list.
        let (port, server) = fake_controller(2, |_, _, _| (200, rules_json(OLD_RUNTIME)));
        let fx = fixture(port, &["DOMAIN-SUFFIX,new.com,DIRECT"], true);
        let history = [entry(1, &["DOMAIN-SUFFIX,old.com,DIRECT"])];
        assert_eq!(
            evaluate(&fx.settings, &history).state.state,
            RulesState::Pending
        );
        // Without history and with Mixin not older than the file, saved is
        // not a prefix of the file -> unknown.
        let state = evaluate(&fx.settings, &[]).state;
        assert_eq!(state.state, RulesState::Unknown);
        assert!(state.detail.unwrap().contains("перезапусти ядро"));
        server.join().unwrap();
    }

    #[test]
    fn reload_pushes_only_rules_and_verifies() {
        let applied = shared(false);
        let flag = applied.clone();
        let (port, server) = fake_controller(4, move |method, path, _| match (method, path) {
            ("GET", "/rules") => {
                let done = *flag.lock().unwrap();
                (
                    200,
                    rules_json(if done { NEW_RUNTIME } else { OLD_RUNTIME }),
                )
            }
            ("GET", "/configs") => (
                200,
                r#"{"mode":"rule","mixed-port":18761,"tun":{"enable":true,"device":"TestTun"}}"#
                    .into(),
            ),
            ("PUT", "/configs") => {
                *flag.lock().unwrap() = true;
                (204, String::new())
            }
            _ => (404, String::new()),
        });
        let fx = fixture(port, &["DOMAIN-SUFFIX,new.com,DIRECT"], true);
        let history = [entry(1, &["DOMAIN-SUFFIX,old.com,DIRECT"])];
        assert_eq!(
            reload_with(&fx.settings, &history).unwrap(),
            CoreRulesState::of(RulesState::Applied)
        );
        let seen = server.join().unwrap();
        let calls: Vec<_> = seen
            .iter()
            .map(|r| format!("{} {}", r.method, r.path))
            .collect();
        assert_eq!(
            calls,
            ["GET /rules", "GET /configs", "PUT /configs", "GET /rules"]
        );
        let put = &seen[2];
        assert!(!put.headers.iter().any(|(name, _)| name == "authorization"));
        let body: serde_json::Value = serde_json::from_str(&put.body).unwrap();
        assert_eq!(body["path"], "");
        let sent = parse_generated(body["payload"].as_str().unwrap().as_bytes()).unwrap();
        let original = parse_generated(
            GENERATED_YAML
                .replace("18767", &port.to_string())
                .as_bytes(),
        )
        .unwrap();
        assert_eq!(
            sent.get("rules").unwrap(),
            &Value::Sequence(
                v(&["DOMAIN-SUFFIX,new.com,DIRECT", "MATCH,Server-4"])
                    .into_iter()
                    .map(Value::String)
                    .collect()
            )
        );
        assert_eq!(sent.get("tun"), original.get("tun"));
        assert_eq!(sent.get("proxies"), original.get("proxies"));
    }

    #[test]
    fn reload_refuses_stale_file_and_unknown_state() {
        let (port, server) = fake_controller(2, |_, path, _| match path {
            "/rules" => (200, rules_json(OLD_RUNTIME)),
            _ => (
                200,
                r#"{"mixed-port":18761,"tun":{"enable":true,"device":"Renamed"}}"#.into(),
            ),
        });
        let fx = fixture(port, &["DOMAIN-SUFFIX,new.com,DIRECT"], true);
        let history = [entry(1, &["DOMAIN-SUFFIX,old.com,DIRECT"])];
        let error = reload_with(&fx.settings, &history).unwrap_err();
        assert!(error.contains("имя TUN-адаптера"), "{error}");
        server.join().unwrap();

        let fx = fixture(1, &["DOMAIN-SUFFIX,new.com,DIRECT"], false);
        assert!(reload_with(&fx.settings, &[])
            .unwrap_err()
            .contains("Mixin"));
    }

    #[test]
    fn reload_is_a_no_op_when_applied() {
        let (port, server) = fake_controller(1, |_, _, _| (200, rules_json(OLD_RUNTIME)));
        let fx = fixture(port, &["DOMAIN-SUFFIX,old.com,DIRECT"], true);
        assert_eq!(
            reload_with(&fx.settings, &[]).unwrap().state,
            RulesState::Applied
        );
        assert_eq!(server.join().unwrap().len(), 1);
    }
}
