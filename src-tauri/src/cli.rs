use crate::backend::{
    active_rules, apply_protection_headless, config_snapshot, edit_rules, edit_settings,
    load_rules, load_settings, open_client, read_status, read_vpn_targets, upsert_rule, Action,
    ConfigSnapshot, Result, DIRECT_DEFAULT,
};
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde_json::{json, Value};
use std::{fs, path::PathBuf};

#[derive(Parser)]
#[command(
    name = "guardctl",
    version,
    about = "Local, JSON command interface for Tunnel Guard"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Read the current firewall and TUN state.
    Status,
    /// Export the settings and saved bypass rules as one JSON object.
    Config,
    /// Read or update the v2rayN connection settings.
    Settings {
        #[command(subcommand)]
        command: SettingsCommand,
    },
    /// Read or update saved bypass rules.
    Rules {
        #[command(subcommand)]
        command: RulesCommand,
    },
    /// Modify the Windows kill switch from an administrator console.
    Protection {
        #[command(subcommand)]
        command: ProtectionCommand,
    },
    /// Configure, inspect or stop a group of local processes.
    Processes {
        #[command(subcommand)]
        command: ProcessCommand,
    },
    /// Start the configured v2rayN executable.
    StartClient,
}

#[derive(Subcommand)]
enum SettingsCommand {
    Get,
    Set {
        #[arg(long)]
        client_path: Option<String>,
        #[arg(long)]
        adapter: Option<String>,
        #[arg(long)]
        proxy_port: Option<u16>,
    },
}

#[derive(Subcommand)]
enum ProcessCommand {
    List,
    Set {
        #[arg(long)]
        file: PathBuf,
        /// JSON output of "guardctl processes list" before the edit.
        #[arg(long)]
        expected: PathBuf,
    },
    Preview {
        group: String,
    },
    Stop {
        group: String,
        #[arg(long, required = true)]
        confirm: bool,
    },
}

#[derive(Subcommand)]
enum RulesCommand {
    List,
    /// Read the rules actually loaded by the running Mihomo controller.
    Active,
    /// List available non-direct destinations in Mihomo.
    Targets,
    /// Set the route for traffic outside the explicit rules.
    Mode {
        #[arg(value_enum)]
        value: RoutingMode,
    },
    Add {
        #[command(flatten)]
        rule: Rule,
        /// Use DIRECT or the name shown by "rules targets".
        #[arg(long, default_value = "DIRECT")]
        via: String,
    },
    Remove(Rule),
    /// Replace the saved list from a JSON array of rule strings.
    Replace {
        #[arg(long)]
        file: PathBuf,
        /// JSON output of "guardctl config" before the edit.
        #[arg(long)]
        expected: PathBuf,
    },
}

#[derive(Clone, ValueEnum)]
enum RoutingMode {
    Profile,
    VpnOnly,
}

#[derive(Args)]
struct Rule {
    #[arg(value_enum)]
    kind: RuleKind,
    value: String,
}

#[derive(Clone, ValueEnum)]
enum RuleKind {
    Domain,
    ProcessName,
    ProcessPath,
}

impl Rule {
    fn prefix(&self) -> String {
        let kind = match self.kind {
            RuleKind::Domain => "DOMAIN-SUFFIX",
            RuleKind::ProcessName => "PROCESS-NAME",
            RuleKind::ProcessPath => "PROCESS-PATH",
        };
        format!("{kind},{},", self.value.trim())
    }
}

#[derive(Subcommand)]
enum ProtectionCommand {
    Enable,
    Disable {
        /// Acknowledge that direct internet access can resume after disabling.
        #[arg(long, required = true)]
        confirm: bool,
    },
    CleanLegacy,
}

fn json_file<T: serde::de::DeserializeOwned>(path: PathBuf) -> Result<T> {
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    let body = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(&bytes);
    serde_json::from_slice(body).map_err(|_| "Проверь формат входного файла JSON UTF-8.".into())
}

fn execute(command: Command) -> Result<Value> {
    match command {
        Command::Status => Ok(json!({ "status": read_status()? })),
        Command::Config => Ok(json!({ "config": config_snapshot()? })),
        Command::Settings { command } => {
            let settings = match command {
                SettingsCommand::Get => load_settings()?,
                SettingsCommand::Set {
                    client_path,
                    adapter,
                    proxy_port,
                } => {
                    if client_path.is_none() && adapter.is_none() && proxy_port.is_none() {
                        return Err("Укажи хотя бы одно поле подключения.".into());
                    }
                    edit_settings(None, |mut current| {
                        if let Some(value) = client_path {
                            current.client_path = value;
                        }
                        if let Some(value) = adapter {
                            current.adapter = value;
                        }
                        if let Some(value) = proxy_port {
                            current.proxy_port = value;
                        }
                        current
                    })?
                }
            };
            Ok(json!({ "settings": settings }))
        }
        Command::Rules { command } => {
            let rules = match command {
                RulesCommand::List => load_rules()?,
                RulesCommand::Active => return active_rules(),
                RulesCommand::Targets => return Ok(json!({ "targets": read_vpn_targets()? })),
                RulesCommand::Mode { value } => edit_rules(None, None, |mut rules| {
                    rules.retain(|rule| rule != DIRECT_DEFAULT);
                    if matches!(value, RoutingMode::VpnOnly) {
                        rules.push(DIRECT_DEFAULT.into());
                    }
                    rules
                })?,
                RulesCommand::Add { rule, via } => {
                    let entry = format!("{}{via}", rule.prefix());
                    edit_rules(None, None, |rules| upsert_rule(rules, entry))?
                }
                RulesCommand::Remove(rule) => edit_rules(None, None, |mut rules| {
                    let prefix = rule.prefix();
                    rules.retain(|rule| !rule.starts_with(&prefix));
                    rules
                })?,
                RulesCommand::Replace { file, expected } => {
                    #[derive(serde::Deserialize)]
                    struct Expected {
                        config: ConfigSnapshot,
                    }
                    let next = json_file(file)?;
                    let expected: Expected = json_file(expected)?;
                    let old = expected
                        .config
                        .rules
                        .ok_or("В исходном снимке нет списка правил.")?;
                    edit_rules(Some(expected.config.settings), Some(old), |_| next)?
                }
            };
            let mode = if rules.last().is_some_and(|rule| rule == DIRECT_DEFAULT) {
                "vpn-only"
            } else {
                "profile"
            };
            Ok(json!({ "rules": rules, "mode": mode }))
        }
        Command::Protection { command } => {
            let action = match command {
                ProtectionCommand::Enable => Action::Enable,
                ProtectionCommand::Disable { confirm: true } => Action::Disable,
                ProtectionCommand::Disable { confirm: false } => {
                    return Err("Требуется --confirm.".into())
                }
                ProtectionCommand::CleanLegacy => Action::CleanLegacy,
            };
            Ok(json!({ "status": apply_protection_headless(action)? }))
        }
        Command::Processes { command } => {
            use crate::process_groups::{
                execute, load_process_groups, save_process_groups, Groups,
            };
            match command {
                ProcessCommand::List => Ok(json!({ "config": load_process_groups()? })),
                ProcessCommand::Set { file, expected } => {
                    #[derive(serde::Deserialize)]
                    struct Expected {
                        config: Groups,
                    }
                    let replacement: Groups = json_file(file)?;
                    let expected: Expected = json_file(expected)?;
                    save_process_groups(replacement.clone(), expected.config)?;
                    Ok(json!({ "config": replacement }))
                }
                ProcessCommand::Preview { group } => {
                    Ok(json!({ "result": execute(&group, false)? }))
                }
                ProcessCommand::Stop {
                    group,
                    confirm: true,
                } => {
                    let result = execute(&group, true)?;
                    if result.get("complete").and_then(Value::as_bool) != Some(true) {
                        return Ok(json!({ "result": result, "partial": true }));
                    }
                    Ok(json!({ "result": result }))
                }
                ProcessCommand::Stop { confirm: false, .. } => Err("Требуется --confirm.".into()),
            }
        }
        Command::StartClient => {
            open_client()?;
            Ok(json!({ "started": true }))
        }
    }
}

pub fn run() -> i32 {
    match execute(Cli::parse().command) {
        Ok(mut data) => {
            let complete = data.get("partial").and_then(Value::as_bool) != Some(true);
            data["ok"] = Value::Bool(complete);
            println!("{data}");
            if complete {
                0
            } else {
                2
            }
        }
        Err(error) => {
            println!("{}", json!({ "ok": false, "error": error }));
            1
        }
    }
}
