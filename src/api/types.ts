// Field names are snake_case on purpose:
// they mirror the JSON that the Rust side serialises. Keep in sync with contract.md.

export type GuardState =
  "On" | "Off" | "Partial" | "LegacyActive" | "LegacyInactive" | "Unsupported" | "Unknown";

export type ProtectionBackend = "group_policy" | "wfp";

/** Why an active guard may not hold as expected; absent when there is none. */
export type StatusWarning = "core_routing" | "foreign_hard_permit" | "outdated_policy";

export type Status = {
  state: GuardState;
  adapter_up: boolean;
  active_backend?: ProtectionBackend;
  /** Unix time in ms of the read that produced this status. */
  checked_at: number;
  warnings?: StatusWarning[];
};

export type Settings = {
  client_path: string;
  adapter: string;
  proxy_port: number;
  protection_backend: ProtectionBackend;
};
export type ConfigSnapshot = { settings: Settings; rules: string[] | null };

export type CheckId =
  "client" | "core" | "mixin" | "client_running" | "proxy" | "controller" | "adapter" | "tun" | "mode";

/** `skip` means the check could not run because a prerequisite failed. */
export type CheckStatus = "ok" | "fail" | "warn" | "skip";
export type Check = { id: CheckId; status: CheckStatus; detail: string | null };

export type ProxyGroup = { name: string; kind: string; now: string | null };
export type CoreInfo = {
  version: string | null;
  mode: string | null;
  tun_enabled: boolean;
  tun_device: string | null;
  groups: ProxyGroup[];
};

export type Diagnosis = {
  checks: Check[];
  /** Every check except `mixin` and `client_running` is `ok`. */
  ready: boolean;
  /** `null` when the Mihomo controller is unreachable. */
  core: CoreInfo | null;
  checked_at: number;
};

export type CoreRulesState = {
  state: "applied" | "pending" | "unknown";
  detail: string | null;
};

export type ProtectionAction = "enable" | "disable" | "clean_legacy";

export type ProgressStage =
  | "preflight"
  | "elevate"
  | "settings"
  | "tun"
  | "egress"
  | "backup"
  | "apply"
  | "policy"
  | "verify"
  | "restore"
  | "cleanup"
  | "done"
  | "failed";

export type Progress = { action: ProtectionAction; stage: ProgressStage; at: number };

export type ClientDetection = {
  settings: Settings | null;
  /** Other v2rayN.exe paths that were found. */
  candidates: string[];
  note: string | null;
};

// Process groups (unchanged from 0.4).
export type SelectorKind = "name" | "path" | "package_family" | "argument" | "service";
export type Selector = { kind: SelectorKind; value: string; image?: string };
export type ProcessGroup = {
  id: string;
  title: string;
  selectors: Selector[];
  includes: string[];
};
export type ProcessGroupsConfig = { groups: ProcessGroup[] };
export type ProcessNetworkState = "off" | "blocked" | "partial";
export type ProcessInfo = { pid: number; name: string; owned: boolean };
export type ServiceOutcome = { name: string; status: string; error?: string | null };
export type Outcome = {
  matched: ProcessInfo[];
  caller_in_group?: boolean;
  stopped?: ProcessInfo[];
  remaining?: ProcessInfo[];
  complete?: boolean;
  services: ServiceOutcome[];
};

/** Payloads of the events the backend emits. */
export type EventMap = {
  "guard-state": Status;
  "guard-config": ConfigSnapshot;
  "guard-progress": Progress;
};

/** Argument shape of every backend command, keyed by command name. */
export type CommandMap = {
  load_settings: { args: undefined; result: Settings };
  save_settings: { args: { settings: Settings; original: Settings }; result: null };
  config_snapshot: { args: undefined; result: ConfigSnapshot };
  recover_routing_draft: { args: undefined; result: string[] | null };
  load_rules: { args: undefined; result: string[] };
  save_rules: { args: { rules: string[]; original: string[]; settings: Settings }; result: null };
  vpn_targets: { args: undefined; result: string[] };
  pick_exe: { args: undefined; result: string | null };
  open_client: { args: undefined; result: null };
  load_process_groups: { args: undefined; result: ProcessGroupsConfig };
  save_process_groups: { args: { config: ProcessGroupsConfig; original: ProcessGroupsConfig }; result: null };
  run_process_group: { args: { id: string; stop: boolean; original: ProcessGroupsConfig }; result: Outcome };
  process_network_states: { args: undefined; result: Record<string, ProcessNetworkState> };
  set_process_network: {
    args: { id: string; blocked: boolean; original: ProcessGroupsConfig };
    result: null;
  };
  change_protection: { args: { action: ProtectionAction }; result: null };
  guard_status: { args: undefined; result: Status };
  diagnose: { args: undefined; result: Diagnosis };
  core_rules_state: { args: undefined; result: CoreRulesState };
  reload_core: { args: undefined; result: CoreRulesState };
  detect_client: { args: undefined; result: ClientDetection };
  set_window_visible: { args: { visible: boolean }; result: null };
};

export type Command = keyof CommandMap;
