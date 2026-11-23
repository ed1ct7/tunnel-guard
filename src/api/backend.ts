import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type {
  ClientDetection,
  Command,
  CommandMap,
  ConfigSnapshot,
  CoreRulesState,
  Diagnosis,
  EventMap,
  Outcome,
  ProcessGroupsConfig,
  ProtectionAction,
  Settings,
  Status,
} from "./types";

/** Minimal surface shared by the real Tauri bridge and the browser mock. */
export type Transport = {
  invoke(command: string, args?: Record<string, unknown>): Promise<unknown>;
  listen(event: string, handler: (payload: unknown) => void): Promise<() => void>;
};

export const insideTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

const tauriTransport: Transport = {
  invoke: (command, args) => invoke(command, args),
  listen: (event, handler) => listen(event, (message) => handler(message.payload)),
};

const unavailableTransport: Transport = {
  invoke: () =>
    Promise.reject(new Error("Tunnel Guard открыт вне приложения: системные функции недоступны.")),
  listen: () => Promise.resolve(() => undefined),
};

let transport: Promise<Transport> | undefined;

async function loadTransport(): Promise<Transport> {
  if (insideTauri) return tauriTransport;
  // Both conditions are replaced with literals at build time, so the mock and its chunk are
  // dropped from the production bundle. `vite build --mode mock` keeps them for a browser demo.
  if (import.meta.env.DEV || import.meta.env.MODE === "mock") {
    const { createMockTransport } = await import("./mock");
    return createMockTransport();
  }
  return unavailableTransport;
}

function getTransport() {
  transport ??= loadTransport();
  return transport;
}

/** Turns whatever a command rejected with (Tauri rejects with a plain string) into readable text. */
export function errorText(error: unknown): string {
  if (typeof error === "string") return error;
  if (error instanceof Error) return error.message;
  if (error && typeof error === "object" && "message" in error && typeof error.message === "string") {
    return error.message;
  }
  try {
    return JSON.stringify(error);
  } catch {
    return String(error);
  }
}

type ArgsOf<C extends Command> = CommandMap[C]["args"] extends undefined ? [] : [CommandMap[C]["args"]];

export async function call<C extends Command>(
  command: C,
  ...args: ArgsOf<C>
): Promise<CommandMap[C]["result"]> {
  const bridge = await getTransport();
  try {
    return (await bridge.invoke(command, args[0])) as CommandMap[C]["result"];
  } catch (error) {
    throw new Error(errorText(error), { cause: error });
  }
}

/** Subscribes to a backend event. Returns a synchronous unsubscribe that is safe to call at any time. */
export function onEvent<E extends keyof EventMap>(
  name: E,
  handler: (payload: EventMap[E]) => void,
): () => void {
  let disposed = false;
  let unlisten: (() => void) | undefined;
  getTransport()
    .then((bridge) => bridge.listen(name, (payload) => handler(payload as EventMap[E])))
    .then((stop) => {
      if (disposed) stop();
      else unlisten = stop;
    })
    .catch(() => undefined);
  return () => {
    disposed = true;
    unlisten?.();
  };
}

/** Like `onEvent`, but resolves only once the listener is registered (use before starting an operation). */
export async function subscribe<E extends keyof EventMap>(
  name: E,
  handler: (payload: EventMap[E]) => void,
): Promise<() => void> {
  const bridge = await getTransport();
  return bridge.listen(name, (payload) => handler(payload as EventMap[E]));
}

export const api = {
  loadSettings: () => call("load_settings"),
  saveSettings: (settings: Settings, original: Settings) => call("save_settings", { settings, original }),
  configSnapshot: (): Promise<ConfigSnapshot> => call("config_snapshot"),
  recoverRoutingDraft: () => call("recover_routing_draft"),
  loadRules: () => call("load_rules"),
  saveRules: (rules: string[], original: string[], settings: Settings) =>
    call("save_rules", { rules, original, settings }),
  vpnTargets: () => call("vpn_targets"),
  pickExe: () => call("pick_exe"),
  openClient: () => call("open_client"),
  loadProcessGroups: (): Promise<ProcessGroupsConfig> => call("load_process_groups"),
  saveProcessGroups: (config: ProcessGroupsConfig, original: ProcessGroupsConfig) =>
    call("save_process_groups", { config, original }),
  runProcessGroup: (id: string, stop: boolean, original: ProcessGroupsConfig): Promise<Outcome> =>
    call("run_process_group", { id, stop, original }),
  processNetworkStates: () => call("process_network_states"),
  setProcessNetwork: (id: string, blocked: boolean, original: ProcessGroupsConfig) =>
    call("set_process_network", { id, blocked, original }),
  changeProtection: (action: ProtectionAction) => call("change_protection", { action }),
  guardStatus: (): Promise<Status> => call("guard_status"),
  diagnose: (): Promise<Diagnosis> => call("diagnose"),
  coreRulesState: (): Promise<CoreRulesState> => call("core_rules_state"),
  reloadCore: (): Promise<CoreRulesState> => call("reload_core"),
  detectClient: (): Promise<ClientDetection> => call("detect_client"),
  setWindowVisible: (visible: boolean) => call("set_window_visible", { visible }),
};
