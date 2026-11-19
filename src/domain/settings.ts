import type { GuardState, Settings } from "../api/types";

export const defaultSettings: Settings = { client_path: "", adapter: "Mihomo", proxy_port: 10808 };

/**
 * The backend reads the controller port from v2rayN's generated Mihomo config and falls back to
 * proxy port + 6 (v2rayN's TUN-mode layout), so the proxy port has to leave room for that.
 */
export const CONTROLLER_OFFSET = 6;
export const MAX_PROXY_PORT = 65535 - CONTROLLER_OFFSET;

export type SettingsProblems = Partial<Record<keyof Settings, string>>;

export function settingsProblems(settings: Settings): SettingsProblems {
  const problems: SettingsProblems = {};
  const path = settings.client_path.trim();
  if (!path) problems.client_path = "Укажи путь к v2rayN.exe.";
  else if (!/(^|[\\/])v2rayN\.exe$/i.test(path))
    problems.client_path = "Путь должен заканчиваться на v2rayN.exe.";
  const adapter = settings.adapter.trim();
  if (!adapter) problems.adapter = "Укажи имя адаптера, например Meta.";
  else if (/[*?]/.test(adapter)) problems.adapter = "Нужно точное имя адаптера, без * и ?.";
  const port = settings.proxy_port;
  if (!Number.isInteger(port) || port < 1 || port > MAX_PROXY_PORT) {
    problems.proxy_port = `Порт — целое число от 1 до ${MAX_PROXY_PORT}.`;
  }
  return problems;
}

/** Mirrors the backend: settings can change only while protection is off. */
export function settingsEditable(state: GuardState | undefined) {
  return state === "Off" || state === "LegacyInactive";
}

export function sameSettings(left: Settings, right: Settings) {
  return (
    left.client_path === right.client_path &&
    left.adapter === right.adapter &&
    left.proxy_port === right.proxy_port
  );
}
