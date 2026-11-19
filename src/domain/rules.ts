// Pure helpers for the Mihomo prepend-rules list. Semantics match 0.4 and the Rust side:
// a trailing `MATCH,DIRECT` switches on "only selected through VPN", new rules go before it,
// and a rule with the same kind + value (case-insensitive) is replaced instead of duplicated.

export const DIRECT_DEFAULT = "MATCH,DIRECT";

export type RuleKindCode = "DOMAIN-SUFFIX" | "PROCESS-NAME" | "PROCESS-PATH";

export const ruleKinds: ReadonlyArray<{ code: RuleKindCode; label: string; example: string }> = [
  { code: "DOMAIN-SUFFIX", label: "Домен", example: "example.org" },
  { code: "PROCESS-NAME", label: "Имя процесса", example: "program.exe" },
  { code: "PROCESS-PATH", label: "Путь к программе", example: "C:\\Folder\\program.exe" },
];

export type RouteKind = "vpn" | "direct" | "reject";

export type RuleView = { kind: string; target: string; route: string; routeKind: RouteKind };

export function isVpnOnly(rules: readonly string[]) {
  return rules.at(-1) === DIRECT_DEFAULT;
}

export function routeKind(route: string): RouteKind {
  return route === "DIRECT" ? "direct" : route === "REJECT" ? "reject" : "vpn";
}

export function routeLabel(route: string) {
  return route === "DIRECT" ? "Напрямую" : route === "REJECT" ? "Блокировать" : `VPN: ${route}`;
}

export function displayRule(rule: string): RuleView {
  const [type = "", ...parts] = rule.split(",");
  const route = parts.pop() ?? "";
  const kind = ruleKinds.find((entry) => entry.code === type);
  return {
    kind: kind?.label ?? type,
    target: parts.join(",") || rule,
    route: routeLabel(route),
    routeKind: routeKind(route),
  };
}

function rulePrefix(kind: RuleKindCode, value: string) {
  return [kind, value, ""].join(",");
}

/** Index of the rule with the same kind and value, or -1. */
export function findRule(rules: readonly string[], kind: RuleKindCode, value: string) {
  const prefix = rulePrefix(kind, value).toLowerCase();
  return rules.findIndex((entry) => entry.toLowerCase().startsWith(prefix));
}

export function upsertRule(
  rules: readonly string[],
  kind: RuleKindCode,
  value: string,
  route: string,
): string[] {
  const updated = [...rules];
  const rule = rulePrefix(kind, value) + route;
  const previous = findRule(updated, kind, value);
  if (previous >= 0) updated[previous] = rule;
  else updated.splice(isVpnOnly(updated) ? updated.length - 1 : updated.length, 0, rule);
  return updated;
}

export function withMode(rules: readonly string[], onlySelected: boolean): string[] {
  const explicit = rules.filter((rule) => rule !== DIRECT_DEFAULT);
  return onlySelected ? [...explicit, DIRECT_DEFAULT] : explicit;
}

/** Client-side hint for a rule value. Never stricter than the backend check. */
export function ruleValueProblem(kind: RuleKindCode, raw: string): string | null {
  const value = raw.trim();
  if (!value) return "Укажи домен или программу.";
  if (value.includes(",")) return "Укажи один домен или процесс — без запятых.";
  switch (kind) {
    case "DOMAIN-SUFFIX":
      if (/[\s/:*]/.test(value) || !value.includes(".")) {
        return "Нужен домен без https://, пути и звёздочек, например example.org.";
      }
      return null;
    case "PROCESS-NAME":
      if (!value.toLowerCase().endsWith(".exe") || /[\\/:*?<>"|]/.test(value)) {
        return "Нужно только имя файла с .exe, например program.exe.";
      }
      return null;
    case "PROCESS-PATH":
      if (!value.toLowerCase().endsWith(".exe") || !/^(?:[a-z]:\\|\\\\)/i.test(value)) {
        return "Нужен полный путь к .exe, например C:\\Folder\\program.exe.";
      }
      return null;
  }
}

function ruleKey(rule: string) {
  if (rule === DIRECT_DEFAULT) return rule;
  const parts = rule.split(",");
  return parts.length >= 3 ? parts.slice(0, -1).join(",").toLowerCase() : rule.toLowerCase();
}

/** Number of user-visible differences: added, removed or re-routed rules, plus a mode switch. */
export function countChanges(saved: readonly string[], draft: readonly string[]) {
  const before = new Map(saved.map((rule) => [ruleKey(rule), rule]));
  const after = new Map(draft.map((rule) => [ruleKey(rule), rule]));
  let changes = 0;
  for (const [key, rule] of after) if (before.get(key) !== rule) changes += 1;
  for (const key of before.keys()) if (!after.has(key)) changes += 1;
  if (changes === 0 && saved.join("\n") !== draft.join("\n")) changes = 1;
  return changes;
}

export function equalLists(left: readonly string[], right: readonly string[]) {
  return left.length === right.length && left.every((item, index) => item === right[index]);
}
