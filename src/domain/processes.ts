import type { ProcessGroup, Selector, SelectorKind } from "../api/types";

export const selectorKinds: ReadonlyArray<{ value: SelectorKind; label: string; hint: string }> = [
  { value: "name", label: "Имя .exe", hint: "program.exe" },
  { value: "path", label: "Полный путь к .exe", hint: "C:\\Apps\\program.exe" },
  { value: "package_family", label: "Семейство пакета Windows", hint: "Publisher.Program_123456789abcd" },
  { value: "argument", label: "Фрагмент аргументов", hint: "--profile example" },
  { value: "service", label: "Служба Windows", hint: "ServiceName" },
];

export function kindLabel(kind: SelectorKind) {
  return selectorKinds.find((entry) => entry.value === kind)?.label ?? kind;
}

export function kindHint(kind: SelectorKind) {
  return selectorKinds.find((entry) => entry.value === kind)?.hint ?? "";
}

/** The backend denies unknown fields, so `image` is sent only for argument selectors. */
export function cleanSelector(selector: Selector): Selector {
  const value = selector.value.trim();
  return selector.kind === "argument"
    ? { kind: selector.kind, image: (selector.image ?? "").trim(), value }
    : { kind: selector.kind, value };
}

export function newGroup(): ProcessGroup {
  return { id: crypto.randomUUID(), title: "", selectors: [], includes: [] };
}

export function groupTitle(groups: readonly ProcessGroup[], id: string) {
  return groups.find((group) => group.id === id)?.title ?? id;
}

const exeName = /^[^\\/:*?"<>|]+\.exe$/i;

/** Client-side hint mirroring the backend selector check. */
export function selectorProblem(selector: Selector): string | null {
  const value = selector.value.trim();
  if (!value) return "Укажи значение.";
  switch (selector.kind) {
    case "name":
      return exeName.test(value) ? null : "Нужно имя файла с .exe, без пути: program.exe.";
    case "path":
      return /^(?:[a-z]:\\|\\\\)/i.test(value) && exeName.test(value.split("\\").pop() ?? "")
        ? null
        : "Нужен полный путь к .exe: C:\\Apps\\program.exe.";
    case "package_family":
      return value.includes("_") && /^[A-Za-z0-9._-]+$/.test(value)
        ? null
        : "Формат: Publisher.Program_123456789abcd — латиница, цифры, точка, дефис и _.";
    case "argument":
      return exeName.test((selector.image ?? "").trim())
        ? null
        : "Укажи имя .exe, в аргументах которого искать.";
    case "service":
      return /^[A-Za-z0-9._$-]+$/.test(value) ? null : "Нужно точное имя службы: латиница, цифры, . _ - $.";
  }
}

/** Ids of groups that (transitively) include `id` — including them in `id` would make a cycle. */
export function groupsIncluding(groups: readonly ProcessGroup[], id: string): Set<string> {
  const result = new Set<string>();
  let changed = true;
  while (changed) {
    changed = false;
    for (const group of groups) {
      if (result.has(group.id)) continue;
      if (group.includes.some((child) => child === id || result.has(child))) {
        result.add(group.id);
        changed = true;
      }
    }
  }
  return result;
}
