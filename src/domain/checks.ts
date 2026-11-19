import type { Check, CheckId, Diagnosis } from "../api/types";

export type CheckFixLink = "connection" | "client";

export type CheckText = {
  title: string;
  /** What to do when the check fails. */
  fix: string;
  /** Where the fix lives: a page in the app or the v2rayN window. */
  link?: CheckFixLink;
};

export const checkTexts: Record<CheckId, CheckText> = {
  client: {
    title: "v2rayN.exe по указанному пути",
    fix: "Укажи путь к v2rayN.exe во вкладке «Подключение» или нажми там «Найти автоматически».",
    link: "connection",
  },
  core: {
    title: "Ядро Mihomo рядом с v2rayN",
    fix: "Рядом с v2rayN.exe нет bin\\mihomo\\mihomo.exe. Выбери копию v2rayN с ядром Mihomo.",
    link: "connection",
  },
  mixin: {
    title: "Enable Mixin Content включён",
    fix: "Включи Enable Mixin Content в настройках Mihomo в v2rayN. Без него не работают только правила маршрутизации.",
  },
  client_running: {
    title: "v2rayN запущен",
    fix: "Запусти v2rayN. Если ядро Mihomo уже работает, защиту можно включить и без окна v2rayN.",
    link: "client",
  },
  proxy: {
    title: "Локальный прокси отвечает",
    fix: "Запусти v2rayN и подключи профиль. Если он уже работает, сверь порт прокси во вкладке «Подключение».",
    link: "client",
  },
  controller: {
    title: "Контроллер Mihomo отвечает",
    fix: "Контроллер Mihomo не ответил или принадлежит другой программе. Запусти профиль в v2rayN или перезапусти ядро.",
    link: "client",
  },
  adapter: {
    title: "TUN-адаптер подключён",
    fix: "Включи Enable TUN в v2rayN. Если TUN уже включён, проверь имя адаптера во вкладке «Подключение».",
    link: "connection",
  },
  tun: {
    title: "TUN включён в Mihomo",
    fix: "Включи Enable TUN в v2rayN. Имя устройства в Mihomo должно совпадать с адаптером во вкладке «Подключение».",
    link: "client",
  },
  mode: {
    title: "Режим Mihomo — Rule",
    fix: "Переключи режим на Rule в v2rayN. В режимах Global и Direct правила маршрутизации не действуют.",
    link: "client",
  },
};

/** Checks that do not block enabling protection (see `Diagnosis.ready`). */
export const advisoryChecks: ReadonlySet<CheckId> = new Set(["mixin", "client_running"]);

export const skipText = "Не проверено: сначала исправь пункт выше.";

export function problems(diagnosis: Diagnosis | null): Check[] {
  if (!diagnosis) return [];
  return diagnosis.checks.filter((check) => check.status === "fail" || check.status === "warn");
}

/** Problems that make `ready` false, in checklist order. */
export function blockingProblems(diagnosis: Diagnosis | null): Check[] {
  return problems(diagnosis).filter((check) => !advisoryChecks.has(check.id));
}
