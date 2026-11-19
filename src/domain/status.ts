import type { GuardState, ProtectionAction, Status } from "../api/types";

export type Tone = "good" | "warn" | "danger" | "idle";

/** State of one traffic lane in the route strip. */
export type Lane = "works" | "down" | "blocked" | "open" | "partial" | "unknown";

export type StatusView = {
  tone: Tone;
  /** Hero title. */
  title: string;
  /** One sentence: what this means for the internet right now. */
  summary: string;
  /** Short label for the sidebar pill. */
  pill: string;
  tunnel: Lane;
  direct: Lane;
};

export function presentStatus(status: Status | null): StatusView {
  if (!status) {
    return {
      tone: "idle",
      title: "Проверяем защиту…",
      summary: "Читаем правила брандмауэра Windows и состояние туннеля.",
      pill: "Проверка…",
      tunnel: "unknown",
      direct: "unknown",
    };
  }
  const tunnel: Lane = status.adapter_up ? "works" : "down";
  switch (status.state) {
    case "On":
      return status.adapter_up
        ? {
            tone: "good",
            title: "Защита включена",
            summary:
              "Интернет идёт только через VPN. Если туннель пропадёт, Windows заблокирует прямой выход и данные не утекут.",
            pill: "Защищено",
            tunnel,
            direct: "blocked",
          }
        : {
            tone: "danger",
            title: "Нет интернета: туннель не работает",
            summary:
              "Защита блокирует прямой выход, а TUN-адаптер отключён. Подключи профиль в v2rayN с Enable TUN — или выключи защиту, чтобы вернуть обычный интернет.",
            pill: "Нет интернета",
            tunnel,
            direct: "blocked",
          };
    case "Off":
      return status.adapter_up
        ? {
            tone: "idle",
            title: "Защита выключена",
            summary:
              "Сейчас трафик идёт через VPN, но если туннель пропадёт, Windows молча переключится на обычное подключение.",
            pill: "Выключена",
            tunnel,
            direct: "open",
          }
        : {
            tone: "idle",
            title: "Защита выключена",
            summary:
              "Интернет работает напрямую, без VPN. Чтобы включить защиту, подключи профиль в v2rayN и включи Enable TUN.",
            pill: "Выключена",
            tunnel,
            direct: "open",
          };
    case "LegacyInactive":
      return {
        tone: "warn",
        title: "Остались правила старой версии",
        summary:
          "Они не действуют, и интернет работает как без защиты, но мешают её включить. Удали их, затем включи защиту.",
        pill: "Старые правила",
        tunnel,
        direct: "open",
      };
    case "Partial":
      return {
        tone: "warn",
        title: "Правила применены частично",
        summary:
          "Изменение брандмауэра не завершилось: часть трафика может блокироваться, часть — уходить напрямую. Восстанови прежние правила и включи защиту заново.",
        pill: "Частично",
        tunnel,
        direct: "partial",
      };
    case "LegacyActive":
      return {
        tone: "warn",
        title: "Работает защита старой версии",
        summary:
          "Правила предыдущего переключателя активны. Сначала отключи их тем способом, которым включал, затем вернись сюда.",
        pill: "Старая защита",
        tunnel,
        direct: "blocked",
      };
    case "Unsupported":
      return {
        tone: "idle",
        title: "Защита недоступна",
        summary: "Системный kill switch для этой ОС ещё не реализован. Интернет работает без защиты.",
        pill: "Недоступна",
        tunnel,
        direct: "open",
      };
    case "Unknown":
      return {
        tone: "warn",
        title: "Состояние неизвестно",
        summary:
          "Не удалось прочитать правила брандмауэра Windows, поэтому неясно, защищён ли трафик. Нажми «Обновить».",
        pill: "Неизвестно",
        tunnel: status.adapter_up ? "works" : "unknown",
        direct: "unknown",
      };
  }
}

export type PrimaryAction = {
  action: ProtectionAction;
  label: string;
  /** Why the action is not available right now; `null` when it is. */
  blocked: string | null;
};

const actionable: GuardState[] = ["On", "Off", "Partial", "LegacyInactive"];

export function primaryAction(status: Status | null): PrimaryAction {
  const state = status?.state ?? "Unknown";
  const action: ProtectionAction =
    state === "LegacyInactive"
      ? "clean_legacy"
      : state === "On" || state === "Partial"
        ? "disable"
        : "enable";
  const label =
    action === "clean_legacy"
      ? "Удалить старые правила"
      : action === "enable"
        ? "Включить защиту"
        : state === "Partial"
          ? "Восстановить правила"
          : "Выключить защиту";
  let blocked: string | null = null;
  if (!status) blocked = "Дождись проверки состояния.";
  else if (!actionable.includes(state)) {
    blocked =
      state === "LegacyActive"
        ? "Сначала отключи старую защиту тем способом, которым её включал."
        : state === "Unsupported"
          ? "Kill switch пока реализован только для Windows."
          : "Состояние брандмауэра не прочитано. Нажми «Обновить».";
  }
  return { action, label, blocked };
}

export const actionTitles: Record<ProtectionAction, { running: string; done: string; failed: string }> = {
  enable: { running: "Включаем защиту", done: "Защита включена", failed: "Защита не включилась" },
  disable: {
    running: "Выключаем защиту",
    done: "Правила Windows восстановлены",
    failed: "Не удалось выключить защиту",
  },
  clean_legacy: {
    running: "Удаляем старые правила",
    done: "Старые правила удалены",
    failed: "Старые правила не удалены",
  },
};

/** Success messages kept from 0.4 so the wording matches the CLI and the README. */
export const actionSuccess: Record<ProtectionAction, string> = {
  enable: "Проверено: через TUN HTTPS работает, тестовый маршрут через обычный адаптер заблокирован.",
  disable: "Правила Windows восстановлены. Приложения снова могут подключаться напрямую.",
  clean_legacy: "Правила предыдущего переключателя удалены. Теперь можно включить защиту.",
};
