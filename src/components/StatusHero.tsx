import { ExternalLink, Power, PowerOff, RefreshCw, RotateCcw, ShieldCheck, Trash2 } from "lucide-react";
import type { Diagnosis, ProtectionBackend, Status } from "../api/types";
import { protectionBackendLabels } from "../domain/settings";
import { blockingProblems } from "../domain/checks";
import { cx, plural } from "../domain/format";
import { activeStepLabel, type Run } from "../domain/progress";
import type { PrimaryAction, StatusView } from "../domain/status";
import { formatAge, useNow } from "../hooks/useNow";
import { Button, Spinner } from "./Button";
import { InlineError } from "./Layout";
import { RouteStrip } from "./RouteStrip";
import { StatusIcon } from "./Sidebar";

function Freshness({
  status,
  refreshing,
  onRefresh,
}: {
  status: Status | null;
  refreshing: boolean;
  onRefresh: () => void;
}) {
  const now = useNow(1000);
  // Polls arrive every ~4 s while the window is open; a much older reading means the backend stalled.
  const stale = status ? now - status.checked_at > 30_000 : false;
  return (
    <div className="hero-fresh">
      {status && (
        <span
          className={cx("checked-ago", stale && "text-warn")}
          title={new Date(status.checked_at).toLocaleTimeString("ru-RU")}
        >
          {stale ? "давно не обновлялось, " : ""}проверено {formatAge(status.checked_at, now)}
        </span>
      )}
      <Button size="sm" variant="ghost" icon={RefreshCw} busy={refreshing} onClick={onRefresh}>
        Обновить
      </Button>
    </div>
  );
}

type StatusHeroProps = {
  status: Status | null;
  statusError: string | null;
  view: StatusView;
  adapter: string;
  selectedBackend: ProtectionBackend | null;
  refreshing: boolean;
  onRefresh: () => void;
  primary: PrimaryAction;
  onPrimary: () => void;
  /** Present when the active filters are outdated and can be replaced in place. */
  onUpgrade: (() => void) | null;
  clientConfigured: boolean;
  onOpenClient: () => void;
  openingClient: boolean;
  diagnosis: Diagnosis | null;
  run: Run | null;
  progressVisible: boolean;
  onShowProgress: () => void;
};

const actionIcons = { enable: Power, disable: PowerOff, clean_legacy: Trash2 };

export function StatusHero(props: StatusHeroProps) {
  const { status, view, primary, run, diagnosis } = props;
  const running = run?.phase === "running";
  const blocking = blockingProblems(diagnosis);

  let note: string | null = null;
  if (primary.blocked) note = primary.blocked;
  else if (primary.action === "enable" && !props.clientConfigured) {
    note = "Сначала укажи v2rayN во вкладке «Подключение» — кнопка откроет её.";
  } else if (primary.action === "enable" && diagnosis && !diagnosis.ready) {
    const count = blocking.length;
    note = count
      ? `Проверка нашла ${count} ${plural(count, "проблему", "проблемы", "проблем")} — смотри «Готовность» ниже. Включить можно и так: перед изменением правил туннель проверится ещё раз.`
      : "Не все пункты готовности проверены. Перед изменением правил туннель проверится ещё раз.";
  } else if (primary.action === "enable" && diagnosis?.ready) {
    note = "Всё готово. Windows попросит подтвердить права администратора.";
  } else if (primary.action !== "enable") {
    note = "Понадобится подтвердить права администратора Windows.";
  }

  const PrimaryIcon =
    primary.action === "disable" && status?.state === "Partial" ? RotateCcw : actionIcons[primary.action];
  // Turning protection off lowers safety, so it is not the visually loudest button.
  const primaryVariant = primary.action === "disable" && status?.state === "On" ? "secondary" : "primary";

  return (
    <section className={cx("hero", `tone-${view.tone}`)} aria-labelledby="hero-title">
      <div className="hero-top">
        <StatusIcon status={status} className="hero-icon" size={34} strokeWidth={1.75} aria-hidden />
        <div className="hero-text" aria-live="polite">
          <h1 id="hero-title" tabIndex={-1}>
            {view.title}
          </h1>
          <p className="hero-summary">{view.summary}</p>
        </div>
        <Freshness status={status} refreshing={props.refreshing} onRefresh={props.onRefresh} />
      </div>

      <RouteStrip tunnel={view.tunnel} direct={view.direct} adapter={props.adapter} />

      {status?.active_backend ? (
        <p className="hero-note">Применённые правила · {protectionBackendLabels[status.active_backend]}</p>
      ) : props.selectedBackend && status?.state === "Off" ? (
        <p className="hero-note">Выбранный способ · {protectionBackendLabels[props.selectedBackend]}</p>
      ) : null}

      {props.statusError && <InlineError>Не удалось прочитать статус: {props.statusError}</InlineError>}

      <div className="hero-actions">
        {running && !props.progressVisible ? (
          <div className="hero-running" role="status">
            <Spinner size={16} />
            <span>{activeStepLabel(run)}</span>
            <Button size="sm" variant="ghost" onClick={props.onShowProgress}>
              Показать ход
            </Button>
          </div>
        ) : (
          <Button
            variant={primaryVariant}
            icon={PrimaryIcon}
            busy={running}
            disabledReason={primary.blocked}
            onClick={props.onPrimary}
          >
            {primary.label}
          </Button>
        )}
        {props.onUpgrade && !running && (
          <Button variant="primary" icon={ShieldCheck} onClick={props.onUpgrade}>
            Обновить фильтры
          </Button>
        )}
        <Button
          variant="ghost"
          icon={ExternalLink}
          busy={props.openingClient}
          disabledReason={
            props.clientConfigured ? null : "Сначала укажи путь к v2rayN во вкладке «Подключение»."
          }
          onClick={props.onOpenClient}
        >
          Открыть v2rayN
        </Button>
      </div>
      {note && !running && <p className="hero-note">{note}</p>}
    </section>
  );
}
