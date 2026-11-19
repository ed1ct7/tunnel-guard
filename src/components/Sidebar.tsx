import {
  AppWindow,
  Cable,
  Gauge,
  Route,
  ShieldAlert,
  ShieldCheck,
  ShieldHalf,
  ShieldOff,
  ShieldQuestion,
  ShieldX,
  type LucideIcon,
  type LucideProps,
} from "lucide-react";
import type { Status } from "../api/types";
import { cx } from "../domain/format";
import { pageTitles, type Page } from "../domain/navigation";
import { actionTitles, type StatusView } from "../domain/status";
import type { Run } from "../domain/progress";
import { Spinner } from "./Button";

/** Shield glyph for the protection state; the shape differs per state, not only the colour. */
export function StatusIcon({ status, ...props }: { status: Status | null } & LucideProps) {
  if (!status) return <ShieldQuestion {...props} />;
  switch (status.state) {
    case "On":
      return status.adapter_up ? <ShieldCheck {...props} /> : <ShieldX {...props} />;
    case "Off":
    case "Unsupported":
      return <ShieldOff {...props} />;
    case "Partial":
    case "LegacyActive":
    case "LegacyInactive":
      return <ShieldAlert {...props} />;
    case "Unknown":
      return <ShieldQuestion {...props} />;
  }
}

const nav: Array<{ id: Page; icon: LucideIcon }> = [
  { id: "overview", icon: Gauge },
  { id: "routing", icon: Route },
  { id: "processes", icon: AppWindow },
  { id: "connection", icon: Cable },
];

type SidebarProps = {
  page: Page;
  onNavigate: (page: Page) => void;
  status: Status | null;
  view: StatusView;
  run: Run | null;
  /** Small markers next to nav items, e.g. unsaved changes. The text is read by screen readers. */
  badges: Partial<Record<Page, string>>;
};

export function Sidebar({ page, onNavigate, status, view, run, badges }: SidebarProps) {
  const busy = run?.phase === "running";
  return (
    <aside className="sidebar">
      <div className="brand">
        <ShieldHalf className="brand-mark" size={22} aria-hidden />
        <span>Tunnel Guard</span>
      </div>
      <button
        type="button"
        className={cx("status-pill", `tone-${busy ? "busy" : view.tone}`)}
        onClick={() => onNavigate("overview")}
        aria-label={`Состояние: ${busy ? actionTitles[run.action].running : view.pill}. Открыть обзор`}
      >
        {busy ? <Spinner size={16} /> : <StatusIcon status={status} size={16} aria-hidden />}
        <span className="status-pill-text" aria-live="polite">
          {busy ? `${actionTitles[run.action].running}…` : view.pill}
        </span>
      </button>
      <nav aria-label="Разделы">
        <ul>
          {nav.map(({ id, icon: NavIcon }) => (
            <li key={id}>
              <button
                type="button"
                className={cx("nav-item", page === id && "nav-active")}
                aria-current={page === id ? "page" : undefined}
                onClick={() => onNavigate(id)}
              >
                <NavIcon size={17} aria-hidden />
                <span>{pageTitles[id]}</span>
                {badges[id] && (
                  <span className="nav-badge" title={badges[id]}>
                    <span className="sr-only">{badges[id]}</span>
                  </span>
                )}
              </button>
            </li>
          ))}
        </ul>
      </nav>
      <p className="sidebar-foot">Закрытое окно остаётся в трее. Защита от этого не выключается.</p>
    </aside>
  );
}
