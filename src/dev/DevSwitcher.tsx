import { FlaskConical, X } from "lucide-react";
import { useState } from "react";
import { getMockBackend, scenarios, type ScenarioName } from "../api/mock";
import "./dev.css";

/**
 * Development-only panel for the browser mock: switches scenarios (reloads with `?mock=<name>`)
 * and simulates outside events. Never part of the production bundle.
 */
export function DevSwitcher() {
  const backend = getMockBackend();
  const [open, setOpen] = useState(false);

  function choose(name: ScenarioName) {
    const url = new URL(window.location.href);
    url.searchParams.set("mock", name);
    window.location.assign(url);
  }

  if (!open) {
    return (
      <button
        type="button"
        className="dev-toggle"
        onClick={() => setOpen(true)}
        title="Сценарии mock-бэкенда"
      >
        <FlaskConical size={14} aria-hidden />
        <span>mock: {backend.scenario}</span>
      </button>
    );
  }

  return (
    <aside className="dev-panel" aria-label="Сценарии mock-бэкенда">
      <header className="dev-panel-head">
        <strong>Mock-бэкенд</strong>
        <button type="button" className="dev-close" aria-label="Свернуть" onClick={() => setOpen(false)}>
          <X size={14} aria-hidden />
        </button>
      </header>
      <label className="dev-field">
        <span>Сценарий</span>
        <select value={backend.scenario} onChange={(event) => choose(event.target.value as ScenarioName)}>
          {Object.entries(scenarios).map(([name, text]) => (
            <option key={name} value={name}>
              {name} — {text}
            </option>
          ))}
        </select>
      </label>
      <div className="dev-actions">
        <button type="button" onClick={() => backend.toggleVpn()}>
          VPN вкл/выкл
        </button>
        <button type="button" onClick={() => backend.externalRulesEdit()}>
          Правила изменены извне
        </button>
      </div>
    </aside>
  );
}
