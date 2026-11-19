import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { createRoot } from "react-dom/client";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { ProcessGroups } from "./process-groups";
import "./style.css";

type Status = { state: string; adapter_up: boolean };
type Settings = { client_path: string; adapter: string; proxy_port: number };
type ConfigSnapshot = { settings: Settings; rules: string[] | null };
type Page = "protection" | "routing" | "connection" | "processes";
type Action = "enable" | "disable" | "clean_legacy";
const directDefaultRule = "MATCH,DIRECT";
const defaultSettings = { client_path: "", adapter: "Mihomo", proxy_port: 10808 };
const ruleKinds = [
  { code: "DOMAIN-SUFFIX", label: "Домен", example: "example.org" },
  { code: "PROCESS-NAME", label: "Имя процесса", example: "program.exe" },
  { code: "PROCESS-PATH", label: "Путь к программе", example: "C:\\Folder\\program.exe" },
];
const pages: Array<{ id: Page; label: string; icon: string }> = [
  { id: "protection", label: "Защита", icon: "shield" },
  { id: "routing", label: "Маршрутизация", icon: "route" },
  { id: "processes", label: "Процессы", icon: "process" },
  { id: "connection", label: "Подключение", icon: "settings" },
];

function equal(left: unknown, right: unknown) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function present(status: Status) {
  switch (status.state) {
    case "On":
      return status.adapter_up
        ? { title: "Защита включена", detail: "Обычный трафик разрешён через TUN. Прямой выход Windows блокирует.", tone: "good" }
        : { title: "Туннель отключён", detail: "Защита включена. Подключи VPN в режиме TUN, чтобы восстановить доступ в интернет.", tone: "warn" };
    case "Off":
    case "LegacyInactive":
      return { title: "Защита выключена", detail: status.adapter_up
        ? "При отключении VPN Windows может использовать обычное подключение."
        : "Windows может подключаться напрямую. Чтобы включить защиту, подключи профиль в v2rayN и включи Enable TUN.", tone: "idle" };
    case "Partial":
      return { title: "Проверь правила", detail: "Изменение брандмауэра завершилось частично. Можно восстановить предыдущие настройки.", tone: "warn" };
    case "LegacyActive":
      return { title: "Найдена старая защита", detail: "Сначала восстанови правила предыдущим переключателем.", tone: "warn" };
    case "Unsupported":
      return { title: "Защита недоступна", detail: "Системный kill switch для этой ОС ещё не реализован.", tone: "idle" };
    default:
      return { title: "Статус недоступен", detail: "Проверяем состояние брандмауэра Windows.", tone: "idle" };
  }
}

function displayRule(rule: string) {
  const [type, ...parts] = rule.split(",");
  const route = parts.pop();
  const kind = ruleKinds.find((entry) => entry.code === type);
  return {
    type: kind?.label ?? type,
    target: parts.join(",") || rule,
    route: route === "DIRECT" ? "Напрямую" : route === "REJECT" ? "Блокировать" : route,
  };
}

function App() {
  const [page, setPage] = useState<Page>("protection");
  const [status, setStatus] = useState<Status>({ state: "Unknown", adapter_up: false });
  const [configured, setConfigured] = useState<Settings>(defaultSettings);
  const [settings, setSettings] = useState<Settings>(defaultSettings);
  const [savedRules, setSavedRules] = useState<string[]>([]);
  const [rules, setRules] = useState<string[]>([]);
  const [ruleKind, setRuleKind] = useState(0);
  const [ruleInput, setRuleInput] = useState("");
  const [ruleRoute, setRuleRoute] = useState("");
  const [targets, setTargets] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<{ text: string; error: boolean }>();
  const reading = useRef(false);
  const state = present(status);
  const vpnOnly = rules.at(-1) === directDefaultRule;
  const selectedRoute = ruleRoute || (vpnOnly ? targets[0] ?? "" : "DIRECT");
  const dirty = !equal(rules, savedRules);
  const drafts = useRef({ configured, settings, savedRules, rules, dirty });
  drafts.current = { configured, settings, savedRules, rules, dirty };

  const syncConfig = useCallback((snapshot: ConfigSnapshot) => {
    const local = drafts.current;
    const settingsChanged = !equal(local.configured, snapshot.settings);
    const rulesChanged = !equal(local.savedRules, snapshot.rules ?? []);
    if (!settingsChanged && !rulesChanged) return;
    if ((settingsChanged && !equal(local.settings, local.configured) && !equal(local.settings, snapshot.settings)) ||
        (local.dirty && (settingsChanged || rulesChanged) && !equal(local.rules, snapshot.rules ?? []))) {
      setNotice({ text: "Настройки изменились в другой программе. Нажми «Перечитать», чтобы загрузить их.", error: true });
      return;
    }
    if (settingsChanged) {
      setConfigured(snapshot.settings);
      setSettings(snapshot.settings);
    }
    setSavedRules(snapshot.rules ?? []);
    setRules(snapshot.rules ?? []);
  }, []);

  const refresh = useCallback(async () => {
    if (reading.current) return;
    reading.current = true;
    try {
      setStatus(await invoke<Status>("guard_status"));
    } catch (error) {
      setStatus({ state: "Unknown", adapter_up: false });
      setNotice({ text: String(error), error: true });
    } finally {
      reading.current = false;
    }
  }, []);

  const loadRules = useCallback(async (showError: boolean) => {
    try {
      const list = await invoke<string[]>("load_rules");
      setSavedRules(list);
      setRules(list);
    } catch (error) {
      if (showError) setNotice({ text: String(error), error: true });
    }
  }, []);

  useEffect(() => {
    void invoke<ConfigSnapshot>("config_snapshot").then(async (snapshot) => {
      syncConfig(snapshot);
      const draft = await invoke<string[] | null>("recover_routing_draft");
      if (draft) {
        setRules(draft);
        setPage("routing");
        setNotice({ text: "Несохранённый список восстановлен. Проверь правила перед сохранением.", error: false });
      }
    })
      .catch((error: unknown) => setNotice({ text: String(error), error: true }));
    void refresh();
    const subscriptions = [
      listen<Status>("guard-state", (event) => setStatus(event.payload)),
      listen<ConfigSnapshot>("guard-config", (event) => syncConfig(event.payload)),
    ];
    return () => {
      for (const subscription of subscriptions) {
        void subscription.then((unlisten) => unlisten()).catch(() => undefined);
      }
    };
  }, [syncConfig, refresh]);

  useEffect(() => {
    if (page !== "routing" || !configured.client_path) return;
    let active = true;
    setTargets([]);
    void invoke<string[]>("vpn_targets").then((value) => {
      if (active) setTargets(value);
    }).catch(() => undefined);
    return () => { active = false; };
  }, [page, configured.client_path, configured.proxy_port, status.adapter_up]);

  async function operation<T>(command: string, args?: Record<string, unknown>, message?: string) {
    setBusy(true);
    setNotice(undefined);
    try {
      const result = await invoke<T>(command, args);
      if (message) setNotice({ text: message, error: false });
      return result;
    } catch (error) {
      setNotice({ text: String(error), error: true });
      return undefined;
    } finally {
      setBusy(false);
    }
  }

  async function change(action: Action) {
    if (action === "disable" &&
        !window.confirm("Вернуть прежние правила Windows? При отключённом VPN приложения снова смогут подключаться напрямую.")) return;
    if (action === "enable" && !configured.client_path) {
      setPage("connection");
      setNotice({ text: "Выбери установленный v2rayN и сохрани подключение.", error: false });
      return;
    }
    await operation("change_protection", { action }, action === "enable"
      ? "Проверено: через TUN HTTPS работает, тестовый маршрут через обычный адаптер заблокирован."
      : "Правила Windows восстановлены.");
    await refresh();
  }

  async function choosePath(forRule: boolean) {
    const selected = await operation<string | null>("pick_exe");
    if (selected) {
      if (forRule) setRuleInput(selected);
      else setSettings({ ...settings, client_path: selected });
    }
  }

  function addRule(event: FormEvent) {
    event.preventDefault();
    const value = ruleInput.trim();
    if (!value || value.includes(",")) {
      setNotice({ text: "Укажи один домен или процесс.", error: true });
      return;
    }
    if (!selectedRoute) {
      setNotice({ text: "Запусти VPN или выбери прямой маршрут.", error: true });
      return;
    }
    const prefix = [ruleKinds[ruleKind].code, value, ""].join(",");
    const updated = [...rules];
    const previous = updated.findIndex((entry) => entry.toLowerCase().startsWith(prefix.toLowerCase()));
    if (previous >= 0) updated[previous] = prefix + selectedRoute;
    else updated.splice(vpnOnly ? updated.length - 1 : updated.length, 0, prefix + selectedRoute);
    setRules(updated);
    setRuleInput("");
    setNotice(undefined);
  }

  async function saveRoutes() {
    if (vpnOnly && savedRules.at(-1) !== directDefaultRule &&
        !window.confirm("Включить режим «Только выбранное через VPN»? Остальной трафик пойдёт напрямую даже при включённом kill switch.")) return;
    const result = await operation<null>("save_rules", { rules, original: savedRules, settings: configured }, "Правила сохранены. Перезапусти v2rayN, чтобы применить их.");
    if (result !== undefined) await loadRules(false);
  }

  function setRoutingMode(onlySelected: boolean) {
    setRules((current) => {
      const explicit = current.filter((rule) => rule !== directDefaultRule);
      return onlySelected ? [...explicit, directDefaultRule] : explicit;
    });
    setRuleRoute("");
    setNotice(undefined);
  }

  async function saveConnection(event: FormEvent) {
    event.preventDefault();
    const before = settings;
    const result = await operation<null>("save_settings", { settings: before, original: configured }, "Подключение сохранено.");
    if (result === undefined) return;
    setConfigured(before);
    setSavedRules([]);
    setRules([]);
    await loadRules(false);
    await refresh();
  }

  async function reloadConfig() {
    if ((dirty || !equal(settings, configured)) &&
        !window.confirm("Перечитать настройки с диска? Несохранённые изменения в окне будут сброшены.")) return;
    const snapshot = await operation<ConfigSnapshot>("config_snapshot");
    if (!snapshot) return;
    setConfigured(snapshot.settings);
    setSettings(snapshot.settings);
    setSavedRules(snapshot.rules ?? []);
    setRules(snapshot.rules ?? []);
    await refresh();
  }

  const action: Action = status.state === "LegacyInactive" ? "clean_legacy"
    : ["On", "Partial"].includes(status.state) ? "disable" : "enable";
  const actionLabel = action === "clean_legacy" ? "Удалить старые правила"
    : action === "enable" ? "Включить защиту"
    : status.state === "Partial" ? "Восстановить правила" : "Выключить защиту";
  const title = pages.find((entry) => entry.id === page)?.label;

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand"><span className="brand-icon" aria-hidden="true" />Tunnel Guard</div>
        <nav aria-label="Разделы">
          {pages.map((entry) => <button key={entry.id} className={page === entry.id ? "nav active" : "nav"}
            aria-current={page === entry.id ? "page" : undefined} onClick={() => { setPage(entry.id); setNotice(undefined); }}>
            <span className={"nav-icon " + entry.icon} aria-hidden="true" />{entry.label}
          </button>)}
        </nav>
        <div className="side-state"><span className={"dot " + state.tone} />{state.title}</div>
      </aside>
      <main>
        <header><h1>{title}</h1></header>
        {page === "processes" && <ProcessGroups />}
        {page === "protection" && <>
          <section className={"status-card " + state.tone} aria-live="polite">
            <span className="status-icon" aria-hidden="true" />
            <h2>{state.title}</h2>
            <p>{state.detail}</p>
            <div className="actions">
              <button className="primary" disabled={busy || !["On", "Off", "Partial", "LegacyInactive"].includes(status.state)}
                onClick={() => void change(action)}>{busy ? "Выполняется…" : actionLabel}</button>
              <button className="secondary" disabled={busy} onClick={() => void operation("open_client")}>Открыть v2rayN</button>
            </div>
          </section>
          <section className="facts" aria-label="Состояние подключения">
            <div><span>Адаптер TUN</span><strong>{status.adapter_up ? "Активен" : "Не обнаружен"}</strong></div>
            <div><span>Режим защиты</span><strong>Системный · Windows</strong></div>
          </section>
          {status.state === "LegacyInactive" && <p className="muted">Перед включением удали правила предыдущего переключателя.</p>}
        </>}
        {page === "routing" && <>
          <div className="routing-mode">
            <label>Режим маршрутизации
              <select value={vpnOnly ? "vpn-only" : "profile"} onChange={(event) => setRoutingMode(event.target.value === "vpn-only")}>
                <option value="profile">По умолчанию как в VPN-профиле</option>
                <option value="vpn-only">Только выбранное через VPN</option>
              </select>
            </label>
            {vpnOnly && <p className="muted">Совпавшие правила идут по указанному маршруту. Весь остальной трафик идёт напрямую.</p>}
          </div>
          <form className="rule-form" onSubmit={addRule}>
            <label>Тип правила<select value={ruleKind} onChange={(event) => { setRuleKind(Number(event.target.value)); setRuleInput(""); }}>
              {ruleKinds.map((kind, index) => <option key={kind.code} value={index}>{kind.label}</option>)}
            </select></label>
            <label className="grow">Адрес или программа<input value={ruleInput} onChange={(event) => setRuleInput(event.target.value)}
              placeholder={ruleKinds[ruleKind].example} required /></label>
            {ruleKind === 2 && <button type="button" className="secondary" onClick={() => void choosePath(true)}>Обзор…</button>}
            <label>Маршрут<select value={selectedRoute} onChange={(event) => setRuleRoute(event.target.value)}>
              {!selectedRoute && <option value="" disabled>Подключи VPN</option>}
              <option value="DIRECT">Напрямую</option>
              {targets.map((target) => <option value={target} key={target}>VPN · {target}</option>)}
            </select></label>
            <button className="primary" disabled={busy || !configured.client_path}>Добавить</button>
          </form>
          <div className="rules">
            <div className="table-header"><span>Тип</span><span>Адрес или программа</span><span>Маршрут</span><span /></div>
            {rules.filter((rule) => rule !== directDefaultRule).length === 0 && <p className="empty">Пользовательских правил пока нет.</p>}
            {rules.map((rule, index) => {
              if (rule === directDefaultRule) return null;
              const row = displayRule(rule);
              return <div className="table-row" key={rule + index}><span>{row.type}</span><span title={row.target}>{row.target}</span>
                <span className="route-badge">{row.route}</span><button className="delete" aria-label={"Удалить " + row.target}
                  onClick={() => setRules(rules.filter((_, i) => i !== index))}>×</button></div>;
            })}
          </div>
          <div className="actions bottom">
            <button className="primary" disabled={busy || !dirty} onClick={() => void saveRoutes()}>Сохранить правила</button>
            <button className="secondary" disabled={busy} onClick={() => void reloadConfig()}>Перечитать</button>
          </div>
          <p className="muted">Первое совпавшее правило имеет приоритет. Сохранённые изменения загружаются при перезапуске ядра.</p>
        </>}
        {page === "connection" && <>
          <p className="intro">Импортируй свой профиль в v2rayN и запусти Mihomo в режиме TUN. Затем укажи подключение здесь.</p>
          <form className="settings-form" onSubmit={(event) => void saveConnection(event)}>
            <label>Исполняемый файл v2rayN<div className="input-row">
              <input className="grow" value={settings.client_path} onChange={(event) => setSettings({ ...settings, client_path: event.target.value })} required />
              <button type="button" className="secondary" disabled={busy} onClick={() => void choosePath(false)}>Обзор…</button>
            </div></label>
            <div className="input-row">
              <label className="grow">Имя адаптера TUN<input value={settings.adapter} onChange={(event) => setSettings({ ...settings, adapter: event.target.value })} required /></label>
              <label>Порт локального прокси<input type="number" min={1} max={65529} value={settings.proxy_port}
                onChange={(event) => setSettings({ ...settings, proxy_port: Number(event.target.value) })} required /></label>
            </div>
            <div className="actions">
              <button className="primary" disabled={busy}>Сохранить подключение</button>
              <button className="secondary" type="button" disabled={busy} onClick={() => void reloadConfig()}>Перечитать</button>
            </div>
          </form>
        </>}
        {notice && <div className={notice.error ? "notice error" : "notice"} role={notice.error ? "alert" : "status"}>{notice.text}</div>}
      </main>
    </div>
  );
}

createRoot(document.getElementById("root")!).render(<App />);
