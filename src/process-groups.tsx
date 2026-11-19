import { useEffect, useRef, useState, type FormEvent } from "react";
import { invoke } from "@tauri-apps/api/core";

type Kind = "name" | "path" | "package_family" | "argument" | "service";
type Selector = { kind: Kind; value: string; image?: string };
type Group = { id: string; title: string; selectors: Selector[]; includes: string[] };
type Config = { groups: Group[] };
type ProcessInfo = { pid: number; name: string; owned: boolean };
type Outcome = {
  matched: ProcessInfo[];
  caller_in_group?: boolean;
  stopped?: ProcessInfo[];
  remaining?: ProcessInfo[];
  complete?: boolean;
  services: Array<{ name: string; status: string; error?: string }>;
};

const kinds: Array<{ value: Kind; label: string; hint: string }> = [
  { value: "name", label: "Имя .exe", hint: "program.exe" },
  { value: "path", label: "Полный путь к .exe", hint: "C:\\Apps\\program.exe" },
  { value: "package_family", label: "Семейство пакета Windows", hint: "Publisher.Program_123456789abcd" },
  { value: "argument", label: "Фрагмент аргументов", hint: "--profile example" },
  { value: "service", label: "Служба Windows", hint: "ServiceName" },
];

export function ProcessGroups() {
  const [config, setConfig] = useState<Config>({ groups: [] });
  const [draft, setDraft] = useState<Group>();
  const [selector, setSelector] = useState<Selector>({ kind: "name", value: "" });
  const [result, setResult] = useState<{ title: string; outcome: Outcome; stop: boolean }>();
  const [busy, setBusy] = useState(false);
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState("");
  const editing = useRef(false);
  editing.current = Boolean(draft);

  async function refresh() {
    try {
      setConfig(await invoke<Config>("load_process_groups"));
      setLoaded(true);
      setError("");
    } catch (reason) {
      setLoaded(false);
      setError(String(reason));
    }
  }

  useEffect(() => {
    void refresh();
    const timer = window.setInterval(() => {
      if (!editing.current) void invoke<Config>("load_process_groups").then(setConfig).catch(() => undefined);
    }, 2500);
    return () => window.clearInterval(timer);
  }, []);

  function begin(group?: Group) {
    setDraft(group ?? { id: crypto.randomUUID(), title: "", selectors: [], includes: [] });
    setSelector({ kind: "name", value: "" });
    setError("");
  }

  async function save(groups: Group[]) {
    setBusy(true);
    setError("");
    const next = { groups };
    try {
      await invoke("save_process_groups", { config: next, original: config });
      setConfig(next);
      setDraft(undefined);
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  }

  function submit(event: FormEvent) {
    event.preventDefault();
    if (!draft) return;
    const group = { ...draft, title: draft.title.trim() };
    void save(config.groups.some((item) => item.id === group.id)
      ? config.groups.map((item) => item.id === group.id ? group : item)
      : [...config.groups, group]);
  }

  async function execute(group: Group, stop: boolean) {
    setBusy(true);
    setError("");
    setResult(undefined);
    try {
      const outcome = await invoke<Outcome>("run_process_group", { id: group.id, stop, original: config });
      setResult({ title: group.title, stop, outcome });
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  }

  return <>
    <p className="intro">Собери приложения и их помощников в группы. Общая группа запускает одну команду для нескольких приложений. При принудительном завершении несохранённые данные могут потеряться.</p>
    <div className="actions processes-top">
      <button className="primary" disabled={busy || !loaded || Boolean(draft)} onClick={() => begin()}>Новая группа</button>
      <button className="secondary" disabled={busy || Boolean(draft)} onClick={() => void refresh()}>Перечитать</button>
    </div>
    {error && <div className="notice error" role="alert">{error}</div>}
    {draft && <form className="settings-form group-editor" onSubmit={submit}>
      <label>Название группы<input required value={draft.title} onChange={(event) => setDraft({ ...draft, title: event.target.value })} /></label>
      <div className="input-row group-selector">
        <label>Как искать<select value={selector.kind} onChange={(event) => setSelector({ kind: event.target.value as Kind, value: "" })}>
          {kinds.map(({ value, label }) => <option key={value} value={value}>{label}</option>)}
        </select></label>
        {selector.kind === "argument" && <label>Имя .exe<input value={selector.image ?? ""} placeholder="program.exe"
          onChange={(event) => setSelector({ ...selector, image: event.target.value })} /></label>}
        <label className="grow">Значение<input value={selector.value} placeholder={kinds.find(({ value }) => value === selector.kind)?.hint}
          onChange={(event) => setSelector({ ...selector, value: event.target.value })} /></label>
        <button type="button" className="secondary" disabled={!selector.value.trim() || (selector.kind === "argument" && !selector.image?.trim())}
          onClick={() => {
            setDraft({ ...draft, selectors: [...draft.selectors, { ...selector, value: selector.value.trim() }] });
            setSelector({ ...selector, value: "" });
          }}>Добавить</button>
      </div>
      {draft.selectors.map((entry, index) => <div className="group-entry" key={index}>
        <span>{kinds.find(({ value }) => value === entry.kind)?.label}</span>
        <strong>{entry.image ? entry.image + " · " : ""}{entry.value}</strong>
        <button type="button" className="delete" aria-label="Удалить условие"
          onClick={() => setDraft({ ...draft, selectors: draft.selectors.filter((_, i) => i !== index) })}>×</button>
      </div>)}
      {config.groups.some((group) => group.id !== draft.id) && <fieldset className="group-includes">
        <legend>Включить другие группы</legend>
        {config.groups.filter((group) => group.id !== draft.id).map((group) => <label key={group.id}>
          <input type="checkbox" checked={draft.includes.includes(group.id)} onChange={(event) => setDraft({
            ...draft, includes: event.target.checked ? [...draft.includes, group.id] : draft.includes.filter((id) => id !== group.id),
          })} />{group.title}
        </label>)}
      </fieldset>}
      <div className="actions">
        <button className="primary" disabled={busy || (!draft.selectors.length && !draft.includes.length)}>Сохранить группу</button>
        <button type="button" className="secondary" disabled={busy} onClick={() => setDraft(undefined)}>Отмена</button>
        {config.groups.some((group) => group.id === draft.id) && <button type="button" className="secondary" disabled={busy}
          onClick={() => { if (window.confirm("Удалить эту группу из настроек?")) void save(config.groups.filter((group) => group.id !== draft.id)); }}>Удалить группу</button>}
      </div>
    </form>}
    <div className="group-cards">
      {loaded && !config.groups.length && !draft && <p className="muted">Групп пока нет.</p>}
      {config.groups.map((group) => <section className="group-card" key={group.id}>
        <div><h3>{group.title}</h3><p className="muted">{group.includes.length
          ? group.includes.map((id) => config.groups.find((item) => item.id === id)?.title).join(" + ")
          : "Условий поиска: " + group.selectors.length}</p></div>
        <div className="actions">
          <button className="secondary" disabled={busy || Boolean(draft)} onClick={() => void execute(group, false)}>Посмотреть</button>
          <button className="secondary" disabled={busy || Boolean(draft)} onClick={() => begin(group)}>Изменить</button>
          <button className="danger" disabled={busy || Boolean(draft)} onClick={() => void execute(group, true)}>Завершить</button>
        </div>
      </section>)}
    </div>
    {busy && <p className="muted" role="status">Операция выполняется…</p>}
    {result && <section className="group-result" aria-live="polite">
      <h3>{result.title}</h3>
      <p>{result.stop
        ? "Завершено: " + (result.outcome.stopped?.length ?? 0) + ". Осталось процессов: " + (result.outcome.remaining?.length ?? 0) + "."
        : "Найдено процессов: " + result.outcome.matched.length + "."}</p>
      {result.outcome.caller_in_group && <p className="muted">Группа включает приложение, из которого вызвана команда.</p>}
      {!result.outcome.complete && result.stop && <p className="muted">Некоторые процессы или службы ещё работают. Проверь список ниже.</p>}
      {(result.stop ? result.outcome.remaining ?? [] : result.outcome.matched).map((process) =>
        <div className="group-result-row" key={process.pid}><span>{process.name}</span><span>PID {process.pid}{process.owned ? "" : " · нет доступа"}</span></div>)}
      {result.outcome.services.map((service) => <div className="group-result-row" key={service.name}>
        <span>{service.name}</span><span title={service.error}>{service.status}{service.error ? " · не удалось остановить" : ""}</span>
      </div>)}
    </section>}
  </>;
}
