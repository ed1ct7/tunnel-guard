import { AppWindow, Layers, Pencil, Plus, RefreshCw, Search, Square, Trash2, X } from "lucide-react";
import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { api, errorText } from "../api/backend";
import type { Outcome, ProcessGroup, ProcessGroupsConfig, Selector, SelectorKind } from "../api/types";
import { Button } from "../components/Button";
import { useConfirm } from "../components/ConfirmDialog";
import { Dialog } from "../components/Dialog";
import { Field, InlineError, PageHeader } from "../components/Layout";
import { cx, plural } from "../domain/format";
import {
  cleanSelector,
  groupsIncluding,
  groupTitle,
  kindHint,
  kindLabel,
  newGroup,
  selectorKinds,
  selectorProblem,
} from "../domain/processes";

const POLL_MS = 2500;

const serviceStatus: Record<string, string> = {
  Running: "работает",
  Stopped: "остановлена",
  StopPending: "останавливается",
  StartPending: "запускается",
  Paused: "приостановлена",
  PausePending: "приостанавливается",
  ContinuePending: "возобновляется",
  Missing: "не найдена",
};

function selectorText(selector: Selector) {
  return selector.kind === "argument" ? `${selector.image ?? ""} · ${selector.value}` : selector.value;
}

function sameGroup(left: ProcessGroup, right: ProcessGroup) {
  return JSON.stringify(left) === JSON.stringify(right);
}

type Result = { groupId: string; stop: boolean; outcome: Outcome };

export function ProcessesPage() {
  const confirm = useConfirm();
  const [config, setConfig] = useState<ProcessGroupsConfig>({ groups: [] });
  const [loaded, setLoaded] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [reloading, setReloading] = useState(false);
  const [draft, setDraft] = useState<ProcessGroup | null>(null);
  const [running, setRunning] = useState<{ id: string; stop: boolean } | null>(null);
  const [result, setResult] = useState<Result | null>(null);
  const [runError, setRunError] = useState<{ groupId: string; text: string } | null>(null);

  // The poll must not replace the list under an open editor (its `original` would go stale).
  const editing = useRef(false);
  useEffect(() => {
    editing.current = draft !== null;
  }, [draft]);

  const load = useCallback(
    () =>
      api.loadProcessGroups().then(
        (value) => {
          setConfig(value);
          setLoaded(true);
          setLoadError(null);
        },
        (reason: unknown) => setLoadError(errorText(reason)),
      ),
    [],
  );

  useEffect(() => {
    void load();
    const timer = window.setInterval(() => {
      if (!editing.current)
        api
          .loadProcessGroups()
          .then(setConfig)
          .catch(() => undefined);
    }, POLL_MS);
    return () => window.clearInterval(timer);
  }, [load]);

  async function reload() {
    setReloading(true);
    await load();
    setReloading(false);
  }

  async function execute(group: ProcessGroup, stop: boolean) {
    if (
      stop &&
      !(await confirm({
        tone: "danger",
        title: `Завершить «${group.title}»?`,
        body: (
          <p>
            Все процессы и службы группы будут остановлены принудительно, без вопроса о сохранении.
            Несохранённые данные в этих приложениях пропадут. Можно сначала нажать «Найти», чтобы увидеть, что
            попадёт под команду.
          </p>
        ),
        confirmLabel: "Завершить",
      }))
    ) {
      return;
    }
    setRunning({ id: group.id, stop });
    setRunError(null);
    setResult(null);
    try {
      const outcome = await api.runProcessGroup(group.id, stop, config);
      setResult({ groupId: group.id, stop, outcome });
    } catch (reason) {
      setRunError({ groupId: group.id, text: errorText(reason) });
    } finally {
      setRunning(null);
    }
  }

  const busy = running !== null;
  const editorReason = !loaded ? "Список групп ещё не прочитан." : null;

  return (
    <div className="page page-processes">
      <PageHeader
        title="Процессы"
        lead="Группы приложений вместе с их помощниками и службами. Одна команда найдёт или завершит их все — например, перед сменой сервера, чтобы старые соединения не остались висеть."
        actions={
          <>
            <Button size="sm" variant="ghost" icon={RefreshCw} busy={reloading} onClick={() => void reload()}>
              Перечитать
            </Button>
            {!(loaded && config.groups.length === 0) && (
              <Button
                size="sm"
                variant="primary"
                icon={Plus}
                disabledReason={editorReason}
                onClick={() => setDraft(newGroup())}
              >
                Новая группа
              </Button>
            )}
          </>
        }
      />

      {loadError && <InlineError>Не удалось прочитать группы: {loadError}</InlineError>}

      {loaded && config.groups.length === 0 && (
        <div className="panel empty-state">
          <AppWindow size={28} aria-hidden />
          <h2>Групп пока нет</h2>
          <p>
            Создай группу, например «Браузер для работы»: укажи browser.exe и его службу обновления. Потом её
            можно найти или завершить одной кнопкой.
          </p>
          <Button variant="primary" icon={Plus} onClick={() => setDraft(newGroup())}>
            Новая группа
          </Button>
        </div>
      )}

      <div className="group-cards">
        {config.groups.map((group) => {
          const isRunning = running?.id === group.id;
          const own = result?.groupId === group.id ? result : null;
          const error = runError?.groupId === group.id ? runError.text : null;
          return (
            <section className="panel group-card" key={group.id} aria-labelledby={`group-${group.id}`}>
              <header className="group-card-head">
                <h2 id={`group-${group.id}`}>{group.title}</h2>
                <span className="group-card-actions">
                  <Button
                    size="sm"
                    variant="ghost"
                    icon={Search}
                    busy={isRunning && !running.stop}
                    disabledReason={busy && !isRunning ? "Дождись окончания другой команды." : null}
                    disabled={isRunning}
                    onClick={() => void execute(group, false)}
                  >
                    Найти
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    icon={Pencil}
                    disabled={busy}
                    onClick={() => setDraft(structuredClone(group))}
                  >
                    Изменить
                  </Button>
                  <Button
                    size="sm"
                    variant="danger"
                    icon={Square}
                    busy={isRunning && running.stop}
                    disabledReason={busy && !isRunning ? "Дождись окончания другой команды." : null}
                    disabled={isRunning}
                    onClick={() => void execute(group, true)}
                  >
                    Завершить
                  </Button>
                </span>
              </header>
              <div className="chips">
                {group.selectors.map((selector, index) => (
                  <span className="chip" key={index} title={kindLabel(selector.kind)}>
                    <span className="chip-kind">{kindLabel(selector.kind)}</span>
                    <span className="mono">{selectorText(selector)}</span>
                  </span>
                ))}
                {group.includes.map((id) => (
                  <span className="chip chip-group" key={id}>
                    <Layers size={13} aria-hidden />
                    <span className="chip-kind">группа</span>
                    {groupTitle(config.groups, id)}
                  </span>
                ))}
                {!group.selectors.length && !group.includes.length && (
                  <span className="muted">Нет условий поиска.</span>
                )}
              </div>
              {error && <InlineError>{error}</InlineError>}
              {own && <OutcomeView result={own} onClose={() => setResult(null)} />}
            </section>
          );
        })}
      </div>

      <GroupEditor
        draft={draft}
        config={config}
        onChange={setDraft}
        onClose={() => setDraft(null)}
        onSaved={(next) => {
          setConfig(next);
          setDraft(null);
        }}
      />
    </div>
  );
}

function OutcomeView({ result, onClose }: { result: Result; onClose: () => void }) {
  const { outcome, stop } = result;
  const processes = stop ? (outcome.remaining ?? []) : outcome.matched;
  const stopped = outcome.stopped?.length ?? 0;
  const remaining = outcome.remaining?.length ?? 0;
  const servicesLeft = outcome.services.filter((service) => !["Stopped", "Missing"].includes(service.status));

  let headline: string;
  let tone: "good" | "warn" | "info";
  if (stop) {
    if (outcome.complete) {
      tone = "good";
      headline = stopped
        ? `Завершено ${stopped} ${plural(stopped, "процесс", "процесса", "процессов")}. Ничего не осталось.`
        : "Процессов группы не было запущено — завершать нечего.";
    } else {
      tone = "warn";
      headline = `Завершено ${stopped}, ещё работают: ${remaining} ${plural(remaining, "процесс", "процесса", "процессов")}${
        servicesLeft.length
          ? ` и ${servicesLeft.length} ${plural(servicesLeft.length, "служба", "службы", "служб")}`
          : ""
      }.`;
    }
  } else {
    tone = "info";
    const count = outcome.matched.length;
    const services = outcome.services.length;
    const found = [
      count ? `${count} ${plural(count, "процесс", "процесса", "процессов")}` : "",
      services ? `${services} ${plural(services, "служба", "службы", "служб")}` : "",
    ]
      .filter(Boolean)
      .join(" и ");
    headline = found
      ? `Найдено: ${found}. Ничего не завершено.`
      : "Сейчас ничего из этой группы не запущено.";
  }

  return (
    <div className={cx("outcome", `outcome-${tone}`)} role="status">
      <div className="outcome-head">
        <strong>{headline}</strong>
        <Button
          size="sm"
          variant="ghost"
          icon={X}
          aria-label="Скрыть результат"
          title="Скрыть"
          onClick={onClose}
        />
      </div>
      {outcome.caller_in_group && (
        <p className="outcome-note">
          В группу входит программа, из которой запущена команда, — её Tunnel Guard не трогал.
        </p>
      )}
      {stop && !outcome.complete && (
        <p className="outcome-note">
          Оставшиеся процессы или службы не дали себя остановить. Обычно помогает запуск от имени
          администратора.
        </p>
      )}
      {(processes.length > 0 || outcome.services.length > 0) && (
        <table className="outcome-table">
          <thead>
            <tr>
              <th scope="col">{stop ? "Ещё работает" : "Найдено"}</th>
              <th scope="col">Подробности</th>
            </tr>
          </thead>
          <tbody>
            {processes.map((process) => (
              <tr key={process.pid}>
                <td className="mono">{process.name}</td>
                <td>
                  PID <span className="num">{process.pid}</span>
                  {process.owned ? "" : " · другой пользователь, нужны права администратора"}
                </td>
              </tr>
            ))}
            {outcome.services.map((service) => (
              <tr key={service.name}>
                <td className="mono">{service.name}</td>
                <td title={service.error ?? undefined}>
                  служба {serviceStatus[service.status] ?? service.status}
                  {service.error ? ` · не удалось остановить: ${service.error}` : ""}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

const emptySelector: Selector = { kind: "name", value: "" };
const closedGroup: ProcessGroup = { id: "", title: "", selectors: [], includes: [] };

function GroupEditor({
  draft,
  config,
  onChange,
  onClose,
  onSaved,
}: {
  draft: ProcessGroup | null;
  config: ProcessGroupsConfig;
  onChange: (group: ProcessGroup) => void;
  onClose: () => void;
  onSaved: (config: ProcessGroupsConfig) => void;
}) {
  const confirm = useConfirm();
  const [selector, setSelector] = useState<Selector>(emptySelector);
  const [selectorError, setSelectorError] = useState<string | null>(null);
  const [titleError, setTitleError] = useState<string | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [openedFor, setOpenedFor] = useState<string | null>(null);

  // Reset the form when another group is opened (state adjusted during render, not in an effect).
  const draftId = draft?.id ?? null;
  if (draftId !== openedFor) {
    setOpenedFor(draftId);
    setSelector(emptySelector);
    setSelectorError(null);
    setTitleError(null);
    setSaveError(null);
  }

  // The dialog stays mounted so it can hand focus back when it closes; its content renders only while open.
  const current = draft ?? closedGroup;
  const original = config.groups.find((group) => group.id === current.id) ?? null;
  const changed = original
    ? !sameGroup(original, current)
    : current.title.trim() !== "" || current.selectors.length > 0;
  const blocked = groupsIncluding(config.groups, current.id);
  const others = config.groups.filter((group) => group.id !== current.id);

  async function close() {
    if (
      changed &&
      !(await confirm({
        title: "Закрыть без сохранения?",
        body: <p>Изменения в группе «{current.title.trim() || "без названия"}» пропадут.</p>,
        confirmLabel: "Закрыть без сохранения",
        cancelLabel: "Продолжить правку",
        tone: "danger",
      }))
    ) {
      return;
    }
    onClose();
  }

  function addSelector() {
    const candidate = cleanSelector(selector);
    const problem = selectorProblem(candidate);
    if (problem) {
      setSelectorError(problem);
      return;
    }
    onChange({ ...current, selectors: [...current.selectors, candidate] });
    setSelector({ ...emptySelector, kind: selector.kind });
    setSelectorError(null);
  }

  async function persist(groups: ProcessGroup[]) {
    setSaving(true);
    setSaveError(null);
    const next = { groups };
    try {
      await api.saveProcessGroups(next, config);
      onSaved(next);
    } catch (reason) {
      setSaveError(errorText(reason));
    } finally {
      setSaving(false);
    }
  }

  function submit(event: FormEvent) {
    event.preventDefault();
    const title = current.title.trim();
    if (!title) {
      setTitleError("Дай группе название.");
      return;
    }
    if (!current.selectors.length && !current.includes.length) {
      setSelectorError("Добавь хотя бы одно условие или включи другую группу.");
      return;
    }
    const group = { ...current, title, selectors: current.selectors.map(cleanSelector) };
    void persist(
      original
        ? config.groups.map((item) => (item.id === group.id ? group : item))
        : [...config.groups, group],
    );
  }

  async function remove() {
    const users = config.groups.filter((group) => group.includes.includes(current.id));
    const ok = await confirm({
      tone: "danger",
      title: `Удалить группу «${original?.title ?? current.title}»?`,
      body: (
        <>
          <p>Группа пропадёт из настроек. Сами программы не затрагиваются.</p>
          {users.length > 0 && (
            <p>
              Она также будет убрана из {plural(users.length, "группы", "групп", "групп")}:{" "}
              {users.map((group) => `«${group.title}»`).join(", ")}.
            </p>
          )}
        </>
      ),
      confirmLabel: "Удалить группу",
    });
    if (!ok) return;
    void persist(
      config.groups
        .filter((group) => group.id !== current.id)
        .map((group) => ({ ...group, includes: group.includes.filter((id) => id !== current.id) })),
    );
  }

  return (
    <Dialog
      open={draft !== null}
      size="lg"
      onClose={() => void close()}
      title={original ? `Группа «${original.title}»` : "Новая группа"}
      footer={
        <>
          {original && (
            <Button
              variant="ghost"
              className="dialog-footer-start"
              icon={Trash2}
              disabled={saving}
              onClick={() => void remove()}
            >
              Удалить группу
            </Button>
          )}
          <Button disabled={saving} onClick={() => void close()}>
            Отмена
          </Button>
          <Button type="submit" form="group-editor" variant="primary" busy={saving}>
            Сохранить группу
          </Button>
        </>
      }
    >
      <form id="group-editor" className="group-editor" onSubmit={submit} noValidate>
        <Field label="Название" error={titleError}>
          {(props) => (
            <input
              {...props}
              data-autofocus
              value={current.title}
              placeholder="Например, Браузер для работы"
              onChange={(event) => {
                onChange({ ...current, title: event.target.value });
                setTitleError(null);
              }}
            />
          )}
        </Field>

        <fieldset className="editor-section">
          <legend>Что входит в группу</legend>
          {current.selectors.length > 0 ? (
            <ul className="selector-list">
              {current.selectors.map((entry, index) => (
                <li key={index}>
                  <span className="chip-kind">{kindLabel(entry.kind)}</span>
                  <span className="mono selector-value">{selectorText(entry)}</span>
                  <Button
                    size="sm"
                    variant="ghost"
                    icon={X}
                    aria-label={`Убрать условие ${selectorText(entry)}`}
                    title="Убрать условие"
                    onClick={() =>
                      onChange({ ...current, selectors: current.selectors.filter((_, i) => i !== index) })
                    }
                  />
                </li>
              ))}
            </ul>
          ) : (
            <p className="muted">Условий пока нет. Добавь программу, службу или фрагмент командной строки.</p>
          )}
          <div className="selector-add">
            <Field label="Как искать" className="field-kind">
              {(props) => (
                <select
                  {...props}
                  value={selector.kind}
                  onChange={(event) => {
                    setSelector({ kind: event.target.value as SelectorKind, value: "" });
                    setSelectorError(null);
                  }}
                >
                  {selectorKinds.map((entry) => (
                    <option key={entry.value} value={entry.value}>
                      {entry.label}
                    </option>
                  ))}
                </select>
              )}
            </Field>
            {selector.kind === "argument" && (
              <Field label="В программе" className="field-image">
                {(props) => (
                  <input
                    {...props}
                    className="mono"
                    value={selector.image ?? ""}
                    placeholder="program.exe"
                    spellCheck={false}
                    onChange={(event) => {
                      setSelector({ ...selector, image: event.target.value });
                      setSelectorError(null);
                    }}
                  />
                )}
              </Field>
            )}
            <Field label="Значение" className="field-grow" error={selectorError}>
              {(props) => (
                <input
                  {...props}
                  className="mono"
                  value={selector.value}
                  placeholder={kindHint(selector.kind)}
                  spellCheck={false}
                  onChange={(event) => {
                    setSelector({ ...selector, value: event.target.value });
                    setSelectorError(null);
                  }}
                  onKeyDown={(event) => {
                    if (event.key === "Enter") {
                      event.preventDefault();
                      addSelector();
                    }
                  }}
                />
              )}
            </Field>
            <Button icon={Plus} className="selector-add-button" onClick={addSelector}>
              Добавить
            </Button>
          </div>
        </fieldset>

        {others.length > 0 && (
          <fieldset className="editor-section includes">
            <legend>Включить другие группы</legend>
            <p className="muted">Общая группа выполняет команду сразу для всех включённых.</p>
            {others.map((group) => {
              const cycle = blocked.has(group.id);
              const checked = current.includes.includes(group.id);
              return (
                <label key={group.id} className={cx("check-row", cycle && "check-row-disabled")}>
                  <input
                    type="checkbox"
                    checked={checked}
                    disabled={cycle && !checked}
                    onChange={(event) =>
                      onChange({
                        ...current,
                        includes: event.target.checked
                          ? [...current.includes, group.id]
                          : current.includes.filter((id) => id !== group.id),
                      })
                    }
                  />
                  <span>{group.title}</span>
                  {cycle && <span className="muted"> — уже включает эту группу</span>}
                </label>
              );
            })}
          </fieldset>
        )}

        {saveError && <InlineError>{saveError}</InlineError>}
      </form>
    </Dialog>
  );
}
