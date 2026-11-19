import {
  Ban,
  FolderOpen,
  Globe,
  Network,
  Plus,
  RefreshCw,
  Search,
  Trash2,
  Undo2,
  Upload,
} from "lucide-react";
import { useEffect, useMemo, useState, type FormEvent } from "react";
import { useApp } from "../AppContext";
import { api, errorText } from "../api/backend";
import { Button } from "../components/Button";
import { useConfirm } from "../components/ConfirmDialog";
import { Banner, Field, InlineError, PageHeader, SectionHead } from "../components/Layout";
import { useToasts } from "../components/Toasts";
import { cx, plural } from "../domain/format";
import {
  DIRECT_DEFAULT,
  displayRule,
  findRule,
  isVpnOnly,
  ruleKinds,
  ruleValueProblem,
  upsertRule,
  withMode,
  type RouteKind,
} from "../domain/rules";

const modes = [
  {
    value: "profile",
    title: "Как в профиле VPN",
    text: "Правила из списка идут по своему маршруту, остальное решает профиль v2rayN.",
  },
  {
    value: "vpn-only",
    title: "Только выбранное через VPN",
    text: "Через VPN идёт только то, что в списке. Всё остальное — напрямую, даже при включённой защите.",
  },
] as const;

const routeIcons: Record<RouteKind, typeof Globe> = { vpn: Network, direct: Globe, reject: Ban };

/** VPN routes from the running core, keyed by what they depend on so stale lists are never shown. */
function useVpnTargets(enabled: boolean, key: string) {
  const [state, setState] = useState<{ key: string; list: string[] }>({ key: "", list: [] });
  useEffect(() => {
    if (!enabled) return;
    let active = true;
    api
      .vpnTargets()
      .then((list) => {
        if (active) setState({ key, list });
      })
      .catch(() => {
        if (active) setState({ key, list: [] });
      });
    return () => {
      active = false;
    };
  }, [enabled, key]);
  return state.key === key ? state.list : [];
}

export function RoutingPage() {
  const app = useApp();
  const toasts = useToasts();
  const confirm = useConfirm();
  const { config, coreRules, status, diagnosis } = app;
  const { dispatch, rules, savedRules, configured } = config;

  const [kindIndex, setKindIndex] = useState(0);
  const [value, setValue] = useState("");
  const [route, setRoute] = useState("");
  const [formError, setFormError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [routeFilter, setRouteFilter] = useState<"all" | RouteKind>("all");
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [applying, setApplying] = useState(false);
  const [applyError, setApplyError] = useState<string | null>(null);
  const [picking, setPicking] = useState(false);

  const configuredClient = Boolean(configured.client_path);
  const targets = useVpnTargets(
    configuredClient,
    `${configured.client_path}|${configured.proxy_port}|${String(status?.adapter_up)}`,
  );
  const { load: loadCoreRules } = coreRules;
  useEffect(() => {
    void loadCoreRules();
  }, [loadCoreRules]);

  const kind = ruleKinds[kindIndex] ?? ruleKinds[0]!;
  const vpnOnly = isVpnOnly(rules);
  const selectedRoute = route || (vpnOnly ? (targets[0] ?? "") : "DIRECT");
  const existing = value.trim() ? findRule(rules, kind.code, value.trim()) : -1;
  const saved = useMemo(() => new Set(savedRules), [savedRules]);
  const mixin = diagnosis.diagnosis?.checks.find((check) => check.id === "mixin");

  const explicit = rules.flatMap((rule, index) => (rule === DIRECT_DEFAULT ? [] : [{ rule, index }]));
  const needle = query.trim().toLowerCase();
  const visible = explicit.filter(({ rule }) => {
    const view = displayRule(rule);
    if (routeFilter !== "all" && view.routeKind !== routeFilter) return false;
    return !needle || rule.toLowerCase().includes(needle) || view.kind.toLowerCase().includes(needle);
  });

  function setMode(onlySelected: boolean) {
    dispatch({ type: "editRules", rules: withMode(rules, onlySelected) });
    setRoute("");
    setFormError(null);
  }

  function addRule(event: FormEvent) {
    event.preventDefault();
    const trimmed = value.trim();
    const problem = ruleValueProblem(kind.code, trimmed);
    if (problem) {
      setFormError(problem);
      return;
    }
    if (!selectedRoute) {
      setFormError("Запусти VPN, чтобы выбрать маршрут через него, или выбери «Напрямую».");
      return;
    }
    dispatch({ type: "editRules", rules: upsertRule(rules, kind.code, trimmed, selectedRoute) });
    setValue("");
    setFormError(null);
  }

  async function pickProgram() {
    setPicking(true);
    try {
      const selected = await api.pickExe();
      if (selected) setValue(selected);
    } catch (reason) {
      setFormError(errorText(reason));
    } finally {
      setPicking(false);
    }
  }

  async function applyNow() {
    const ok = await confirm({
      title: "Применить правила в работающем Mihomo?",
      body: (
        <p>
          Tunnel Guard передаст сохранённый список ядру без перезапуска v2rayN. Активные соединения могут на
          мгновение оборваться — загрузки и звонки переподключатся.
        </p>
      ),
      confirmLabel: "Применить",
    });
    if (!ok) return;
    setApplying(true);
    setApplyError(null);
    try {
      const state = await coreRules.reload();
      if (state.state === "applied") {
        toasts.push({ tone: "success", text: "Готово: Mihomo использует сохранённые правила." });
      } else {
        setApplyError(
          state.detail ?? "Ядро перечитало конфигурацию, но список всё ещё отличается от сохранённого.",
        );
      }
    } catch (reason) {
      setApplyError(errorText(reason));
    } finally {
      setApplying(false);
    }
  }

  async function save() {
    if (
      vpnOnly &&
      savedRules.at(-1) !== DIRECT_DEFAULT &&
      !(await confirm({
        tone: "danger",
        title: "Включить режим «Только выбранное через VPN»?",
        body: <p>Остальной трафик пойдёт напрямую, даже при включённой защите.</p>,
        confirmLabel: "Сохранить и включить",
      }))
    ) {
      return;
    }
    setSaving(true);
    setSaveError(null);
    try {
      await api.saveRules(rules, savedRules, configured);
      try {
        dispatch({ type: "rulesLoaded", rules: await api.loadRules() });
      } catch {
        // The file watcher delivers the new list anyway.
      }
      const state = await coreRules.load();
      toasts.push(
        state?.state === "pending"
          ? {
              tone: "info",
              title: "Правила сохранены",
              text: "Работающий Mihomo пока использует старый список.",
              action: { label: "Применить сейчас", onClick: () => void applyNow() },
            }
          : { tone: "success", text: "Правила сохранены." },
      );
    } catch (reason) {
      setSaveError(errorText(reason));
    } finally {
      setSaving(false);
    }
  }

  const changes = config.ruleChanges;
  const noClientReason = configuredClient ? null : "Сначала укажи v2rayN во вкладке «Подключение».";

  return (
    <div className="page page-routing">
      <PageHeader
        title="Маршрутизация"
        lead="Какие сайты и программы идут через VPN, а какие — напрямую. Список хранится в Mixin.yaml профиля v2rayN."
        actions={
          <Button size="sm" variant="ghost" icon={RefreshCw} onClick={() => void app.reloadConfig()}>
            Перечитать
          </Button>
        }
      />

      {!configuredClient && config.loaded && (
        <Banner
          tone="info"
          title="Подключение не настроено"
          actions={
            <Button size="sm" onClick={() => app.navigate("connection")}>
              Открыть «Подключение»
            </Button>
          }
        >
          Правила хранятся рядом с v2rayN, поэтому сначала укажи, где он установлен.
        </Banner>
      )}

      {mixin && mixin.status !== "ok" && mixin.status !== "skip" && (
        <Banner tone="warn" title="Правила не применятся">
          В v2rayN выключен Enable Mixin Content. Включи его в настройках Mihomo — без него ядро игнорирует
          этот список.
        </Banner>
      )}

      {!config.rulesDirty && coreRules.coreRules?.state === "pending" && (
        <Banner
          tone="warn"
          title="Правила сохранены, но работающий Mihomo использует старый список"
          actions={
            <Button size="sm" variant="primary" icon={Upload} busy={applying} onClick={() => void applyNow()}>
              Применить сейчас
            </Button>
          }
        >
          Можно применить их сразу или перезапустить ядро в v2rayN.
          {applyError && <InlineError>{applyError}</InlineError>}
        </Banner>
      )}
      {!config.rulesDirty && coreRules.coreRules?.state === "unknown" && configuredClient && (
        <p className="core-note">
          Не удалось сравнить с работающим Mihomo
          {coreRules.coreRules.detail ? `: ${coreRules.coreRules.detail}` : "."}
        </p>
      )}
      {!config.rulesDirty && coreRules.coreRules?.state === "applied" && (
        <p className="core-note core-note-good">Работающий Mihomo использует сохранённый список.</p>
      )}

      <fieldset className="segmented">
        <legend>Что делать с трафиком вне списка</legend>
        {modes.map((mode) => {
          const checked = (mode.value === "vpn-only") === vpnOnly;
          return (
            <label key={mode.value} className={cx("segment", checked && "segment-on")}>
              <input
                type="radio"
                name="routing-mode"
                value={mode.value}
                checked={checked}
                onChange={() => setMode(mode.value === "vpn-only")}
              />
              <span className="segment-title">{mode.title}</span>
              <span className="segment-text">{mode.text}</span>
            </label>
          );
        })}
      </fieldset>

      <form className="panel rule-form" onSubmit={addRule} noValidate>
        <SectionHead title={existing >= 0 ? "Изменить маршрут правила" : "Новое правило"} />
        <div className="rule-form-row">
          <Field label="Что сравнивать" className="field-kind">
            {(props) => (
              <select
                {...props}
                value={kindIndex}
                onChange={(event) => {
                  setKindIndex(Number(event.target.value));
                  setValue("");
                  setFormError(null);
                }}
              >
                {ruleKinds.map((entry, index) => (
                  <option key={entry.code} value={index}>
                    {entry.label}
                  </option>
                ))}
              </select>
            )}
          </Field>
          <Field label="Адрес или программа" className="field-grow" error={formError}>
            {(props) => (
              <div className="input-with-button">
                <input
                  {...props}
                  className="mono"
                  value={value}
                  placeholder={kind.example}
                  spellCheck={false}
                  autoComplete="off"
                  onChange={(event) => {
                    setValue(event.target.value);
                    setFormError(null);
                  }}
                />
                {kind.code === "PROCESS-PATH" && (
                  <Button icon={FolderOpen} busy={picking} onClick={() => void pickProgram()}>
                    Обзор…
                  </Button>
                )}
              </div>
            )}
          </Field>
          <Field
            label="Маршрут"
            className="field-route"
            hint={
              !targets.length && configuredClient ? "VPN-маршруты появятся, когда Mihomo запущен." : undefined
            }
          >
            {(props) => (
              <select {...props} value={selectedRoute} onChange={(event) => setRoute(event.target.value)}>
                {!selectedRoute && (
                  <option value="" disabled>
                    Подключи VPN
                  </option>
                )}
                <option value="DIRECT">Напрямую</option>
                {targets.map((target) => (
                  <option value={target} key={target}>
                    VPN: {target}
                  </option>
                ))}
              </select>
            )}
          </Field>
          <Button
            type="submit"
            variant="primary"
            icon={Plus}
            className="rule-submit"
            disabledReason={noClientReason}
          >
            {existing >= 0 ? "Заменить" : "Добавить"}
          </Button>
        </div>
      </form>

      <section className="panel rules" aria-labelledby="rules-title">
        <header className="panel-head">
          <h2 id="rules-title">Правила</h2>
          <span className="panel-summary">
            {explicit.length} {plural(explicit.length, "правило", "правила", "правил")}, первое совпавшее
            важнее
          </span>
          <span className="panel-head-side rules-tools">
            <label className="search">
              <Search size={14} aria-hidden />
              <span className="sr-only">Поиск по правилам</span>
              <input
                type="search"
                value={query}
                placeholder="Поиск"
                onChange={(event) => setQuery(event.target.value)}
              />
            </label>
            <label className="sr-only" htmlFor="route-filter">
              Показать маршрут
            </label>
            <select
              id="route-filter"
              className="select-sm"
              value={routeFilter}
              onChange={(event) => setRouteFilter(event.target.value as "all" | RouteKind)}
            >
              <option value="all">Все маршруты</option>
              <option value="vpn">Через VPN</option>
              <option value="direct">Напрямую</option>
              <option value="reject">Блокировать</option>
            </select>
          </span>
        </header>
        {explicit.length === 0 ? (
          <p className="empty">
            Правил пока нет. Добавь домен или программу выше — например, чтобы пустить банк мимо VPN.
          </p>
        ) : visible.length === 0 ? (
          <p className="empty">Ничего не найдено. Измени поиск или фильтр.</p>
        ) : (
          <table className="rules-table">
            <thead>
              <tr>
                <th scope="col" className="col-index">
                  <span className="sr-only">Приоритет</span>№
                </th>
                <th scope="col">Тип</th>
                <th scope="col">Адрес или программа</th>
                <th scope="col">Маршрут</th>
                <th scope="col" className="col-action">
                  <span className="sr-only">Удалить</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {visible.map(({ rule, index }) => {
                const row = displayRule(rule);
                const RouteIcon = routeIcons[row.routeKind];
                const isNew = !saved.has(rule);
                return (
                  <tr key={rule + index} className={cx(isNew && "row-changed")}>
                    <td className="col-index num">{index + 1}</td>
                    <td>{row.kind}</td>
                    <td title={row.target}>
                      <span className="cell-target-inner">
                        <span className="mono cell-text">{row.target}</span>
                        {isNew && <span className="row-tag">не сохранено</span>}
                      </span>
                    </td>
                    <td>
                      <span className={cx("route", `route-${row.routeKind}`)}>
                        <RouteIcon size={13} aria-hidden />
                        {row.route}
                      </span>
                    </td>
                    <td className="col-action">
                      <Button
                        size="sm"
                        variant="ghost"
                        icon={Trash2}
                        aria-label={`Удалить правило ${row.target}`}
                        title="Удалить правило"
                        onClick={() =>
                          dispatch({ type: "editRules", rules: rules.filter((_, i) => i !== index) })
                        }
                      />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
        <p className="rules-rest">Всё остальное: {vpnOnly ? "напрямую" : "по правилам профиля v2rayN"}</p>
      </section>

      {config.rulesDirty && (
        <div className="savebar" role="region" aria-label="Несохранённые изменения">
          <span className="savebar-count">
            <strong className="num">{changes}</strong>{" "}
            {plural(changes, "несохранённое изменение", "несохранённых изменения", "несохранённых изменений")}
          </span>
          {saveError && (
            <span className="savebar-error" role="alert">
              {saveError}
            </span>
          )}
          <span className="savebar-actions">
            <Button
              variant="ghost"
              icon={Undo2}
              disabled={saving}
              onClick={() => {
                dispatch({ type: "revertRules" });
                setSaveError(null);
              }}
            >
              Отменить
            </Button>
            <Button
              variant="primary"
              busy={saving}
              disabledReason={noClientReason}
              onClick={() => void save()}
            >
              Сохранить
            </Button>
          </span>
        </div>
      )}
    </div>
  );
}
