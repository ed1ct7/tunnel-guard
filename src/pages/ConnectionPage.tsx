import { FolderOpen, RefreshCw, Save, ScanSearch, Undo2 } from "lucide-react";
import { useState, type FormEvent } from "react";
import { useApp } from "../AppContext";
import { api, errorText } from "../api/backend";
import type { CheckId, Settings } from "../api/types";
import { Button } from "../components/Button";
import { Checklist } from "../components/Checklist";
import { Banner, Field, InlineError, PageHeader } from "../components/Layout";
import { useToasts } from "../components/Toasts";
import type { CheckFixLink } from "../domain/checks";
import {
  CONTROLLER_OFFSET,
  MAX_PROXY_PORT,
  protectionBackendLabels,
  settingsEditable,
  settingsProblems,
} from "../domain/settings";

const connectionChecks: readonly CheckId[] = ["client", "core", "mixin", "proxy", "controller", "adapter"];

type Detection = { candidates: string[]; note: string | null; found: string | null };

export function ConnectionPage() {
  const app = useApp();
  const toasts = useToasts();
  const { config, status, diagnosis } = app;
  const { settings, configured, dispatch } = config;

  const [touched, setTouched] = useState<Partial<Record<keyof Settings, boolean>>>({});
  const [submitted, setSubmitted] = useState(false);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [detecting, setDetecting] = useState(false);
  const [detection, setDetection] = useState<Detection | null>(null);
  const [detectError, setDetectError] = useState<string | null>(null);
  const [picking, setPicking] = useState(false);

  const problems = settingsProblems(settings);
  const invalid = Object.keys(problems).length > 0;
  const shown = (field: keyof Settings) => (submitted || touched[field] ? (problems[field] ?? null) : null);
  const locked = status ? !settingsEditable(status.state) : false;

  function edit(patch: Partial<Settings>) {
    dispatch({ type: "editSettings", settings: { ...settings, ...patch } });
    setSaveError(null);
  }

  function touch(field: keyof Settings) {
    setTouched((current) => (current[field] ? current : { ...current, [field]: true }));
  }

  async function pickClient() {
    setPicking(true);
    try {
      const selected = await api.pickExe();
      if (selected) {
        edit({ client_path: selected });
        touch("client_path");
      }
    } catch (reason) {
      setSaveError(errorText(reason));
    } finally {
      setPicking(false);
    }
  }

  async function detect() {
    setDetecting(true);
    setDetectError(null);
    try {
      const result = await api.detectClient();
      if (result.settings) {
        const { client_path, adapter, proxy_port } = result.settings;
        edit({ client_path, adapter, proxy_port });
        setTouched({ client_path: true, adapter: true, proxy_port: true });
      }
      setDetection({
        candidates: result.candidates.filter((path) => path !== result.settings?.client_path),
        note: result.note,
        found: result.settings?.client_path ?? null,
      });
    } catch (reason) {
      setDetection(null);
      setDetectError(errorText(reason));
    } finally {
      setDetecting(false);
    }
  }

  async function save(event: FormEvent) {
    event.preventDefault();
    setSubmitted(true);
    if (invalid || locked || !config.settingsDirty) return;
    const next = { ...settings, client_path: settings.client_path.trim(), adapter: settings.adapter.trim() };
    setSaving(true);
    setSaveError(null);
    try {
      await api.saveSettings(next, configured);
      dispatch({ type: "settingsSaved", settings: next });
      setSubmitted(false);
      setTouched({});
      setDetection(null);
      toasts.push({ tone: "success", text: "Подключение сохранено." });
      try {
        dispatch({ type: "rulesLoaded", rules: await api.loadRules() });
      } catch (reason) {
        toasts.push({ tone: "error", title: "Не удалось прочитать правила", text: errorText(reason) });
      }
      await app.refreshAll();
    } catch (reason) {
      setSaveError(errorText(reason));
    } finally {
      setSaving(false);
    }
  }

  function fix(link: CheckFixLink) {
    if (link === "client") void app.openClient();
  }

  const saveReason = locked
    ? "Сначала выключи защиту: подключение меняется только при выключенной защите."
    : !config.settingsDirty
      ? "Изменений нет."
      : null;

  return (
    <div className="page page-connection">
      <PageHeader
        title="Подключение"
        lead="Где установлен v2rayN и как Tunnel Guard узнаёт туннель. Эти данные нужны, чтобы проверять VPN и читать правила."
        actions={
          <Button size="sm" variant="ghost" icon={RefreshCw} onClick={() => void app.reloadConfig()}>
            Перечитать
          </Button>
        }
      />

      {locked && (
        <Banner
          tone="info"
          title="Защита включена — подключение только для чтения"
          actions={
            <Button size="sm" onClick={() => app.navigate("overview")}>
              К обзору
            </Button>
          }
        >
          Чтобы изменить подключение или способ защиты, сначала выключи защиту.
        </Banner>
      )}

      <form className="panel connection-form" onSubmit={(event) => void save(event)} noValidate>
        <div className="detect">
          <div className="detect-text">
            <h2>Найти автоматически</h2>
            <p>
              Tunnel Guard поищет запущенный и установленный v2rayN и прочитает порт и имя адаптера из его
              настроек.
            </p>
          </div>
          <Button icon={ScanSearch} busy={detecting} onClick={() => void detect()}>
            Найти автоматически
          </Button>
        </div>
        {detectError && <InlineError>{detectError}</InlineError>}
        {detection && (
          <div className="detect-result" role="status">
            <p>
              {detection.found
                ? "Нашли v2rayN и заполнили поля ниже. Проверь и сохрани."
                : detection.candidates.length
                  ? "Нашли несколько копий v2rayN. Выбери нужную:"
                  : "v2rayN не нашёлся. Укажи путь вручную через «Обзор…»."}
            </p>
            {detection.note && <p className="detect-note">{detection.note}</p>}
            {detection.candidates.length > 0 && (
              <div className="chips" role="group" aria-label="Другие найденные копии v2rayN">
                {detection.found && <span className="chips-label">Другие копии:</span>}
                {detection.candidates.map((path) => (
                  <button
                    type="button"
                    key={path}
                    className="chip chip-button mono"
                    title="Использовать эту копию"
                    onClick={() => {
                      edit({ client_path: path });
                      touch("client_path");
                    }}
                  >
                    {path}
                  </button>
                ))}
              </div>
            )}
          </div>
        )}

        <Field
          label="Программа v2rayN"
          hint="Файл v2rayN.exe. Рядом с ним лежит профиль Mihomo и список правил."
          error={shown("client_path")}
        >
          {(props) => (
            <div className="input-with-button">
              <input
                {...props}
                className="mono"
                value={settings.client_path}
                placeholder="C:\v2rayN\v2rayN.exe"
                spellCheck={false}
                autoComplete="off"
                onChange={(event) => edit({ client_path: event.target.value })}
                onBlur={() => touch("client_path")}
              />
              <Button icon={FolderOpen} busy={picking} onClick={() => void pickClient()}>
                Обзор…
              </Button>
            </div>
          )}
        </Field>

        <div className="field-row">
          <Field
            label="Сетевой адаптер туннеля"
            className="field-grow"
            hint="Точное имя TUN-адаптера из сетевых подключений Windows. Mihomo по умолчанию называет его Meta, профиль v2rayN может задать своё — «Найти автоматически» подставит нужное."
            error={shown("adapter")}
          >
            {(props) => (
              <input
                {...props}
                value={settings.adapter}
                spellCheck={false}
                autoComplete="off"
                onChange={(event) => edit({ adapter: event.target.value })}
                onBlur={() => touch("adapter")}
              />
            )}
          </Field>
          <Field
            label="Порт прокси"
            className="field-port"
            hint={`Как «Локальный порт» в v2rayN, от 1 до ${MAX_PROXY_PORT}.`}
            error={shown("proxy_port")}
          >
            {(props) => (
              <input
                {...props}
                className="num"
                inputMode="numeric"
                value={Number.isNaN(settings.proxy_port) ? "" : String(settings.proxy_port)}
                onChange={(event) => {
                  const digits = event.target.value.replace(/\D/g, "").slice(0, 5);
                  edit({ proxy_port: digits ? Number(digits) : Number.NaN });
                }}
                onBlur={() => touch("proxy_port")}
              />
            )}
          </Field>
        </div>
        <p className="controller-note">
          Порт контроллера Mihomo Tunnel Guard находит сам: берёт его из конфигурации, которую создаёт v2rayN,
          а если её нет — порт прокси + {CONTROLLER_OFFSET}. Через контроллер он узнаёт режим, TUN и выбранные
          серверы.
        </p>

        <Field label="Способ защиты" hint="WFP — тестовый режим для Windows Home.">
          {(props) => (
            <select
              {...props}
              value={settings.protection_backend}
              disabled={locked}
              onChange={(event) =>
                edit({
                  protection_backend: event.target.value === "wfp" ? "wfp" : "group_policy",
                })
              }
            >
              <option value="group_policy">{protectionBackendLabels.group_policy}</option>
              <option value="wfp">{protectionBackendLabels.wfp}</option>
            </select>
          )}
        </Field>

        {saveError && <InlineError>{saveError}</InlineError>}
        <div className="form-actions">
          {config.settingsDirty && (
            <Button
              variant="ghost"
              icon={Undo2}
              disabled={saving}
              onClick={() => {
                dispatch({ type: "editSettings", settings: configured });
                setTouched({});
                setSubmitted(false);
                setSaveError(null);
              }}
            >
              Отменить
            </Button>
          )}
          <Button type="submit" variant="primary" icon={Save} busy={saving} disabledReason={saveReason}>
            Сохранить подключение
          </Button>
        </div>
      </form>

      <Checklist
        title="Проверка подключения"
        diagnosis={diagnosis.diagnosis}
        error={diagnosis.error}
        loading={diagnosis.loading}
        onRefresh={() => void diagnosis.refresh()}
        onFix={fix}
        only={connectionChecks}
        hideLink="connection"
        note={
          config.settingsDirty
            ? "Проверка относится к сохранённому подключению. Сохрани изменения, чтобы проверить новые."
            : undefined
        }
      />
    </div>
  );
}
