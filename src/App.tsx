import { RefreshCw } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { AppContext, type AppModel } from "./AppContext";
import { api, errorText } from "./api/backend";
import type { ProtectionAction } from "./api/types";
import { Button } from "./components/Button";
import { useConfirm } from "./components/ConfirmDialog";
import { Banner } from "./components/Layout";
import { ProgressDialog } from "./components/ProgressDialog";
import { Sidebar } from "./components/Sidebar";
import { useToasts } from "./components/Toasts";
import { blockingProblems, checkTexts } from "./domain/checks";
import type { Page } from "./domain/navigation";
import { actionSuccess, actionTitles, presentStatus } from "./domain/status";
import { useConfigState } from "./hooks/useConfigState";
import { useCoreRules, useDiagnosis } from "./hooks/useDiagnosis";
import { useGuardStatus } from "./hooks/useGuardStatus";
import { useProtection } from "./hooks/useProtection";
import { ConnectionPage } from "./pages/ConnectionPage";
import { OverviewPage } from "./pages/OverviewPage";
import { ProcessesPage } from "./pages/ProcessesPage";
import { RoutingPage } from "./pages/RoutingPage";

export function App() {
  const toasts = useToasts();
  const confirm = useConfirm();
  const [page, setPage] = useState<Page>("overview");
  const guard = useGuardStatus();
  const diagnosis = useDiagnosis();
  const coreRules = useCoreRules();
  const config = useConfigState();
  const protection = useProtection();
  const [openingClient, setOpeningClient] = useState(false);
  const view = presentStatus(guard.status);
  const { push } = toasts;
  const { dispatch } = config;
  const { load: loadDiagnosis } = diagnosis;
  const { load: loadCoreRules } = coreRules;

  // Initial config read and draft recovery. Runs once: the backend hands a draft out only once.
  const started = useRef(false);
  useEffect(() => {
    if (started.current) return;
    started.current = true;
    api
      .configSnapshot()
      .then(async (snapshot) => {
        dispatch({ type: "sync", snapshot });
        const draft = await api.recoverRoutingDraft();
        if (draft) {
          dispatch({ type: "editRules", rules: draft });
          setPage("routing");
          push({
            tone: "info",
            text: "Несохранённый список правил восстановлен. Проверь его перед сохранением.",
          });
        }
      })
      .catch((reason: unknown) => push({ tone: "error", text: errorText(reason) }));
  }, [dispatch, push]);

  // Readiness and core rules follow the protection state: re-check whenever it changes.
  const statusKey = guard.status ? `${guard.status.state}:${guard.status.adapter_up}` : null;
  const clientPath = config.configured.client_path;
  useEffect(() => {
    if (!statusKey) return;
    void loadDiagnosis();
    void loadCoreRules();
  }, [statusKey, clientPath, loadDiagnosis, loadCoreRules]);

  // Hint for the backend poll interval (fast while visible, slow in the tray).
  const { refresh: refreshStatus } = guard;
  useEffect(() => {
    function update() {
      const visible = document.visibilityState === "visible";
      api.setWindowVisible(visible).catch(() => undefined);
      if (visible) void refreshStatus();
    }
    document.addEventListener("visibilitychange", update);
    return () => document.removeEventListener("visibilitychange", update);
  }, [refreshStatus]);

  // Move focus to the new page heading so keyboard and screen reader users land in the content.
  const mainRef = useRef<HTMLElement>(null);
  const firstPage = useRef(true);
  useEffect(() => {
    if (firstPage.current) {
      firstPage.current = false;
      return;
    }
    mainRef.current?.scrollTo({ top: 0 });
    mainRef.current?.querySelector<HTMLElement>("h1")?.focus({ preventScroll: true });
  }, [page]);

  async function refreshAll() {
    await Promise.all([guard.refresh(), diagnosis.refresh(), coreRules.load()]);
  }

  async function requestProtection(action: ProtectionAction) {
    if (action === "enable" && !config.configured.client_path) {
      setPage("connection");
      push({ tone: "info", text: "Выбери установленный v2rayN и сохрани подключение." });
      return;
    }
    if (action === "disable") {
      const partial = guard.status?.state === "Partial";
      const ok = await confirm({
        tone: "danger",
        title: partial ? "Восстановить прежние правила Windows?" : "Выключить защиту?",
        body: (
          <p>
            Tunnel Guard вернёт правила брандмауэра, которые были до включения защиты. При отключённом VPN
            приложения снова смогут подключаться напрямую.
          </p>
        ),
        confirmLabel: partial ? "Восстановить правила" : "Выключить защиту",
      });
      if (!ok) return;
    }
    const current = diagnosis.diagnosis;
    if (action === "enable" && current && !current.ready) {
      const blocking = blockingProblems(current);
      const ok = await confirm({
        title: "Проверка нашла проблемы",
        body: (
          <>
            {blocking.length > 0 && (
              <>
                <p>Не выполнено:</p>
                <ul className="confirm-list">
                  {blocking.map((check) => (
                    <li key={check.id}>
                      {checkTexts[check.id].title}
                      {check.detail && <span className="confirm-detail"> — {check.detail}</span>}
                    </li>
                  ))}
                </ul>
              </>
            )}
            <p>
              Перед изменением правил Tunnel Guard ещё раз проверит туннель и не включит защиту, если он не
              готов. Попробовать всё равно?
            </p>
          </>
        ),
        confirmLabel: "Попробовать включить",
      });
      if (!ok) return;
    }
    const result = await protection.start(action);
    if (!protection.isDialogVisible()) {
      // The dialog was hidden: report the outcome where the user will see it.
      push(
        result.ok
          ? { tone: "success", title: actionTitles[action].done, text: actionSuccess[action] }
          : {
              tone: "error",
              title: actionTitles[action].failed,
              text: result.error,
              action: { label: "Подробнее", onClick: protection.showDialog },
            },
      );
    }
    await Promise.all([guard.refresh(), diagnosis.load()]);
  }

  async function openClient() {
    setOpeningClient(true);
    try {
      await api.openClient();
      push({ tone: "info", text: "v2rayN запускается. Статус и проверка обновятся сами." });
      window.setTimeout(() => void loadDiagnosis(), 4000);
    } catch (reason) {
      push({ tone: "error", text: errorText(reason) });
    } finally {
      setOpeningClient(false);
    }
  }

  async function reloadConfig() {
    if (
      (config.rulesDirty || config.settingsDirty) &&
      !(await confirm({
        tone: "danger",
        title: "Перечитать настройки с диска?",
        body: <p>Несохранённые изменения в окне будут сброшены.</p>,
        confirmLabel: "Перечитать и сбросить",
      }))
    ) {
      return;
    }
    try {
      const snapshot = await api.configSnapshot();
      dispatch({ type: "replace", snapshot });
      push({ tone: "success", text: "Настройки и правила перечитаны с диска." });
      void loadCoreRules();
      await guard.refresh();
    } catch (reason) {
      push({ tone: "error", text: errorText(reason) });
    }
  }

  const model: AppModel = {
    page,
    navigate: setPage,
    status: guard.status,
    statusError: guard.error,
    refreshingStatus: guard.refreshing,
    view,
    diagnosis,
    coreRules,
    config,
    protection,
    refreshAll,
    requestProtection,
    openClient,
    openingClient,
    reloadConfig,
  };

  const settingsBroken = diagnosis.diagnosis?.checks.some(
    (check) => (check.id === "client" || check.id === "core") && check.status === "fail",
  );
  const badges: Partial<Record<Page, string>> = {
    routing: config.rulesDirty
      ? "есть несохранённые изменения"
      : coreRules.coreRules?.state === "pending"
        ? "правила ждут применения в Mihomo"
        : undefined,
    connection: config.settingsDirty
      ? "есть несохранённые изменения"
      : settingsBroken || (config.loaded && !config.configured.client_path)
        ? "подключение не настроено"
        : undefined,
  };

  return (
    <AppContext value={model}>
      <div className="shell">
        <Sidebar
          page={page}
          onNavigate={setPage}
          status={guard.status}
          view={view}
          run={protection.run}
          badges={badges}
        />
        <main className="main" ref={mainRef}>
          {config.conflict && (
            <Banner
              tone="warn"
              role="alert"
              title="Настройки изменились в другой программе"
              actions={
                <>
                  <Button size="sm" icon={RefreshCw} onClick={() => void reloadConfig()}>
                    Перечитать
                  </Button>
                  <Button size="sm" variant="ghost" onClick={() => dispatch({ type: "dismissConflict" })}>
                    Скрыть
                  </Button>
                </>
              }
            >
              Нажми «Перечитать», чтобы загрузить их. Несохранённые изменения в этом окне при этом сбросятся.
            </Banner>
          )}
          {page === "overview" && <OverviewPage />}
          {page === "routing" && <RoutingPage />}
          {page === "processes" && <ProcessesPage />}
          {page === "connection" && <ConnectionPage />}
        </main>
      </div>
      <ProgressDialog
        run={protection.run}
        open={protection.dialogOpen}
        onHide={protection.hideDialog}
        onClose={protection.closeDialog}
        onOpenConnection={() => {
          protection.closeDialog();
          setPage("connection");
        }}
      />
    </AppContext>
  );
}
