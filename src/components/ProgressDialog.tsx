import { useEffect } from "react";
import { Check, Circle, CircleCheck, CircleX, ShieldHalf, X } from "lucide-react";
import { actionSuccess, actionTitles } from "../domain/status";
import { stageText, stepState, type Run } from "../domain/progress";
import { cx } from "../domain/format";
import { formatDuration, useNow } from "../hooks/useNow";
import { Button, Spinner } from "./Button";
import { Dialog } from "./Dialog";

export function ProgressSteps({ run }: { run: Run }) {
  return (
    <ol className="steps">
      {run.steps.map((stage) => {
        const state = stepState(run, stage);
        const text = stageText[stage];
        return (
          <li
            key={stage}
            className={cx("step", `step-${state}`)}
            aria-current={state === "active" ? "step" : undefined}
          >
            <span className="step-glyph">
              {state === "done" && <Check size={14} aria-hidden />}
              {state === "active" && <Spinner size={16} />}
              {state === "failed" && <X size={14} aria-hidden />}
              {state === "pending" && <Circle size={8} aria-hidden />}
            </span>
            <span className="step-text">
              <span className="step-label">
                {text.label}
                <span className="sr-only">
                  {state === "done"
                    ? " — готово"
                    : state === "active"
                      ? " — выполняется"
                      : state === "failed"
                        ? " — ошибка"
                        : ""}
                </span>
              </span>
              {state === "active" && text.hint && <span className="step-hint">{text.hint}</span>}
            </span>
          </li>
        );
      })}
    </ol>
  );
}

function Elapsed({ run }: { run: Run }) {
  const now = useNow(1000);
  const end = run.finishedAt ?? now;
  return (
    <span className="elapsed num">
      {run.phase === "running" ? "Прошло" : "Заняло"} {formatDuration(end - run.startedAt)}
    </span>
  );
}

type ProgressDialogProps = {
  run: Run | null;
  open: boolean;
  onHide: () => void;
  onClose: () => void;
  onOpenConnection: () => void;
};

/** Step-by-step view of enable/disable driven by `guard-progress`. */
export function ProgressDialog({ run, open, onHide, onClose, onOpenConnection }: ProgressDialogProps) {
  const phase = run?.phase;
  useEffect(() => {
    // When the run finishes the "hide" button disappears; move focus to "Close" instead of losing it.
    if (open && phase && phase !== "running") {
      document.querySelector<HTMLElement>(".dialog-progress [data-autofocus]")?.focus();
    }
  }, [open, phase]);
  if (!run) return null;
  const titles = actionTitles[run.action];
  const running = run.phase === "running";
  const title = running ? titles.running : run.phase === "done" ? titles.done : titles.failed;
  const pointsToConnection = Boolean(run.error?.includes("«Подключение»"));
  return (
    <Dialog
      open={open}
      className="dialog-progress"
      onClose={running ? onHide : onClose}
      closeLabel={running ? "Скрыть окно, операция продолжится" : "Закрыть"}
      title={title}
      tone={run.phase === "done" ? "good" : run.phase === "failed" ? "danger" : "default"}
      icon={
        run.phase === "done" ? (
          <CircleCheck size={20} aria-hidden />
        ) : run.phase === "failed" ? (
          <CircleX size={20} aria-hidden />
        ) : (
          <ShieldHalf size={20} aria-hidden />
        )
      }
      footer={
        <>
          <Elapsed run={run} />
          {running ? (
            <Button variant="ghost" onClick={onHide}>
              Скрыть, пусть идёт в фоне
            </Button>
          ) : (
            <>
              {pointsToConnection && (
                <Button variant="ghost" onClick={onOpenConnection}>
                  Открыть «Подключение»
                </Button>
              )}
              <Button variant="primary" onClick={onClose} data-autofocus>
                Закрыть
              </Button>
            </>
          )}
        </>
      }
    >
      {running && (
        <p className="dialog-lead">
          {run.action === "enable"
            ? "Tunnel Guard проверит туннель, заменит правила брандмауэра и убедится, что прямой выход закрыт. Обычно это занимает до минуты — дольше всего обновляется политика Windows."
            : "Tunnel Guard вернёт правила брандмауэра, которые были до включения защиты. Обычно это занимает до минуты."}
        </p>
      )}
      <ProgressSteps run={run} />
      <div aria-live="polite">
        {run.phase === "failed" && (
          <div className="callout callout-danger" role="alert">
            <strong>Что пошло не так</strong>
            <p>{run.error}</p>
          </div>
        )}
        {run.phase === "done" && (
          <div className="callout callout-good">
            <p>{actionSuccess[run.action]}</p>
          </div>
        )}
      </div>
    </Dialog>
  );
}
