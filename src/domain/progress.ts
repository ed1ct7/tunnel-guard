import type { ProgressStage, ProtectionAction } from "../api/types";

export type StepStage = Exclude<ProgressStage, "done" | "failed">;

export const stageText: Record<StepStage, { label: string; hint?: string }> = {
  preflight: { label: "Проверяем v2rayN и туннель" },
  elevate: {
    label: "Подтверди запрос администратора Windows",
    hint: "Окно контроля учётных записей может открыться позади этого окна или мигать на панели задач.",
  },
  settings: { label: "Передаём настройки подключения" },
  tun: { label: "Проверяем TUN-адаптер" },
  egress: { label: "Находим прямой выход в интернет" },
  backup: { label: "Сохраняем текущую политику брандмауэра" },
  apply: { label: "Применяем правила брандмауэра" },
  policy: {
    label: "Обновляем групповую политику Windows",
    hint: "gpupdate — самый долгий шаг, иногда до минуты.",
  },
  verify: { label: "Проверяем: HTTPS через TUN работает, прямой выход закрыт" },
  restore: { label: "Возвращаем прежнюю политику брандмауэра" },
  cleanup: { label: "Удаляем правила старой версии" },
};

export const expectedStages: Record<ProtectionAction, StepStage[]> = {
  enable: ["preflight", "elevate", "settings", "tun", "egress", "backup", "apply", "policy", "verify"],
  disable: ["elevate", "restore", "policy"],
  clean_legacy: ["elevate", "cleanup", "policy"],
};

export type Run = {
  action: ProtectionAction;
  steps: StepStage[];
  current: StepStage | null;
  phase: "running" | "done" | "failed";
  error: string | null;
  startedAt: number;
  finishedAt: number | null;
};

export type StepState = "pending" | "active" | "done" | "failed";

export function startRun(action: ProtectionAction, now: number): Run {
  return {
    action,
    steps: [...expectedStages[action]],
    current: null,
    phase: "running",
    error: null,
    startedAt: now,
    finishedAt: null,
  };
}

/** Applies one `guard-progress` stage. Unknown stages are inserted right after the current one. */
export function advance(run: Run, stage: ProgressStage, now: number): Run {
  if (run.phase !== "running") return run;
  if (stage === "done") return { ...run, phase: "done", finishedAt: now };
  if (stage === "failed") return run; // the rejected promise carries the reason; see `failRun`
  if (run.steps.includes(stage)) {
    // Never move backwards if events arrive out of order.
    const from = run.current ? run.steps.indexOf(run.current) : -1;
    return run.steps.indexOf(stage) >= from ? { ...run, current: stage } : run;
  }
  const steps = [...run.steps];
  const after = run.current ? steps.indexOf(run.current) + 1 : 0;
  steps.splice(after, 0, stage);
  return { ...run, steps, current: stage };
}

export function finishRun(run: Run, now: number): Run {
  return run.phase === "running" ? { ...run, phase: "done", finishedAt: now } : run;
}

export function failRun(run: Run, error: string, now: number): Run {
  return { ...run, phase: "failed", error, finishedAt: run.finishedAt ?? now };
}

export function stepState(run: Run, stage: StepStage): StepState {
  if (run.phase === "done") return "done";
  const index = run.steps.indexOf(stage);
  // Before the first event the first step is the one being waited for.
  const current = run.current ? run.steps.indexOf(run.current) : 0;
  if (index < current) return "done";
  if (index > current) return "pending";
  return run.phase === "failed" ? "failed" : "active";
}

/** The step to show while the dialog is hidden. */
export function activeStepLabel(run: Run) {
  const stage = run.current ?? run.steps[0];
  return stage ? stageText[stage].label : "";
}
