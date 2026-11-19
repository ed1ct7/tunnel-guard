import { useCallback, useRef, useState } from "react";
import { api, errorText, subscribe } from "../api/backend";
import type { ProtectionAction } from "../api/types";
import { advance, failRun, finishRun, startRun, type Run } from "../domain/progress";

export type ProtectionResult = { ok: true } | { ok: false; error: string };

/**
 * Runs `change_protection` and tracks its `guard-progress` stages.
 * The dialog can be hidden while the operation continues; `run` stays until the user closes it.
 */
export function useProtection() {
  const [run, setRun] = useState<Run | null>(null);
  const [dialogOpen, setDialogOpenState] = useState(false);
  const running = useRef(false);
  const visible = useRef(false);

  const setDialogOpen = useCallback((open: boolean) => {
    visible.current = open;
    setDialogOpenState(open);
  }, []);

  const start = useCallback(
    async (action: ProtectionAction): Promise<ProtectionResult> => {
      if (running.current)
        return { ok: false, error: "Tunnel Guard уже меняет настройки. Дождись завершения." };
      running.current = true;
      setRun(startRun(action, Date.now()));
      setDialogOpen(true);
      let stop: (() => void) | undefined;
      try {
        stop = await subscribe("guard-progress", (progress) => {
          if (progress.action !== action) return;
          setRun((current) => (current ? advance(current, progress.stage, Date.now()) : current));
        });
      } catch {
        // Progress is a nicety: without events the dialog still shows the first step and the result.
      }
      try {
        await api.changeProtection(action);
        setRun((current) => (current ? finishRun(current, Date.now()) : current));
        return { ok: true };
      } catch (reason) {
        const error = errorText(reason);
        setRun((current) => (current ? failRun(current, error, Date.now()) : current));
        return { ok: false, error };
      } finally {
        stop?.();
        running.current = false;
      }
    },
    [setDialogOpen],
  );

  const showDialog = useCallback(() => setDialogOpen(true), [setDialogOpen]);
  const hideDialog = useCallback(() => setDialogOpen(false), [setDialogOpen]);
  /** Closes the dialog; a finished run is forgotten, a running one keeps going in the background. */
  const closeDialog = useCallback(() => {
    setDialogOpen(false);
    setRun((current) => (current && current.phase !== "running" ? null : current));
  }, [setDialogOpen]);
  /** Whether the user is looking at the dialog right now (read at the moment of the call). */
  const isDialogVisible = useCallback(() => visible.current, []);

  return { run, dialogOpen, start, showDialog, hideDialog, closeDialog, isDialogVisible };
}

export type ProtectionController = ReturnType<typeof useProtection>;
