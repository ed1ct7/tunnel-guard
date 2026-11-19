import { CircleCheck, CircleX, Info, X } from "lucide-react";
import { createContext, useCallback, useContext, useMemo, useRef, useState, type ReactNode } from "react";

export type ToastTone = "success" | "error" | "info";
export type ToastInput = {
  tone: ToastTone;
  text: string;
  title?: string;
  action?: { label: string; onClick: () => void };
};
type Toast = ToastInput & { id: number };

type ToastApi = {
  push: (toast: ToastInput) => number;
  dismiss: (id: number) => void;
};

const ToastContext = createContext<ToastApi | null>(null);

/** Success toasts leave by themselves; errors stay until closed. */
const lifetime: Record<ToastTone, number> = { success: 4500, info: 8000, error: 0 };
const icons = { success: CircleCheck, error: CircleX, info: Info };

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const nextId = useRef(1);

  const dismiss = useCallback(
    (id: number) => setToasts((list) => list.filter((toast) => toast.id !== id)),
    [],
  );

  const push = useCallback(
    (input: ToastInput) => {
      const id = nextId.current++;
      // The same message twice in a row replaces the old one instead of stacking.
      setToasts((list) => [...list.filter((toast) => toast.text !== input.text), { ...input, id }].slice(-4));
      const life = lifetime[input.tone];
      if (life) window.setTimeout(() => dismiss(id), life);
      return id;
    },
    [dismiss],
  );

  const api = useMemo(() => ({ push, dismiss }), [push, dismiss]);

  return (
    <ToastContext value={api}>
      {children}
      <section className="toasts" aria-label="Уведомления" aria-live="polite">
        {toasts.map((toast) => {
          const Icon = icons[toast.tone];
          return (
            <div
              key={toast.id}
              className={`toast toast-${toast.tone}`}
              role={toast.tone === "error" ? "alert" : "status"}
            >
              <Icon className="toast-icon" size={18} aria-hidden />
              <div className="toast-body">
                {toast.title && <strong>{toast.title}</strong>}
                <p>{toast.text}</p>
                {toast.action && (
                  <button
                    type="button"
                    className="link-button"
                    onClick={() => {
                      dismiss(toast.id);
                      toast.action?.onClick();
                    }}
                  >
                    {toast.action.label}
                  </button>
                )}
              </div>
              <button
                type="button"
                className="toast-close"
                aria-label="Закрыть уведомление"
                onClick={() => dismiss(toast.id)}
              >
                <X size={14} aria-hidden />
              </button>
            </div>
          );
        })}
      </section>
    </ToastContext>
  );
}

export function useToasts() {
  const api = useContext(ToastContext);
  if (!api) throw new Error("useToasts outside ToastProvider");
  return api;
}
