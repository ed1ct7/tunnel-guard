import { TriangleAlert } from "lucide-react";
import { createContext, useCallback, useContext, useState, type ReactNode } from "react";
import { Button } from "./Button";
import { Dialog } from "./Dialog";

export type ConfirmOptions = {
  title: string;
  body: ReactNode;
  confirmLabel: string;
  cancelLabel?: string;
  /** `danger` styles the confirm button red and puts initial focus on Cancel. */
  tone?: "default" | "danger";
};

type Request = ConfirmOptions & { resolve: (value: boolean) => void };

const ConfirmContext = createContext<((options: ConfirmOptions) => Promise<boolean>) | null>(null);

export function ConfirmProvider({ children }: { children: ReactNode }) {
  const [request, setRequest] = useState<Request | null>(null);

  const confirm = useCallback(
    (options: ConfirmOptions) =>
      new Promise<boolean>((resolve) => {
        setRequest((previous) => {
          previous?.resolve(false);
          return { ...options, resolve };
        });
      }),
    [],
  );

  function settle(value: boolean) {
    request?.resolve(value);
    setRequest(null);
  }

  const danger = request?.tone === "danger";
  return (
    <ConfirmContext value={confirm}>
      {children}
      <Dialog
        open={Boolean(request)}
        onClose={() => settle(false)}
        title={request?.title ?? ""}
        tone={danger ? "danger" : "default"}
        icon={danger ? <TriangleAlert size={20} aria-hidden /> : undefined}
        size="sm"
        hideClose
        footer={
          <>
            <Button variant="ghost" onClick={() => settle(false)} data-autofocus={danger ? true : undefined}>
              {request?.cancelLabel ?? "Отмена"}
            </Button>
            <Button
              variant={danger ? "danger" : "primary"}
              onClick={() => settle(true)}
              data-autofocus={danger ? undefined : true}
            >
              {request?.confirmLabel}
            </Button>
          </>
        }
      >
        <div className="confirm-body">{request?.body}</div>
      </Dialog>
    </ConfirmContext>
  );
}

export function useConfirm() {
  const confirm = useContext(ConfirmContext);
  if (!confirm) throw new Error("useConfirm outside ConfirmProvider");
  return confirm;
}
