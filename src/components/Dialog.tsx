import { X } from "lucide-react";
import { useEffect, useId, useRef, type KeyboardEvent, type MouseEvent, type ReactNode } from "react";
import { cx } from "../domain/format";

const focusableSelector = [
  "button:not([disabled])",
  "[href]",
  "input:not([disabled])",
  "select:not([disabled])",
  "textarea:not([disabled])",
  '[tabindex]:not([tabindex="-1"])',
].join(",");

function focusables(root: HTMLElement) {
  return [...root.querySelectorAll<HTMLElement>(focusableSelector)].filter(
    (element) => element.offsetParent !== null,
  );
}

type DialogProps = {
  open: boolean;
  /** Esc, the close button and a click on the backdrop. */
  onClose: () => void;
  title: ReactNode;
  icon?: ReactNode;
  tone?: "default" | "danger" | "good" | "warn";
  size?: "sm" | "md" | "lg";
  children: ReactNode;
  footer?: ReactNode;
  /** Hide the corner close button (Esc still calls `onClose`). */
  hideClose?: boolean;
  closeLabel?: string;
  className?: string;
};

/**
 * Modal dialog on top of the native <dialog>: the rest of the page is inert, Tab is trapped inside,
 * Esc closes, and focus returns to where it was. An element with `data-autofocus` gets initial focus.
 */
export function Dialog({
  open,
  onClose,
  title,
  icon,
  tone = "default",
  size = "md",
  children,
  footer,
  hideClose = false,
  closeLabel = "Закрыть",
  className,
}: DialogProps) {
  const ref = useRef<HTMLDialogElement>(null);
  const restoreTo = useRef<HTMLElement | null>(null);
  const titleId = useId();

  useEffect(() => {
    const dialog = ref.current;
    if (!dialog) return;
    if (open && !dialog.open) {
      restoreTo.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
      dialog.showModal();
      const target = dialog.querySelector<HTMLElement>("[data-autofocus]") ?? focusables(dialog)[0];
      target?.focus();
    } else if (!open && dialog.open) {
      dialog.close();
      restoreTo.current?.focus();
      restoreTo.current = null;
    }
  }, [open]);

  useEffect(() => {
    const dialog = ref.current;
    return () => {
      if (dialog?.open) dialog.close();
    };
  }, []);

  function trapTab(event: KeyboardEvent<HTMLDialogElement>) {
    if (event.key !== "Tab" || !ref.current) return;
    const items = focusables(ref.current);
    const first = items[0];
    const last = items.at(-1);
    if (!first || !last) return;
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }

  function backdropClick(event: MouseEvent<HTMLDialogElement>) {
    // The panel fills the <dialog>, so a click whose target is the dialog itself hit the backdrop.
    if (event.target === ref.current) onClose();
  }

  return (
    <dialog
      ref={ref}
      className={cx("dialog", `dialog-${size}`, `dialog-tone-${tone}`, className)}
      aria-labelledby={titleId}
      onCancel={(event) => {
        event.preventDefault();
        onClose();
      }}
      onKeyDown={trapTab}
      onMouseDown={backdropClick}
    >
      {open && (
        <div className="dialog-panel">
          <header className="dialog-head">
            {icon && <span className="dialog-icon">{icon}</span>}
            <h2 id={titleId}>{title}</h2>
            {!hideClose && (
              <button type="button" className="dialog-close" aria-label={closeLabel} onClick={onClose}>
                <X size={16} aria-hidden />
              </button>
            )}
          </header>
          <div className="dialog-body">{children}</div>
          {footer && <footer className="dialog-foot">{footer}</footer>}
        </div>
      )}
    </dialog>
  );
}
