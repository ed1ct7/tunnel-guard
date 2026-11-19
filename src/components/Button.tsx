import { LoaderCircle, type LucideIcon } from "lucide-react";
import type { ButtonHTMLAttributes, MouseEvent, ReactNode } from "react";
import { cx } from "../domain/format";

export function Spinner({ size = 16, label }: { size?: number; label?: string }) {
  return (
    <LoaderCircle
      className="spin"
      size={size}
      aria-hidden={label ? undefined : true}
      aria-label={label}
      role={label ? "img" : undefined}
    />
  );
}

type ButtonProps = Omit<ButtonHTMLAttributes<HTMLButtonElement>, "disabled"> & {
  variant?: "primary" | "secondary" | "danger" | "ghost";
  size?: "md" | "sm";
  icon?: LucideIcon;
  /** Shows a spinner instead of the icon and ignores clicks. */
  busy?: boolean;
  disabled?: boolean;
  /**
   * Why the button cannot be used right now. The button stays focusable (aria-disabled),
   * so the reason is reachable by keyboard and shown as a tooltip.
   */
  disabledReason?: string | null;
  children?: ReactNode;
};

export function Button({
  variant = "secondary",
  size = "md",
  icon: Icon,
  busy = false,
  disabled = false,
  disabledReason,
  className,
  children,
  onClick,
  title,
  type = "button",
  ...rest
}: ButtonProps) {
  const inert = busy || disabled || Boolean(disabledReason);
  function handleClick(event: MouseEvent<HTMLButtonElement>) {
    if (inert) {
      event.preventDefault();
      return;
    }
    onClick?.(event);
  }
  return (
    <button
      {...rest}
      type={type}
      className={cx("btn", `btn-${variant}`, size === "sm" && "btn-sm", !children && "btn-icon", className)}
      aria-disabled={inert || undefined}
      aria-busy={busy || undefined}
      title={disabledReason ?? title}
      onClick={handleClick}
    >
      {busy ? (
        <Spinner size={size === "sm" ? 14 : 16} />
      ) : Icon ? (
        <Icon size={size === "sm" ? 14 : 16} aria-hidden />
      ) : null}
      {children && <span>{children}</span>}
    </button>
  );
}
