import { CircleCheck, Info, TriangleAlert, CircleX } from "lucide-react";
import { useId, type ReactNode } from "react";
import { cx } from "../domain/format";

export function PageHeader({
  title,
  lead,
  actions,
}: {
  title: string;
  lead?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <header className="page-head">
      <div className="page-head-text">
        <h1 tabIndex={-1}>{title}</h1>
        {lead && <p className="page-lead">{lead}</p>}
      </div>
      {actions && <div className="page-actions">{actions}</div>}
    </header>
  );
}

export type BannerTone = "info" | "good" | "warn" | "danger";
const bannerIcons = { info: Info, good: CircleCheck, warn: TriangleAlert, danger: CircleX };

/** A message tied to the page section it sits in. */
export function Banner({
  tone,
  title,
  children,
  actions,
  role,
}: {
  tone: BannerTone;
  title?: ReactNode;
  children?: ReactNode;
  actions?: ReactNode;
  role?: "alert" | "status";
}) {
  const Icon = bannerIcons[tone];
  return (
    <div className={`banner banner-${tone}`} role={role}>
      <Icon className="banner-icon" size={18} aria-hidden />
      <div className="banner-body">
        {title && <strong className="banner-title">{title}</strong>}
        {children && <div className="banner-text">{children}</div>}
      </div>
      {actions && <div className="banner-actions">{actions}</div>}
    </div>
  );
}

export function InlineError({ children }: { children: ReactNode }) {
  return (
    <p className="inline-error" role="alert">
      <CircleX size={14} aria-hidden />
      <span>{children}</span>
    </p>
  );
}

type ControlProps = { id: string; "aria-describedby"?: string; "aria-invalid"?: boolean };

/** Label + control + hint/error, wired with ids for screen readers. */
export function Field({
  label,
  hint,
  error,
  className,
  children,
}: {
  label: ReactNode;
  hint?: ReactNode;
  /** Shown instead of the hint. */
  error?: string | null;
  className?: string;
  children: (props: ControlProps) => ReactNode;
}) {
  const id = useId();
  const noteId = `${id}-note`;
  const note = error ?? hint;
  return (
    <div className={cx("field", error && "field-invalid", className)}>
      <label htmlFor={id}>{label}</label>
      {children({
        id,
        "aria-describedby": note ? noteId : undefined,
        "aria-invalid": error ? true : undefined,
      })}
      {note && (
        <p id={noteId} className={error ? "field-error" : "field-hint"}>
          {error && <CircleX size={13} aria-hidden />}
          <span>{note}</span>
        </p>
      )}
    </div>
  );
}

export function SectionHead({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <header className="section-head">
      <h2>{title}</h2>
      {children && <div className="section-head-side">{children}</div>}
    </header>
  );
}
