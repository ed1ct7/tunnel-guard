import {
  CircleCheck,
  CircleDashed,
  CircleX,
  ExternalLink,
  RefreshCw,
  Settings2,
  TriangleAlert,
} from "lucide-react";
import { useId } from "react";
import type { CheckId, CheckStatus, Diagnosis } from "../api/types";
import { advisoryChecks, checkTexts, skipText, type CheckFixLink } from "../domain/checks";
import { cx, plural } from "../domain/format";
import { formatAge, useNow } from "../hooks/useNow";
import { Button } from "./Button";
import { InlineError } from "./Layout";

const glyphs: Record<CheckStatus, { Icon: typeof CircleCheck; label: string }> = {
  ok: { Icon: CircleCheck, label: "готово" },
  fail: { Icon: CircleX, label: "ошибка" },
  warn: { Icon: TriangleAlert, label: "предупреждение" },
  skip: { Icon: CircleDashed, label: "не проверено" },
};

export function CheckedAgo({ at }: { at: number }) {
  const now = useNow(1000);
  return <span className="checked-ago">проверено {formatAge(at, now)}</span>;
}

type ChecklistProps = {
  title: string;
  diagnosis: Diagnosis | null;
  error: string | null;
  loading: boolean;
  onRefresh: () => void;
  onFix: (link: CheckFixLink) => void;
  /** Show only these checks (in checklist order). */
  only?: readonly CheckId[];
  /** Fix links that lead to the page the checklist is already on are hidden. */
  hideLink?: CheckFixLink;
  note?: string;
};

function summary(diagnosis: Diagnosis, ids: readonly CheckId[] | undefined) {
  const checks = diagnosis.checks.filter((check) => !ids || ids.includes(check.id));
  const blocking = checks.filter((check) => check.status !== "ok" && !advisoryChecks.has(check.id));
  const failing = blocking.filter((check) => check.status === "fail" || check.status === "warn").length;
  const advisory = checks.filter((check) => check.status !== "ok" && advisoryChecks.has(check.id)).length;
  if (failing) {
    return {
      tone: "danger",
      text: `${failing} ${plural(failing, "проблема мешает", "проблемы мешают", "проблем мешают")} включению`,
    };
  }
  if (blocking.length) return { tone: "warn", text: "Часть пунктов не проверена" };
  if (advisory)
    return {
      tone: "warn",
      text: `Всё готово, ${advisory} ${plural(advisory, "замечание", "замечания", "замечаний")}`,
    };
  return { tone: "good", text: "Всё готово" };
}

export function Checklist({
  title,
  diagnosis,
  error,
  loading,
  onRefresh,
  onFix,
  only,
  hideLink,
  note,
}: ChecklistProps) {
  const titleId = useId();
  const checks = diagnosis?.checks.filter((check) => !only || only.includes(check.id)) ?? [];
  const head = diagnosis ? summary(diagnosis, only) : null;
  return (
    <section className="panel checklist" aria-labelledby={titleId} aria-busy={loading || undefined}>
      <header className="panel-head">
        <h2 id={titleId}>{title}</h2>
        {head && <span className={cx("panel-summary", `text-${head.tone}`)}>{head.text}</span>}
        <span className="panel-head-side">
          {diagnosis && <CheckedAgo at={diagnosis.checked_at} />}
          <Button size="sm" variant="ghost" icon={RefreshCw} busy={loading} onClick={onRefresh}>
            Проверить
          </Button>
        </span>
      </header>
      {note && <p className="panel-note">{note}</p>}
      {error && <InlineError>Проверка не выполнилась: {error}</InlineError>}
      {!diagnosis && !error && (
        <ul className="checks checks-placeholder" aria-label="Идёт проверка">
          {(only ?? Object.keys(checkTexts)).map((id) => (
            <li key={id} className="check check-pending">
              <CircleDashed size={18} aria-hidden className="check-glyph" />
              <span className="check-title">{checkTexts[id as CheckId].title}</span>
            </li>
          ))}
        </ul>
      )}
      {checks.length > 0 && (
        <ul className="checks">
          {checks.map((check) => {
            const text = checkTexts[check.id];
            const { Icon, label } = glyphs[check.status];
            const problem = check.status === "fail" || check.status === "warn";
            const link = problem && text.link && text.link !== hideLink ? text.link : undefined;
            return (
              <li key={check.id} className={cx("check", `check-${check.status}`)}>
                <Icon size={18} className="check-glyph" aria-hidden />
                <div className="check-main">
                  <div className="check-line">
                    <span className="check-title">
                      {text.title}
                      <span className="sr-only">: {label}</span>
                    </span>
                    {check.detail && <span className="check-detail">{check.detail}</span>}
                  </div>
                  {problem && (
                    <p className="check-fix">
                      {text.fix}
                      {advisoryChecks.has(check.id) && <span className="check-tag">не мешает включению</span>}
                    </p>
                  )}
                  {check.status === "skip" && <p className="check-fix check-fix-muted">{skipText}</p>}
                </div>
                {link && (
                  <Button
                    size="sm"
                    variant="ghost"
                    className="check-action"
                    icon={link === "connection" ? Settings2 : ExternalLink}
                    onClick={() => onFix(link)}
                  >
                    {link === "connection" ? "Подключение" : "Открыть v2rayN"}
                  </Button>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}
