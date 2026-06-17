import { ReactNode } from "react";

interface FirstRunHintProps {
  /** Short headline. */
  title: string;
  /** What the operator should do next. */
  message: ReactNode;
  /** The seed command to surface (rendered in mono). */
  command?: string;
  /** Optional additional inline note. */
  note?: ReactNode;
}

/** Inline card surfaced on screens that need built-in data to function.
 *
 *  A fresh ``docker compose up`` boots an empty platform by design.
 *  Screens whose primary purpose depends on a seeded table — /matrix,
 *  /prompts, /imports preset list, /settings/profiles — render this
 *  card with a pointer to ``./setup.sh`` so operators don't see a
 *  silent empty grid and wonder if the platform is broken.
 *
 *  The card sits inside the screen's normal container; it does not
 *  replace the screen content, just leads with guidance.
 */
export function FirstRunHint({ title, message, command, note }: FirstRunHintProps) {
  return (
    <div className="first-run-hint" role="status">
      <div className="first-run-hint-title">{title}</div>
      <div className="first-run-hint-message">{message}</div>
      {command && (
        <div className="first-run-hint-command">
          <span className="first-run-hint-prompt mono">$</span>
          <code className="mono">{command}</code>
        </div>
      )}
      {note && <div className="first-run-hint-note">{note}</div>}
    </div>
  );
}
