import { ReactNode, useEffect } from "react";
import { createPortal } from "react-dom";

interface SidePanelProps {
  open: boolean;
  onClose: () => void;
  title?: ReactNode;
  children: ReactNode;
  footer?: ReactNode;
  /** Use the wide variant (640px) for diff / chain detail screens. */
  wide?: boolean;
  /** When false, clicking the scrim is a no-op (e.g. while a form is dirty). */
  dismissOnBackdrop?: boolean;
}

/** Right-side slide-in detail panel — DarkOps `.side-panel`.
 *
 *  Sits below the topbar (`top: var(--topbar-height)`). Use for row
 *  detail views (CVE detail, Queue item detail, Rule detail).
 */
export function SidePanel({
  open,
  onClose,
  title,
  children,
  footer,
  wide,
  dismissOnBackdrop = true,
}: SidePanelProps) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  if (!open) return null;

  const content = (
    <>
      <div
        className="side-panel-overlay"
        onClick={() => dismissOnBackdrop && onClose()}
      />
      <aside className={`side-panel${wide ? " wide" : ""}`} role="complementary">
        {title !== undefined && (
          <div className="side-panel-header">
            <div className="side-panel-title">{title}</div>
            <button
              type="button"
              className="modal-close"
              aria-label="Close panel"
              onClick={onClose}
            >
              ×
            </button>
          </div>
        )}
        <div className="side-panel-body">{children}</div>
        {footer !== undefined && <div className="side-panel-footer">{footer}</div>}
      </aside>
    </>
  );

  return createPortal(content, document.body);
}
