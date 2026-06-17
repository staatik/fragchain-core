import { ReactNode, useEffect } from "react";
import { createPortal } from "react-dom";

interface ModalProps {
  open: boolean;
  onClose: () => void;
  title?: ReactNode;
  children: ReactNode;
  footer?: ReactNode;
  /** When false, clicks on the dim scrim do not dismiss. Default true. */
  dismissOnBackdrop?: boolean;
  /** Force a wider modal (e.g. for diff views). */
  wide?: boolean;
}

/** Generic centred modal — DarkOps `.modal-overlay / .modal`. */
export function Modal({
  open,
  onClose,
  title,
  children,
  footer,
  dismissOnBackdrop = true,
  wide,
}: ModalProps) {
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
    <div
      className="modal-overlay"
      onClick={() => dismissOnBackdrop && onClose()}
      role="dialog"
      aria-modal="true"
    >
      <div
        className="modal"
        style={wide ? { maxWidth: 720 } : undefined}
        onClick={(e) => e.stopPropagation()}
      >
        {title !== undefined && (
          <div className="modal-header">
            <div className="modal-title">{title}</div>
            <button
              type="button"
              className="modal-close"
              aria-label="Close"
              onClick={onClose}
            >
              ×
            </button>
          </div>
        )}
        <div className="modal-body">{children}</div>
        {footer !== undefined && <div className="modal-footer">{footer}</div>}
      </div>
    </div>
  );

  return createPortal(content, document.body);
}
