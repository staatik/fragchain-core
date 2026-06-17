import { ReactNode } from "react";

import { Modal } from "./Modal";

interface ConfirmDialogProps {
  open: boolean;
  title: string;
  message: ReactNode;
  confirmLabel?: string;
  cancelLabel?: string;
  /** Use a danger-styled confirm button. */
  destructive?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
  busy?: boolean;
}

/** Confirmation prompt — single-screen yes/no dialog.
 *
 *  Use for destructive operations (reject, delete, contribute to commons,
 *  re-synthesise). For multi-step flows use Modal directly.
 */
export function ConfirmDialog({
  open,
  title,
  message,
  confirmLabel = "Confirm",
  cancelLabel = "Cancel",
  destructive,
  onConfirm,
  onCancel,
  busy,
}: ConfirmDialogProps) {
  return (
    <Modal
      open={open}
      onClose={busy ? () => undefined : onCancel}
      title={title}
      dismissOnBackdrop={!busy}
      footer={
        <>
          <button type="button" className="btn ghost" onClick={onCancel} disabled={busy}>
            {cancelLabel}
          </button>
          <button
            type="button"
            className={destructive ? "btn danger" : "btn active"}
            onClick={onConfirm}
            disabled={busy}
          >
            {busy ? "WORKING…" : confirmLabel}
          </button>
        </>
      }
    >
      <div style={{ color: "var(--text)", fontSize: "var(--text-sm)" }}>{message}</div>
    </Modal>
  );
}
