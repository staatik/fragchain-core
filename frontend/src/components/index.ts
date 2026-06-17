/* Barrel exports — single import surface for shared UI primitives.
 *
 * Screens / future modules can do:
 *   import { DataTable, Toast, ConfirmDialog } from "../components";
 *
 * AppShell + ProtectedLayout stay separately importable for the route
 * tree in App.tsx.
 */
export { AppShell, titleForPath } from "./AppShell";
export { Badge } from "./Badge";
export type { BadgeVariant } from "./Badge";
export { ConfirmDialog } from "./ConfirmDialog";
export { DataTable } from "./DataTable";
export type { ColumnDef } from "./DataTable";
export { Dropdown } from "./Dropdown";
export type { DropdownOption } from "./Dropdown";
export { EmbargoIndicator } from "./EmbargoIndicator";
export { EmptyState, Spinner } from "./EmptyState";
export { FirstRunHint } from "./FirstRunHint";
export { ProtectedLayout } from "./Layout";
export { Modal } from "./Modal";
export { ProgressBar } from "./ProgressBar";
export { Sidebar } from "./Sidebar";
export { SidePanel } from "./SidePanel";
export { StatBlock, StatGrid } from "./StatBlock";
export type { StatColor } from "./StatBlock";
export { TLPBadge } from "./TLPBadge";
export type { TLPLevel } from "./TLPBadge";
export { Topbar } from "./Topbar";
export { ToastProvider, useToast } from "./Toast";
export type { ToastInput, ToastVariant } from "./Toast";
