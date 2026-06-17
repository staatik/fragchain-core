import { ReactNode, useMemo, useState } from "react";

export interface ColumnDef<T> {
  /** Stable key used both as React `key` and as the sort accessor. */
  key: string;
  /** Header label. */
  header: ReactNode;
  /** Cell renderer. Defaults to `row[key]` stringified. */
  render?: (row: T, rowIndex: number) => ReactNode;
  /** Optional accessor for sort comparison; defaults to `row[key]`. */
  sortAccessor?: (row: T) => string | number | null | undefined;
  /** When true, header click toggles asc → desc → none. */
  sortable?: boolean;
  /** Horizontal alignment for both cell and header. */
  align?: "left" | "center" | "right";
  /** Header `<th>` className override. */
  className?: string;
  /** Per-cell className. Receives the row. */
  cellClassName?: (row: T) => string | undefined;
  /** Fixed width (CSS string e.g. "120px" or "20%"). */
  width?: string;
}

interface DataTableProps<T> {
  rows: T[];
  columns: ColumnDef<T>[];
  /** Unique key per row. */
  rowKey: (row: T, index: number) => string;
  /** Row click → opens a side panel typically. */
  onRowClick?: (row: T) => void;
  /** Render an inline "empty" state when `rows` is empty. */
  emptyState?: ReactNode;
  /** Whether to render header row. */
  showHeader?: boolean;
  /** Compact row padding. */
  dense?: boolean;
  className?: string;
}

type SortDir = "asc" | "desc" | null;

interface SortState {
  key: string | null;
  dir: SortDir;
}

function compare<T>(a: T, b: T, accessor: (row: T) => unknown): number {
  const va = accessor(a);
  const vb = accessor(b);
  if (va == null && vb == null) return 0;
  if (va == null) return 1;
  if (vb == null) return -1;
  if (typeof va === "number" && typeof vb === "number") return va - vb;
  return String(va).localeCompare(String(vb));
}

/** Generic data table — DarkOps `.data-table` styling.
 *
 *  Sorting is client-side: pass `sortable: true` on a column to enable
 *  clicking the header. For server-driven sorting, omit `sortable` and
 *  drive the request from the parent.
 */
export function DataTable<T>({
  rows,
  columns,
  rowKey,
  onRowClick,
  emptyState,
  showHeader = true,
  dense = false,
  className,
}: DataTableProps<T>) {
  const [sort, setSort] = useState<SortState>({ key: null, dir: null });

  const sortedRows = useMemo(() => {
    if (!sort.key || !sort.dir) return rows;
    const col = columns.find((c) => c.key === sort.key);
    if (!col || !col.sortable) return rows;
    const accessor =
      col.sortAccessor ?? ((row: T) => (row as Record<string, unknown>)[sort.key as string]);
    const copy = rows.slice();
    copy.sort((a, b) => compare(a, b, accessor));
    if (sort.dir === "desc") copy.reverse();
    return copy;
  }, [rows, columns, sort]);

  const toggleSort = (key: string) => {
    setSort((cur) => {
      if (cur.key !== key) return { key, dir: "asc" };
      if (cur.dir === "asc") return { key, dir: "desc" };
      return { key: null, dir: null };
    });
  };

  if (!rows.length && emptyState !== undefined) {
    return <>{emptyState}</>;
  }

  return (
    <table className={`data-table${dense ? " dense" : ""}${className ? ` ${className}` : ""}`}>
      {showHeader && (
        <thead>
          <tr>
            {columns.map((c) => {
              const alignClass = c.align && c.align !== "left" ? c.align : "";
              const sortClass = c.sortable
                ? sort.key === c.key && sort.dir === "asc"
                  ? "sortable asc"
                  : sort.key === c.key && sort.dir === "desc"
                  ? "sortable desc"
                  : "sortable"
                : "";
              const cls = [alignClass, sortClass, c.className].filter(Boolean).join(" ");
              return (
                <th
                  key={c.key}
                  className={cls || undefined}
                  style={c.width ? { width: c.width } : undefined}
                  onClick={c.sortable ? () => toggleSort(c.key) : undefined}
                >
                  {c.header}
                </th>
              );
            })}
          </tr>
        </thead>
      )}
      <tbody>
        {sortedRows.map((row, i) => (
          <tr
            key={rowKey(row, i)}
            className={onRowClick ? "row-clickable" : undefined}
            onClick={onRowClick ? () => onRowClick(row) : undefined}
          >
            {columns.map((c) => {
              const alignClass = c.align && c.align !== "left" ? c.align : "";
              const cellCls = [alignClass, c.cellClassName?.(row) ?? ""].filter(Boolean).join(" ");
              const content = c.render
                ? c.render(row, i)
                : ((row as Record<string, unknown>)[c.key] as ReactNode);
              return (
                <td key={c.key} className={cellCls || undefined}>
                  {content as ReactNode}
                </td>
              );
            })}
          </tr>
        ))}
      </tbody>
    </table>
  );
}
