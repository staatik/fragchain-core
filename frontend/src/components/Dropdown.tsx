import { ReactNode, useEffect, useMemo, useRef, useState } from "react";

export interface DropdownOption<V = string> {
  value: V;
  label: ReactNode;
  /** Plain-text label used by the search filter. Falls back to String(label). */
  searchText?: string;
  disabled?: boolean;
}

interface DropdownBaseProps<V> {
  options: DropdownOption<V>[];
  placeholder?: string;
  searchable?: boolean;
  disabled?: boolean;
  className?: string;
  triggerLabel?: ReactNode;
  /** Accessible name applied to the trigger button (the menu has no native label). */
  ariaLabel?: string;
}

interface SingleProps<V> extends DropdownBaseProps<V> {
  multi?: false;
  value: V | null;
  onChange: (value: V | null) => void;
}

interface MultiProps<V> extends DropdownBaseProps<V> {
  multi: true;
  value: V[];
  onChange: (value: V[]) => void;
}

type DropdownProps<V = string> = SingleProps<V> | MultiProps<V>;

function optionLabelText<V>(opt: DropdownOption<V>): string {
  if (opt.searchText) return opt.searchText;
  if (typeof opt.label === "string" || typeof opt.label === "number") return String(opt.label);
  return String(opt.value);
}

/** Custom dropdown per DarkOps v3 — replaces the native `<select>`.
 *
 *  Supports single-select, multi-select (`multi`), and an optional search
 *  input that filters by `searchText` (or the stringified label).
 *
 *  Click-outside closes the menu; Escape also closes. Selecting an option
 *  in single-select mode closes the menu; multi-select stays open so the
 *  user can tick multiple items at once.
 */
export function Dropdown<V = string>(props: DropdownProps<V>) {
  const { options, placeholder = "Select…", searchable, disabled, className, triggerLabel, ariaLabel } = props;
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const rootRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onClick = (e: MouseEvent) => {
      if (!rootRef.current) return;
      if (!rootRef.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onClick);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onClick);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  useEffect(() => {
    if (!open) setQuery("");
  }, [open]);

  const filtered = useMemo(() => {
    if (!searchable || !query.trim()) return options;
    const q = query.toLowerCase();
    return options.filter((o) => optionLabelText(o).toLowerCase().includes(q));
  }, [options, query, searchable]);

  const isSelected = (val: V): boolean => {
    if (props.multi) return props.value.includes(val);
    return props.value === val;
  };

  const selectValue = (val: V) => {
    if (props.multi) {
      const current = props.value;
      const next = current.includes(val) ? current.filter((v) => v !== val) : [...current, val];
      props.onChange(next);
    } else {
      props.onChange(val === props.value ? null : val);
      setOpen(false);
    }
  };

  const renderTriggerLabel = (): ReactNode => {
    if (triggerLabel !== undefined) return triggerLabel;
    if (props.multi) {
      if (!props.value.length) return placeholder;
      if (props.value.length === 1) {
        const opt = options.find((o) => o.value === props.value[0]);
        return opt?.label ?? String(props.value[0]);
      }
      return `${props.value.length} selected`;
    }
    if (props.value === null) return placeholder;
    const opt = options.find((o) => o.value === props.value);
    return opt?.label ?? String(props.value);
  };

  const isPlaceholder = props.multi ? props.value.length === 0 : props.value === null;

  return (
    <div
      ref={rootRef}
      className={`dropdown${open ? " open" : ""}${className ? ` ${className}` : ""}`}
    >
      <button
        type="button"
        className="dropdown-trigger"
        disabled={disabled}
        onClick={() => !disabled && setOpen((o) => !o)}
        aria-label={ariaLabel}
        aria-expanded={open}
        aria-haspopup="listbox"
        style={isPlaceholder ? { color: "var(--text-muted)" } : undefined}
      >
        {renderTriggerLabel()}
      </button>
      <div className="dropdown-menu" role="listbox">
        {searchable && (
          <input
            className="dropdown-search"
            autoFocus
            placeholder="Search…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onClick={(e) => e.stopPropagation()}
          />
        )}
        {filtered.length === 0 ? (
          <div className="dropdown-empty">No matches</div>
        ) : (
          filtered.map((opt) => {
            const selected = isSelected(opt.value);
            return (
              <div
                key={String(opt.value)}
                className={`dropdown-option${props.multi ? " multi" : ""}${selected ? " selected" : ""}${opt.disabled ? " disabled" : ""}`}
                role="option"
                aria-selected={selected}
                onClick={() => !opt.disabled && selectValue(opt.value)}
              >
                {props.multi && (
                  <span className="dropdown-check">{selected ? "✓" : ""}</span>
                )}
                {opt.label}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
