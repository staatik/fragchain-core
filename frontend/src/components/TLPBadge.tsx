import "./TLPBadge.css";

export type TLPLevel =
  | "tlp:clear"
  | "tlp:green"
  | "tlp:amber"
  | "tlp:amber+strict"
  | "tlp:red";

interface TLPBadgeProps {
  level: TLPLevel | string;
  showPrefix?: boolean;
  className?: string;
  title?: string;
}

const LEVEL_TO_CLASS: Record<string, string> = {
  "tlp:clear": "tlp-clear",
  "tlp:green": "tlp-green",
  "tlp:amber": "tlp-amber",
  "tlp:amber+strict": "tlp-amber-strict",
  "tlp:red": "tlp-red",
};

const LEVEL_TO_LABEL: Record<string, string> = {
  "tlp:clear": "CLEAR",
  "tlp:green": "GREEN",
  "tlp:amber": "AMBER",
  "tlp:amber+strict": "AMBER+STRICT",
  "tlp:red": "RED",
};

/** TLP 2.0 classification badge.
 *
 *  Uses the DarkOps `.badge.tlp-*` styles from `darkops.css`. The colour and
 *  border treatment match the FragChain design system reference:
 *    - clear → text-dim, no border
 *    - green → accent3 border
 *    - amber → warning border
 *    - amber+strict → warning border with diagonal stripes
 *    - red → danger background
 */
export function TLPBadge({ level, showPrefix = true, className, title }: TLPBadgeProps) {
  const normalized = String(level).toLowerCase();
  const variant = LEVEL_TO_CLASS[normalized] ?? "tlp-clear";
  const label = LEVEL_TO_LABEL[normalized] ?? normalized.toUpperCase();
  const display = showPrefix ? `TLP:${label}` : label;
  return (
    <span
      className={`badge ${variant} tlp-badge${className ? ` ${className}` : ""}`}
      title={title ?? `Traffic Light Protocol: ${label}`}
      data-level={normalized}
    >
      {display}
    </span>
  );
}
