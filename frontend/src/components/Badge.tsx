import { ReactNode } from "react";

export type BadgeVariant =
  | "default"
  | "accent"
  | "accent2"
  | "success"
  | "warning"
  | "danger";

interface BadgeProps {
  variant?: BadgeVariant;
  children: ReactNode;
  className?: string;
  title?: string;
}

/** Coloured semantic badge. Use TLPBadge for TLP-specific styling. */
export function Badge({ variant = "default", children, className, title }: BadgeProps) {
  const variantClass = variant === "default" ? "" : variant;
  return (
    <span
      className={`badge ${variantClass}${className ? ` ${className}` : ""}`.trim()}
      title={title}
    >
      {children}
    </span>
  );
}
