import { cn } from "../lib/utils";

const variants = {
  default: "bg-secondary",
  primary: "bg-primary",
  critical: "bg-danger",
  warning: "bg-warning text-dark",
  safe: "bg-success",
};

export function Badge({ children, variant = "default", className, ...props }) {
  return (
    <span className={cn("badge", variants[variant], className)} {...props}>
      {children}
    </span>
  );
}
