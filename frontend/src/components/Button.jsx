import { cn } from "../lib/utils";

const variants = {
  primary: "btn-primary",
  danger: "btn-danger",
  secondary: "btn-secondary",
  ghost: "btn-link text-body-secondary",
};

const sizes = {
  sm: "btn-sm",
  md: "",
  lg: "btn-lg",
};

export function Button({
  children,
  variant = "primary",
  size = "md",
  className,
  disabled,
  loading,
  type = "button",
  ...props
}) {
  return (
    <button
      type={type}
      disabled={disabled || loading}
      className={cn("btn", variants[variant], sizes[size], className)}
      {...props}
    >
      {loading ? (
        <>
          <span
            className="spinner-border spinner-border-sm me-2"
            role="status"
            aria-hidden="true"
          />
          Loading...
        </>
      ) : (
        children
      )}
    </button>
  );
}
