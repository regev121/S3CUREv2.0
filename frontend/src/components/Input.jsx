import { cn } from "../lib/utils";

export function Input({
  label,
  error,
  type = "text",
  className,
  id,
  ...props
}) {
  const inputId = id || label?.toLowerCase().replace(/\s+/g, "-");
  return (
    <div className="mb-3">
      {label && (
        <label htmlFor={inputId} className="form-label text-body-secondary">
          {label}
        </label>
      )}
      <input
        id={inputId}
        type={type}
        className={cn(
          "form-control form-control-lg bg-dark border-secondary text-light",
          error && "border-danger is-invalid",
          className
        )}
        {...props}
      />
      {error && <div className="invalid-feedback d-block">{error}</div>}
    </div>
  );
}
