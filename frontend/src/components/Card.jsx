import { cn } from "../lib/utils";

export function Card({ children, className, ...props }) {
  return (
    <div
      className={cn("card shadow bg-dark border-secondary", className)}
      {...props}
    >
      {children}
    </div>
  );
}

export function CardHeader({ children, className }) {
  return (
    <div className={cn("card-header bg-dark border-secondary", className)}>
      {children}
    </div>
  );
}

export function CardTitle({ children, className }) {
  return (
    <h3 className={cn("card-title mb-0 h5 text-light", className)}>
      {children}
    </h3>
  );
}

export function CardContent({ children, className }) {
  return <div className={cn("card-body", className)}>{children}</div>;
}

export function CardFooter({ children, className }) {
  return (
    <div className={cn("card-footer bg-dark border-secondary", className)}>
      {children}
    </div>
  );
}
