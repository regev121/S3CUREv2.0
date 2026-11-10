import { clsx } from "clsx";

/** Merge class names (Bootstrap / utility). */
export function cn(...inputs) {
  return clsx(inputs);
}
