import { createContext, useContext } from "react";

export const AuthContext = createContext(null);

/**
 * Custom Hook for accessing Authentication Context.
 * Enforces usage within the AuthProvider hierarchy.
 */
export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error("useAuth must be used within AuthProvider");
  }
  return ctx;
}
