import { useCallback, useEffect, useState } from "react";
import api, { setCsrfToken } from "../services/api";
import { AuthContext } from "./auth";

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [isInitialized, setIsInitialized] = useState(false);

  const updateUser = useCallback((data) => {
    const { csrf_token: csrf, ...profile } = data;
    setCsrfToken(csrf);
    setUser(profile);
    return profile;
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    localStorage.removeItem("s3cure_token");
    api.get("/api/auth/me", { signal: controller.signal })
      .then(({ data }) => updateUser(data))
      .catch(() => {})
      .finally(() => {
        if (!controller.signal.aborted) setIsInitialized(true);
      });
    return () => controller.abort();
  }, [updateUser]);

  const login = useCallback(async (credentials) => {
    const { data } = await api.post("/api/auth/login", credentials);
    return updateUser(data);
  }, [updateUser]);

  const logout = useCallback(async () => {
    await api.post("/api/auth/logout");
    setCsrfToken(null);
    setUser(null);
  }, []);

  const value = { user, isAuthenticated: Boolean(user), isInitialized, login, logout };
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
