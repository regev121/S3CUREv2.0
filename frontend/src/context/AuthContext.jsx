import {
  useState,
  useEffect,
  useCallback,
} from "react";
import api from "../services/api";

import { AuthContext } from "./auth";

const TOKEN_KEY = "s3cure_token";

/**
 * Authentication Context Provider.
 * Manages the global security state of the application, including:
 * - JWT Token persistence and retrieval.
 * - User Profile data synchronization.
 * - Session initialization and validation.
 */
export function AuthProvider({ children }) {
  const [token, setTokenState] = useState(() =>
    localStorage.getItem(TOKEN_KEY)
  );
  const [user, setUser] = useState(null); // Structure: { username, role, id }
  const [isInitialized, setIsInitialized] = useState(false);

  /**
   * Asynchronously retrieves the current user's profile from the backend.
   * Updates the local state with identity and RBAC role information.
   * Handles potential API failures gracefully by resetting the user state.
   */
  const fetchUser = useCallback(async () => {
    try {
      const { data } = await api.get("/api/auth/me");
      setUser(data);
    } catch (error) {
      console.error("Failed to fetch user profile", error);
      setUser(null);
    }
  }, []);

  /**
   * Session Initialization Effect.
   * - Hydrates the session from LocalStorage upon application mount.
   * - Validates the stored token by attempting to fetch the user profile.
   * - Marks initialization as complete to unblock UI rendering.
   */
  useEffect(() => {
    const initializeHelper = async () => {
        const stored = localStorage.getItem(TOKEN_KEY);
        if (stored) {
            setTokenState(stored);
            try {
                // Verify token validity via backend profile endpoint
                const { data } = await api.get("/api/auth/me");
                setUser(data);
            } catch (e) {
                console.error("Token invalid or server error", e);
                // Token is retained for retry unless explicitly invalidated by interceptor
            }
        }
        setIsInitialized(true);
    };

    initializeHelper();
  }, []);

  /**
   * Establishes a new authenticated session.
   * - Persists the JWT token to LocalStorage.
   * - Updates context state.
   * - Trigger immediate profile synchronization.
   */
  const login = useCallback(async (newToken) => {
    if (newToken) {
      localStorage.setItem(TOKEN_KEY, newToken);
      setTokenState(newToken);

      try {
        const { data } = await api.get("/api/auth/me");
        setUser(data);
        return data;
      } catch (e) {
        localStorage.removeItem(TOKEN_KEY);
        setTokenState(null);
        setUser(null);
        throw e;
      }
    }
  }, []);

  /**
   * Terminates the current session.
   * - Clears persistence.
   * - Resets all security context states.
   */
  const logout = useCallback(() => {
    localStorage.removeItem(TOKEN_KEY);
    setTokenState(null);
    setUser(null);
  }, []);

  const isAuthenticated = Boolean(token);

  const value = {
    token,
    user,
    isAuthenticated,
    isInitialized,
    login,
    logout,
    refreshUser: fetchUser
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
