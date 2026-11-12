import axios from "axios";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";

/**
 * Singleton Axios Instance.
 * Configured with base URL and default JSON headers for consistent API communication.
 */
const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    "Content-Type": "application/json",
  },
});

/**
 * Request Interceptor.
 * Automatically injects the JWT Authentication Bearer token into the Authorization header
 * of every outgoing request, ensuring secure stateless communication.
 */
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem("s3cure_token");
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

/**
 * Response Interceptor.
 * Global error handling middleware.
 * - Captures 401 Unauthorized responses to trigger session termination and redirection.
 * - Captures 403 Forbidden responses to notify the user of privilege violations.
 */
api.interceptors.response.use(
  (response) => response,
  (error) => {
    // Session Expiration Handling
    if (error.response?.status === 401) {
      localStorage.removeItem("s3cure_token");

      // Prevent redirection loop if already on authentication pages
      if (!window.location.pathname.startsWith("/login")) {
        window.location.href = "/login";
      }
    }
    // Authorization Failure Handling
    else if (error.response?.status === 403) {
      alert("Access Denied: You do not have permission to perform this action.");
    }
    return Promise.reject(error);
  }
);

export default api;
export { API_BASE_URL };
