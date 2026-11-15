import axios from "axios";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ||
  (import.meta.env.DEV ? `${window.location.protocol}//${window.location.hostname}:8000` : "");

const api = axios.create({ baseURL: API_BASE_URL, withCredentials: true });
let csrfToken = null;

export function setCsrfToken(token) {
  csrfToken = token;
}

api.interceptors.request.use((config) => {
  if (csrfToken && !["get", "head", "options"].includes(config.method)) {
    config.headers["X-CSRF-Token"] = csrfToken;
  }
  return config;
});

api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      setCsrfToken(null);
      if (!window.location.pathname.startsWith("/login")) {
        window.location.assign("/login");
      }
    }
    return Promise.reject(error);
  },
);

export default api;
export { API_BASE_URL };
