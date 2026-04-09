import axios from "axios";

const api = axios.create({
  baseURL: "/",
});

// Attach JWT on every request
api.interceptors.request.use((config) => {
  const token = localStorage.getItem("sg_token");
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// On 401 → clear token and redirect to login
api.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response?.status === 401) {
      localStorage.removeItem("sg_token");
      window.location.href = "/login";
    }
    return Promise.reject(err);
  }
);

export const setAuthToken = (token) => {
  localStorage.setItem("sg_token", token);
};

export const clearAuthToken = () => {
  localStorage.removeItem("sg_token");
};

export const isAuthenticated = () => !!localStorage.getItem("sg_token");

export default api;
