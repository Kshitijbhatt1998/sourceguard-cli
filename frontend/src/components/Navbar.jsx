import { useNavigate } from "react-router-dom";
import { clearAuthToken } from "../api/client";

export default function Navbar() {
  const navigate = useNavigate();

  const handleLogout = () => {
    clearAuthToken();
    navigate("/login");
  };

  return (
    <nav className="bg-gray-900 border-b border-gray-800 px-6 py-4 flex items-center justify-between">
      <div
        className="flex items-center gap-2 cursor-pointer"
        onClick={() => navigate("/dashboard")}
      >
        <span className="text-brand-500 font-bold text-xl">⛨</span>
        <span className="font-semibold text-white text-lg tracking-tight">
          SourceGuard
        </span>
      </div>
      <button
        onClick={handleLogout}
        className="text-sm text-gray-400 hover:text-white transition-colors"
      >
        Sign out
      </button>
    </nav>
  );
}
