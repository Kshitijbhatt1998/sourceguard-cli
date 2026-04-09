import { useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import api from "../api/client";
import FindingsTable from "../components/FindingsTable";
import Navbar from "../components/Navbar";

const STATUS_CLASSES = {
  completed: "text-green-400",
  pending:   "text-yellow-400",
  running:   "text-blue-400",
  failed:    "text-red-400",
};

export default function Project() {
  const { scanId } = useParams();
  const navigate = useNavigate();
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    api
      .get(`/scan/${scanId}/findings`)
      .then((res) => setFindings(res.data))
      .catch(() => setError("Failed to load findings."))
      .finally(() => setLoading(false));
  }, [scanId]);

  // Severity breakdown
  const counts = findings.reduce(
    (acc, f) => {
      acc[f.severity] = (acc[f.severity] ?? 0) + 1;
      return acc;
    },
    { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
  );

  return (
    <div className="min-h-screen bg-gray-950">
      <Navbar />

      <main className="max-w-6xl mx-auto px-6 py-8">
        <button
          onClick={() => navigate("/dashboard")}
          className="text-sm text-gray-400 hover:text-white mb-6 flex items-center gap-1"
        >
          ← Back to dashboard
        </button>

        <div className="flex items-center justify-between mb-6">
          <h2 className="text-xl font-semibold text-white">Scan findings</h2>
          <span className="text-xs text-gray-500 font-mono">{scanId}</span>
        </div>

        {/* Severity summary */}
        {!loading && !error && (
          <div className="grid grid-cols-4 gap-3 mb-8">
            {[
              { label: "Critical", key: "CRITICAL", cls: "text-red-400" },
              { label: "High",     key: "HIGH",     cls: "text-orange-400" },
              { label: "Medium",   key: "MEDIUM",   cls: "text-yellow-400" },
              { label: "Low",      key: "LOW",      cls: "text-blue-400" },
            ].map(({ label, key, cls }) => (
              <div key={key} className="bg-gray-900 border border-gray-800 rounded-lg px-4 py-3">
                <p className="text-xs text-gray-500 uppercase tracking-wider">{label}</p>
                <p className={`text-2xl font-bold mt-0.5 ${cls}`}>{counts[key]}</p>
              </div>
            ))}
          </div>
        )}

        {loading && <p className="text-gray-500 text-sm">Loading findings…</p>}
        {error   && <p className="text-red-400 text-sm">{error}</p>}
        {!loading && !error && <FindingsTable findings={findings} />}
      </main>
    </div>
  );
}
