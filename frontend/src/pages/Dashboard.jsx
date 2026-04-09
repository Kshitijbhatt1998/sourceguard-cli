import { useEffect, useState } from "react";
import api from "../api/client";
import Navbar from "../components/Navbar";
import ScanList from "../components/ScanList";

export default function Dashboard() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    api
      .get("/scan/")
      .then((res) => setScans(res.data))
      .catch(() => setError("Failed to load scans."))
      .finally(() => setLoading(false));
  }, []);

  // Aggregate stats
  const totalFindings = scans.reduce((sum, s) => sum + s.total_findings, 0);
  const maxRisk = scans.reduce((max, s) => Math.max(max, s.risk_score), 0);
  const failedScans = scans.filter((s) => s.status === "failed").length;

  return (
    <div className="min-h-screen bg-gray-950">
      <Navbar />

      <main className="max-w-5xl mx-auto px-6 py-8">
        <h2 className="text-xl font-semibold text-white mb-6">Overview</h2>

        {/* Stats row */}
        <div className="grid grid-cols-3 gap-4 mb-8">
          <StatCard label="Total Scans" value={scans.length} />
          <StatCard label="Total Findings" value={totalFindings} highlight={totalFindings > 0} />
          <StatCard label="Highest Risk Score" value={maxRisk} highlight={maxRisk >= 15} />
        </div>

        {failedScans > 0 && (
          <div className="mb-6 bg-red-950/40 border border-red-800 rounded-lg px-4 py-3 text-sm text-red-300">
            {failedScans} scan{failedScans > 1 ? "s" : ""} failed. Check your GitHub webhook configuration.
          </div>
        )}

        <h2 className="text-lg font-semibold text-white mb-4">Recent Scans</h2>

        {loading && <p className="text-gray-500 text-sm">Loading…</p>}
        {error && <p className="text-red-400 text-sm">{error}</p>}
        {!loading && !error && <ScanList scans={scans} />}
      </main>
    </div>
  );
}

function StatCard({ label, value, highlight = false }) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg px-5 py-4">
      <p className="text-xs text-gray-500 uppercase tracking-wider">{label}</p>
      <p className={`text-3xl font-bold mt-1 ${highlight ? "text-red-400" : "text-white"}`}>
        {value}
      </p>
    </div>
  );
}
