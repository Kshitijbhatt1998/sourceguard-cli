import { useNavigate } from "react-router-dom";

const SEVERITY_COLORS = {
  completed: "text-green-400",
  pending: "text-yellow-400",
  running: "text-blue-400",
  failed: "text-red-400",
};

const RISK_BADGE = (score) => {
  if (score >= 30) return "bg-red-900/50 text-red-300 border border-red-700";
  if (score >= 15) return "bg-orange-900/50 text-orange-300 border border-orange-700";
  if (score >= 5) return "bg-yellow-900/50 text-yellow-300 border border-yellow-700";
  return "bg-green-900/50 text-green-300 border border-green-700";
};

export default function ScanList({ scans }) {
  const navigate = useNavigate();

  if (!scans.length) {
    return (
      <p className="text-gray-500 text-sm mt-8 text-center">
        No scans yet. Run <code className="bg-gray-800 px-1 rounded">sourceguard scan</code> from the CLI to get started.
      </p>
    );
  }

  return (
    <div className="space-y-3">
      {scans.map((scan) => (
        <div
          key={scan.id}
          onClick={() => navigate(`/scan/${scan.id}`)}
          className="bg-gray-900 border border-gray-800 rounded-lg px-5 py-4 flex items-center justify-between cursor-pointer hover:border-gray-600 transition-colors"
        >
          <div>
            <p className="font-medium text-white">{scan.project_name || scan.project_id}</p>
            <p className="text-xs text-gray-500 mt-0.5">
              {scan.source.toUpperCase()} &nbsp;·&nbsp;{" "}
              {scan.started_at
                ? new Date(scan.started_at).toLocaleString()
                : "—"}
            </p>
          </div>

          <div className="flex items-center gap-4">
            <span className={`text-sm capitalize ${SEVERITY_COLORS[scan.status] ?? "text-gray-400"}`}>
              {scan.status}
            </span>
            <span className={`text-xs px-2 py-0.5 rounded-full font-mono ${RISK_BADGE(scan.risk_score)}`}>
              {scan.total_findings} finding{scan.total_findings !== 1 ? "s" : ""}
            </span>
            <span className={`text-xs px-2 py-0.5 rounded-full font-mono ${RISK_BADGE(scan.risk_score)}`}>
              risk {scan.risk_score}
            </span>
          </div>
        </div>
      ))}
    </div>
  );
}
