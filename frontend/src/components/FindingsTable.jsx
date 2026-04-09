const SEV_CLASSES = {
  CRITICAL: "bg-red-900/60 text-red-300 border border-red-700",
  HIGH:     "bg-orange-900/60 text-orange-300 border border-orange-700",
  MEDIUM:   "bg-yellow-900/60 text-yellow-300 border border-yellow-700",
  LOW:      "bg-blue-900/60 text-blue-300 border border-blue-700",
};

export default function FindingsTable({ findings }) {
  if (!findings.length) {
    return (
      <p className="text-green-400 text-sm mt-4">
        No findings — this scan is clean.
      </p>
    );
  }

  return (
    <div className="overflow-x-auto rounded-lg border border-gray-800">
      <table className="w-full text-sm">
        <thead className="bg-gray-900 text-gray-400 text-xs uppercase tracking-wider">
          <tr>
            <th className="px-4 py-3 text-left">Severity</th>
            <th className="px-4 py-3 text-left">Type</th>
            <th className="px-4 py-3 text-left">File</th>
            <th className="px-4 py-3 text-left">Line</th>
            <th className="px-4 py-3 text-left">Match</th>
            <th className="px-4 py-3 text-left">Suggestion</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-800">
          {findings.map((f) => (
            <tr key={f.id} className="hover:bg-gray-900/50 transition-colors">
              <td className="px-4 py-3">
                <span
                  className={`text-xs px-2 py-0.5 rounded-full font-semibold ${
                    SEV_CLASSES[f.severity] ?? "bg-gray-800 text-gray-300"
                  }`}
                >
                  {f.severity}
                </span>
              </td>
              <td className="px-4 py-3 text-gray-300 font-mono text-xs">{f.type}</td>
              <td className="px-4 py-3 text-gray-400 font-mono text-xs truncate max-w-xs" title={f.file_path}>
                {f.file_path}
              </td>
              <td className="px-4 py-3 text-gray-400 font-mono">{f.line_number}</td>
              <td className="px-4 py-3 font-mono text-xs text-red-300 bg-red-950/20 rounded">
                {f.match_masked}
              </td>
              <td className="px-4 py-3 text-gray-400 text-xs max-w-sm">{f.suggestion}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
