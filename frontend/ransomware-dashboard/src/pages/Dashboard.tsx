import { useEffect, useState } from "react";
import { fetchResults, fetchQuarantinedFiles } from "../api/scanApi";
import { ScanResult, QuarantinedFile } from "../types/scan";
import {
  ShieldAlert,
  Activity,
  RefreshCw,
  Cpu,
  Terminal,
  Eye,
  AlertTriangle,
  Archive,
  Lock,
  Trash2,
  RotateCcw,
} from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

import ScanControls from "../components/ScanControls";
import ScanTables from "../components/ScanTables";
import QuarantineTables from "../components/QuarantineTables";
import StatusBadge from "../components/StatusBadge";

type ViewMode = "scans" | "quarantine";

export default function Dashboard() {
  const [data, setData] = useState<ScanResult>({
    timestamp: null,
    files: [],
  });
  
  const [quarantinedFiles, setQuarantinedFiles] = useState<QuarantinedFile[]>([]);
  const [viewMode, setViewMode] = useState<ViewMode>("scans");
  const [loading, setLoading] = useState<boolean>(true);
  const [quarantineLoading, setQuarantineLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [quarantineError, setQuarantineError] = useState<string | null>(null);

  // Fetch scan results
  useEffect(() => {
    const fetchData = async () => {
      try {
        const res = await fetchResults();
        setData(res);
        setError(null);
      } catch (err) {
        setError("Connection interrupted");
      } finally {
        setLoading(false);
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 2000);
    return () => clearInterval(interval);
  }, []);

  // Fetch quarantined files
  const loadQuarantinedFiles = async () => {
    setQuarantineLoading(true);
    try {
      const files = await fetchQuarantinedFiles();
      setQuarantinedFiles(files);
      setQuarantineError(null);
    } catch (err) {
      setQuarantineError("Failed to load quarantined files");
    } finally {
      setQuarantineLoading(false);
    }
  };

  // Load quarantined files when switching to quarantine view
  useEffect(() => {
    if (viewMode === "quarantine") {
      loadQuarantinedFiles();
    }
  }, [viewMode]);

  // Calculate risk levels for scan results
  const criticalFiles = data.files.filter(
    (f) => f.risk_level === "CRITICAL" || (f.risk_score !== undefined && f.risk_score >= 80)
  ).length;

  const highFiles = data.files.filter(
    (f) => f.risk_level === "HIGH" || (f.risk_score !== undefined && f.risk_score >= 60 && f.risk_score < 80)
  ).length;

  const mediumFiles = data.files.filter(
    (f) => f.risk_level === "MEDIUM" || (f.risk_score !== undefined && f.risk_score >= 40 && f.risk_score < 60)
  ).length;

  // Calculate quarantine stats
  const quarantineTotal = quarantinedFiles.length;
  const quarantineSize = quarantinedFiles.reduce((acc, file) => acc + (file.size || 0), 0);
  const formattedQuarantineSize = formatFileSize(quarantineSize);

  // Helper function to format file size
  function formatFileSize(bytes: number): string {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  return (
    <div className="min-h-screen bg-[#0B0B0F] text-zinc-50 antialiased">
      <div className="fixed inset-0 bg-gradient-to-br from-violet-950/20 via-[#0B0B0F] to-fuchsia-950/10" />
      <div className="fixed inset-0 bg-[radial-gradient(ellipse_at_top_right,_var(--tw-gradient-stops))] from-violet-900/10 via-transparent to-transparent" />
      <div className="fixed inset-0 bg-[linear-gradient(rgba(255,255,255,0.02)_1px,transparent_1px),linear-gradient(90deg,rgba(255,255,255,0.02)_1px,transparent_1px)] bg-[size:64px_64px] [mask-image:radial-gradient(ellipse_at_center,black_20%,transparent_80%)]" />

      <div className="relative">
        {/* HEADER */}
        <header className="border-b border-white/5 backdrop-blur-xl bg-black/20">
          <div className="max-w-[1600px] mx-auto px-8 py-5 flex justify-between items-center">
            <div className="flex items-center gap-3">
              <div className="h-9 w-9 flex items-center justify-center rounded-lg bg-gradient-to-br from-violet-500 to-fuchsia-500">
                <ShieldAlert className="w-5 h-5 text-white" strokeWidth={2.5} />
              </div>
              <div>
                <h1 className="text-lg font-semibold tracking-tight text-white">
                  Reconware
                </h1>
                <p className="text-[10px] text-zinc-500 font-medium">
                  Threat Detection Platform
                </p>
              </div>
            </div>

            <div className="flex items-center gap-4">
              {/* View Toggle */}
              <div className="flex items-center gap-1 p-1 rounded-lg bg-white/5 border border-white/10">
                <button
                  onClick={() => setViewMode("scans")}
                  className={`px-3 py-1.5 rounded-md text-xs font-medium transition-all ${
                    viewMode === "scans"
                      ? "bg-violet-500/20 text-violet-400"
                      : "text-zinc-400 hover:text-zinc-300"
                  }`}
                >
                  <Terminal className="w-3.5 h-3.5 inline-block mr-1.5" />
                  Scans
                </button>
                <button
                  onClick={() => setViewMode("quarantine")}
                  className={`px-3 py-1.5 rounded-md text-xs font-medium transition-all ${
                    viewMode === "quarantine"
                      ? "bg-violet-500/20 text-violet-400"
                      : "text-zinc-400 hover:text-zinc-300"
                  }`}
                >
                  <Archive className="w-3.5 h-3.5 inline-block mr-1.5" />
                  Quarantine
                  {quarantineTotal > 0 && (
                    <span className="ml-1.5 px-1.5 py-0.5 bg-rose-500/20 text-rose-400 rounded-full text-[8px]">
                      {quarantineTotal}
                    </span>
                  )}
                </button>
              </div>

              <div className="hidden md:flex items-center gap-6 px-4 py-2 rounded-full bg-white/5 border border-white/5">
                <div className="flex items-center gap-2">
                  <div className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
                  <span className="text-xs text-zinc-400 font-medium">
                    Active
                  </span>
                </div>
                <div className="h-3 w-px bg-white/10" />
                <div className="flex items-center gap-2">
                  <Eye className="w-3.5 h-3.5 text-zinc-500" />
                  <span className="text-xs text-zinc-400 font-medium">
                    {viewMode === "scans" ? data.files.length : quarantineTotal}
                  </span>
                </div>
              </div>

              <StatusBadge filesCount={data.files.length} />
            </div>
          </div>
        </header>

        {/* MAIN */}
        <main className="max-w-[1600px] mx-auto px-8 py-12">

          {/* Scan Controls - Only show in scans view */}
          {viewMode === "scans" && (
            <div className="mb-8">
              <ScanControls />
            </div>
          )}

          {/* Stats - Dynamic based on view mode */}
          {viewMode === "scans" ? (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
              {/* Critical */}
              <div className="p-6 rounded-2xl bg-black/40 border border-white/10">
                <div className="flex justify-between mb-4">
                  <AlertTriangle className="w-4 h-4 text-rose-400" />
                  <span className="text-[10px] font-bold text-rose-400 uppercase">
                    Critical
                  </span>
                </div>
                <h3 className="text-3xl font-bold">{criticalFiles}</h3>
                <p className="text-xs text-zinc-500">Severe detections</p>
              </div>

              {/* High */}
              <div className="p-6 rounded-2xl bg-black/40 border border-white/10">
                <div className="flex justify-between mb-4">
                  <Activity className="w-4 h-4 text-orange-400" />
                  <span className="text-[10px] font-bold text-orange-400 uppercase">
                    High
                  </span>
                </div>
                <h3 className="text-3xl font-bold">{highFiles}</h3>
                <p className="text-xs text-zinc-500">High-risk threats</p>
              </div>

              {/* Medium */}
              <div className="p-6 rounded-2xl bg-black/40 border border-white/10">
                <div className="flex justify-between mb-4">
                  <Cpu className="w-4 h-4 text-amber-400" />
                  <span className="text-[10px] font-bold text-amber-400 uppercase">
                    Medium
                  </span>
                </div>
                <h3 className="text-3xl font-bold">{mediumFiles}</h3>
                <p className="text-xs text-zinc-500">Suspicious patterns</p>
              </div>
            </div>
          ) : (
            // Quarantine Stats
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
              <div className="p-6 rounded-2xl bg-black/40 border border-white/10">
                <div className="flex justify-between mb-4">
                  <Archive className="w-4 h-4 text-violet-400" />
                  <span className="text-[10px] font-bold text-violet-400 uppercase">
                    Total
                  </span>
                </div>
                <h3 className="text-3xl font-bold">{quarantineTotal}</h3>
                <p className="text-xs text-zinc-500">Quarantined files</p>
              </div>

              <div className="p-6 rounded-2xl bg-black/40 border border-white/10">
                <div className="flex justify-between mb-4">
                  <Lock className="w-4 h-4 text-blue-400" />
                  <span className="text-[10px] font-bold text-blue-400 uppercase">
                    Size
                  </span>
                </div>
                <h3 className="text-3xl font-bold">{formattedQuarantineSize}</h3>
                <p className="text-xs text-zinc-500">Total quarantine size</p>
              </div>

              <div className="p-6 rounded-2xl bg-black/40 border border-white/10">
                <div className="flex justify-between mb-4">
                  <Trash2 className="w-4 h-4 text-amber-400" />
                  <span className="text-[10px] font-bold text-amber-400 uppercase">
                    Actions
                  </span>
                </div>
                <button
                  onClick={loadQuarantinedFiles}
                  className="text-xs flex items-center gap-2 px-3 py-1.5 rounded-lg bg-white/5 hover:bg-white/10 transition-colors"
                >
                  <RotateCcw className="w-3 h-3" />
                  Refresh
                </button>
              </div>
            </div>
          )}

          {/* Table */}
          <div className="rounded-2xl bg-black/40 border border-white/10 overflow-hidden">
            <div className="px-6 py-4 border-b border-white/5 bg-white/5 flex justify-between items-center">
              <div className="flex items-center gap-3">
                {viewMode === "scans" ? (
                  <Terminal className="w-4 h-4 text-violet-400" />
                ) : (
                  <Archive className="w-4 h-4 text-violet-400" />
                )}
                <div>
                  <h3 className="text-sm font-semibold">
                    {viewMode === "scans" ? "Detection Log" : "Quarantined Files"}
                  </h3>
                  <p className="text-xs text-zinc-500">
                    {viewMode === "scans" 
                      ? `${data.files.length} entries indexed`
                      : `${quarantineTotal} files isolated`
                    }
                  </p>
                </div>
              </div>

              {viewMode === "scans" ? (
                !error ? (
                  <div className="flex items-center gap-2 text-xs text-zinc-500">
                    <RefreshCw className="w-3 h-3" />
                    {data.timestamp
                      ? new Date(data.timestamp).toLocaleTimeString()
                      : "Syncing..."}
                  </div>
                ) : (
                  <div className="text-xs text-rose-400">{error}</div>
                )
              ) : (
                quarantineError && (
                  <div className="text-xs text-rose-400">{quarantineError}</div>
                )
              )}
            </div>

            <div className="p-6">
              <AnimatePresence mode="wait">
                {viewMode === "scans" ? (
                  loading ? (
                    <motion.div
                      key="loading"
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      exit={{ opacity: 0 }}
                      className="h-96 flex items-center justify-center"
                    >
                      <motion.div
                        animate={{ rotate: 360 }}
                        transition={{ duration: 2, repeat: Infinity, ease: "linear" }}
                        className="w-12 h-12 border-2 border-white/10 border-t-violet-500 rounded-full"
                      />
                    </motion.div>
                  ) : (
                    <motion.div
                      key="content"
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      exit={{ opacity: 0 }}
                    >
                      <ScanTables files={data.files} />
                    </motion.div>
                  )
                ) : (
                  quarantineLoading ? (
                    <motion.div
                      key="quarantine-loading"
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      exit={{ opacity: 0 }}
                      className="h-96 flex items-center justify-center"
                    >
                      <motion.div
                        animate={{ rotate: 360 }}
                        transition={{ duration: 2, repeat: Infinity, ease: "linear" }}
                        className="w-12 h-12 border-2 border-white/10 border-t-violet-500 rounded-full"
                      />
                    </motion.div>
                  ) : (
                    <motion.div
                      key="quarantine-content"
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      exit={{ opacity: 0 }}
                    >
                      <QuarantineTables 
                        files={quarantinedFiles} 
                        onRefresh={loadQuarantinedFiles}
                      />
                    </motion.div>
                  )
                )}
              </AnimatePresence>
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}