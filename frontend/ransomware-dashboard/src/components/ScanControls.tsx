import { useState } from "react";
import { scanFolder } from "../api/scanApi";
import { Search, Terminal, Loader2 } from "lucide-react";
import { motion } from "framer-motion";

export default function ScanControls() {
  const [path, setPath] = useState("");
  const [isScanning, setIsScanning] = useState(false);

  const handleScan = async () => {
    if (!path) return;
    try {
      setIsScanning(true);
      await scanFolder(path);
    } finally {
      setIsScanning(false);
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="glass-card rounded-2xl p-4 md:p-6 flex flex-col md:flex-row gap-4 items-stretch md:items-center"
    >
      <div className="flex items-center gap-4 flex-1">
        <div className="hidden sm:flex items-center justify-center h-12 w-12 rounded-xl bg-orange-500/10 border border-orange-500/20 shadow-inner">
          <Search className="w-5 h-5 text-orange-500" />
        </div>
        <div className="flex-1 space-y-1.5">
          <label className="flex items-center gap-2 text-[10px] font-mono uppercase tracking-[0.2em] text-zinc-500 ml-1">
            <Terminal className="w-3 h-3" />
            Target Vector
          </label>
          <input
            type="text"
            value={path}
            onChange={(e) => setPath(e.target.value)}
            placeholder="D:\\system\\volumes\\..."
            className="w-full bg-black/40 border border-white/5 rounded-xl px-4 py-2.5 text-sm text-zinc-100 placeholder:text-zinc-600 focus:outline-none focus:ring-1 focus:ring-orange-500/50 focus:border-orange-500/30 transition-all font-mono"
          />
        </div>
      </div>

      <motion.button
        whileHover={{ scale: 1.02 }}
        whileTap={{ scale: 0.98 }}
        onClick={handleScan}
        disabled={isScanning || !path}
        className="relative group overflow-hidden px-8 py-3 rounded-xl bg-orange-500 text-black font-bold text-xs uppercase tracking-widest disabled:opacity-50 disabled:cursor-not-allowed transition-all shadow-[0_0_20px_rgba(249,115,22,0.3)] hover:shadow-[0_0_30px_rgba(249,115,22,0.5)]"
      >
        <div className="absolute inset-0 bg-gradient-to-r from-white/0 via-white/20 to-white/0 translate-x-[-100%] group-hover:translate-x-[100%] transition-transform duration-700" />
        <span className="relative flex items-center justify-center gap-2">
          {isScanning ? (
            <>
              <Loader2 className="w-3.5 h-3.5 animate-spin" />
              Analyzing...
            </>
          ) : (
            "Initiate Pulse"
          )}
        </span>
      </motion.button>
    </motion.div>
  );
}
