import { useState } from "react";
import { motion } from "framer-motion";
import { 
  RotateCcw, 
  Trash2, 
  FileText, 
  AlertTriangle,
  Calendar,
  HardDrive,
  Shield
} from "lucide-react";
import { QuarantinedFile } from "../types/scan";
import { restoreFromQuarantine, deleteFromQuarantine } from "../api/scanApi";

interface QuarantineTablesProps {
  files: QuarantinedFile[];
  onRefresh: () => void;
}

export default function QuarantineTables({ files, onRefresh }: QuarantineTablesProps) {
  const [actionInProgress, setActionInProgress] = useState<string | null>(null);

  const handleRestore = async (fileId: string) => {
    setActionInProgress(fileId);
    try {
      await restoreFromQuarantine(fileId);
      onRefresh();
    } catch (error) {
      console.error("Failed to restore file:", error);
    } finally {
      setActionInProgress(null);
    }
  };

  const handleDelete = async (fileId: string) => {
    if (!confirm("Are you sure you want to permanently delete this file?")) return;
    
    setActionInProgress(fileId);
    try {
      await deleteFromQuarantine(fileId);
      onRefresh();
    } catch (error) {
      console.error("Failed to delete file:", error);
    } finally {
      setActionInProgress(null);
    }
  };

  const getRiskColor = (level: string) => {
    switch (level) {
      case "CRITICAL": return "text-rose-400 bg-rose-400/10";
      case "HIGH": return "text-orange-400 bg-orange-400/10";
      case "MEDIUM": return "text-amber-400 bg-amber-400/10";
      default: return "text-blue-400 bg-blue-400/10";
    }
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleString();
  };

  const formatSize = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  if (files.length === 0) {
    return (
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="h-96 flex flex-col items-center justify-center text-center"
      >
        <Shield className="w-16 h-16 text-zinc-700 mb-4" />
        <h3 className="text-lg font-semibold text-zinc-400 mb-2">No Quarantined Files</h3>
        <p className="text-sm text-zinc-600 max-w-md">
          Quarantine is empty. When threats are detected and isolated, they will appear here.
        </p>
      </motion.div>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full">
        <thead>
          <tr className="text-xs text-zinc-500 border-b border-white/5">
            <th className="text-left font-medium pb-3">File</th>
            <th className="text-left font-medium pb-3">Threat</th>
            <th className="text-left font-medium pb-3">Risk Level</th>
            <th className="text-left font-medium pb-3">Size</th>
            <th className="text-left font-medium pb-3">Quarantined</th>
            <th className="text-right font-medium pb-3">Actions</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-white/5">
          {files.map((file) => (
            <motion.tr
              key={file.id}
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="group hover:bg-white/5 transition-colors"
            >
              <td className="py-4">
                <div className="flex items-center gap-3">
                  <FileText className="w-4 h-4 text-zinc-600" />
                  <div>
                    <div className="text-sm font-medium text-zinc-300">
                      {file.filename}
                    </div>
                    <div className="text-xs text-zinc-600">
                      {file.original_path}
                    </div>
                  </div>
                </div>
              </td>
              <td className="py-4">
                <div className="text-sm text-zinc-300">{file.threat_name}</div>
              </td>
              <td className="py-4">
                <span className={`text-[10px] font-bold px-2 py-1 rounded-full ${getRiskColor(file.risk_level)}`}>
                  {file.risk_level}
                </span>
              </td>
              <td className="py-4">
                <div className="flex items-center gap-1.5 text-sm text-zinc-400">
                  <HardDrive className="w-3.5 h-3.5" />
                  {formatSize(file.size)}
                </div>
              </td>
              <td className="py-4">
                <div className="flex items-center gap-1.5 text-sm text-zinc-400">
                  <Calendar className="w-3.5 h-3.5" />
                  {formatDate(file.quarantine_date)}
                </div>
              </td>
              <td className="py-4 text-right">
                <div className="flex items-center justify-end gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                  <button
                    onClick={() => handleRestore(file.id)}
                    disabled={actionInProgress === file.id}
                    className="p-1.5 rounded-lg bg-emerald-400/10 text-emerald-400 hover:bg-emerald-400/20 transition-colors disabled:opacity-50"
                    title="Restore file"
                  >
                    <RotateCcw className="w-4 h-4" />
                  </button>
                  <button
                    onClick={() => handleDelete(file.id)}
                    disabled={actionInProgress === file.id}
                    className="p-1.5 rounded-lg bg-rose-400/10 text-rose-400 hover:bg-rose-400/20 transition-colors disabled:opacity-50"
                    title="Delete permanently"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </td>
            </motion.tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}