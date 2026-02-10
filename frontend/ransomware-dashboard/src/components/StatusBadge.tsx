import { motion } from "framer-motion";

interface StatusBadgeProps {
  filesCount: number;
}

const getStatus = (filesCount: number) => {
  if (filesCount === 0)
    return {
      text: "Sector Idle",
      tone: "idle",
      color: "zinc",
    };
  return {
    text: "Intercepting",
    tone: "active",
    color: "emerald",
  };
};

export default function StatusBadge({ filesCount }: StatusBadgeProps) {
  const status = getStatus(filesCount);

  return (
    <div className="inline-flex items-center gap-3 px-4 py-2 rounded-full glass-card border-white/5 bg-white/[0.01]">
      <div className="relative flex h-2 w-2">
        <motion.span
          animate={status.tone === "active" ? { scale: [1, 1.5, 1], opacity: [0.5, 1, 0.5] } : {}}
          transition={{ duration: 2, repeat: Infinity }}
          className={`absolute inline-flex h-full w-full rounded-full opacity-75 ${status.color === "emerald" ? "bg-emerald-400" : "bg-zinc-500"
            }`}
        />
        <span className={`relative inline-flex rounded-full h-2 w-2 ${status.color === "emerald" ? "bg-emerald-500" : "bg-zinc-600"
          }`} />
      </div>
      <span className="text-[10px] font-mono uppercase tracking-[0.3em] text-white/60">
        {status.text}
      </span>
    </div>
  );
}