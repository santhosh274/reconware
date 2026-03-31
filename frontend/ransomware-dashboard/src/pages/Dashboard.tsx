import React, { useEffect, useState, useMemo, useRef } from "react";
import { fetchResults, fetchQuarantinedFiles, scanFolder, restoreFromQuarantine, deleteFromQuarantine, quarantineFile, getThreatIntel, getReports } from "../api/scanApi";
import { ScanResult, QuarantinedFile } from "../types/scan";

type ViewMode = "scans" | "quarantine" | "threats" | "reports";
type RiskLevel = "ALL" | "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "CLEARED";

const CSS = `
  :root {
    --glass: rgba(255,255,255,0.04);
    --glass-border: rgba(255,255,255,0.09);
    --glass-hover: rgba(255,255,255,0.07);
    --critical: #ff4757;
    --high: #ff6b35;
    --medium: #ffd32a;
    --safe: #2ed573;
    --accent: #a855f7;
    --accent2: #06b6d4;
    --bg-deep: #080b12;
    --text-primary: #f0f0f5;
    --text-muted: rgba(240,240,245,0.45);
    --text-dim: rgba(240,240,245,0.25);
    --mono: 'JetBrains Mono', monospace;
    --sans: 'Syne', sans-serif;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  
  .rw-app { font-family: var(--sans); background: var(--bg-deep); color: var(--text-primary); min-height: 100vh; overflow-x: hidden; position: relative; }
  .rw-bg-orbs { position: fixed; inset: 0; pointer-events: none; z-index: 0; }
  .rw-orb { position: absolute; border-radius: 50%; filter: blur(80px); opacity: 0.18; animation: rw-drift 20s ease-in-out infinite; }
  .rw-orb-1 { width: 500px; height: 500px; background: radial-gradient(circle, #a855f7, transparent); top: -120px; right: -80px; animation-delay: 0s; }
  .rw-orb-2 { width: 400px; height: 400px; background: radial-gradient(circle, #06b6d4, transparent); bottom: -100px; left: -60px; animation-delay: -8s; }
  .rw-orb-3 { width: 300px; height: 300px; background: radial-gradient(circle, #ff4757, transparent); top: 40%; left: 30%; animation-delay: -14s; }
  @keyframes rw-drift { 0%,100% { transform: translate(0,0) scale(1); } 33% { transform: translate(30px,-40px) scale(1.1); } 66% { transform: translate(-20px,20px) scale(0.95); } }
  .rw-scanline { position: fixed; inset: 0; pointer-events: none; z-index: 1; background: repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,0,0,0.03) 2px, rgba(0,0,0,0.03) 4px); }
  .rw-main-app { position: relative; z-index: 2; display: flex; height: 100vh; }

  .rw-sidebar { width: 220px; flex-shrink: 0; background: rgba(8,11,18,0.7); border-right: 1px solid var(--glass-border); backdrop-filter: blur(20px); display: flex; flex-direction: column; }
  .rw-brand { padding: 20px 20px 16px; border-bottom: 1px solid var(--glass-border); }
  .rw-brand-icon { width: 36px; height: 36px; background: linear-gradient(135deg, #a855f7, #06b6d4); border-radius: 10px; display: flex; align-items: center; justify-content: center; margin-bottom: 10px; }
  .rw-brand-icon svg { width: 18px; height: 18px; }
  .rw-brand-name { font-size: 15px; font-weight: 800; letter-spacing: 0.05em; background: linear-gradient(90deg, #a855f7, #06b6d4); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
  .rw-brand-tagline { font-size: 10px; color: var(--text-dim); font-family: var(--mono); letter-spacing: 0.1em; margin-top: 2px; }
  .rw-nav-section { padding: 16px 12px 8px; }
  .rw-nav-label { font-size: 9px; font-family: var(--mono); color: var(--text-dim); letter-spacing: 0.15em; padding: 0 8px; margin-bottom: 6px; }
  .rw-nav-item { display: flex; align-items: center; gap: 10px; padding: 9px 10px; border-radius: 8px; cursor: pointer; transition: all 0.2s; font-size: 13px; font-weight: 600; color: var(--text-muted); border: 1px solid transparent; }
  .rw-nav-item:hover { background: var(--glass); color: var(--text-primary); }
  .rw-nav-item.active { background: linear-gradient(135deg, rgba(168,85,247,0.15), rgba(6,182,212,0.08)); color: var(--text-primary); border-color: rgba(168,85,247,0.3); }
  .rw-nav-item svg { width: 15px; height: 15px; flex-shrink: 0; }
  .rw-nav-badge { margin-left: auto; font-size: 10px; font-family: var(--mono); background: linear-gradient(135deg, #ff4757, #ff6b35); color: white; padding: 2px 6px; border-radius: 10px; font-weight: 700; }
  .rw-sidebar-status { margin-top: auto; padding: 16px; border-top: 1px solid var(--glass-border); }
  .rw-status-row { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; }
  .rw-dot-live { width: 8px; height: 8px; background: var(--safe); border-radius: 50%; animation: rw-pulse-dot 2s infinite; flex-shrink: 0; }
  @keyframes rw-pulse-dot { 0%,100% { box-shadow: 0 0 0 0 rgba(46,213,115,0.4); } 50% { box-shadow: 0 0 0 5px rgba(46,213,115,0); } }
  .rw-status-text { font-size: 11px; color: var(--safe); font-family: var(--mono); font-weight: 600; }
  .rw-status-detail { font-size: 10px; color: var(--text-dim); font-family: var(--mono); }

  .rw-main { flex: 1; display: flex; flex-direction: column; overflow: hidden; }
  .rw-topbar { display: flex; align-items: center; gap: 12px; padding: 14px 24px; background: rgba(8,11,18,0.5); border-bottom: 1px solid var(--glass-border); backdrop-filter: blur(20px); flex-shrink: 0; }
  .rw-search-wrap { flex: 1; position: relative; max-width: 400px; }
  .rw-search-wrap svg { position: absolute; left: 12px; top: 50%; transform: translateY(-50%); width: 14px; height: 14px; color: var(--text-dim); pointer-events: none; }
  .rw-search-input { width: 100%; padding: 8px 12px 8px 36px; background: var(--glass); border: 1px solid var(--glass-border); border-radius: 8px; color: var(--text-primary); font-family: var(--mono); font-size: 12px; outline: none; transition: all 0.2s; }
  .rw-search-input:focus { border-color: rgba(168,85,247,0.4); background: rgba(255,255,255,0.06); }
  .rw-topbar-actions { display: flex; align-items: center; gap: 8px; margin-left: auto; }
  .rw-icon-btn { width: 34px; height: 34px; border-radius: 8px; background: var(--glass); border: 1px solid var(--glass-border); display: flex; align-items: center; justify-content: center; cursor: pointer; transition: all 0.2s; position: relative; color: var(--text-muted); }
  .rw-icon-btn:hover { background: var(--glass-hover); color: var(--text-primary); border-color: rgba(255,255,255,0.15); }
  .rw-icon-btn svg { width: 15px; height: 15px; }
  .rw-notif-badge { position: absolute; top: -4px; right: -4px; width: 16px; height: 16px; border-radius: 50%; background: var(--critical); font-size: 9px; font-weight: 700; display: flex; align-items: center; justify-content: center; font-family: var(--mono); color: white; border: 2px solid var(--bg-deep); }
  .rw-view-toggle { display: flex; gap: 2px; padding: 3px; background: var(--glass); border: 1px solid var(--glass-border); border-radius: 9px; }
  .rw-view-btn { padding: 5px 14px; border-radius: 6px; font-size: 12px; font-weight: 700; cursor: pointer; transition: all 0.2s; color: var(--text-muted); border: none; background: transparent; font-family: var(--sans); white-space: nowrap; }
  .rw-view-btn.active { background: linear-gradient(135deg, #a855f7, #7c3aed); color: white; }
  .rw-avatar { width: 32px; height: 32px; border-radius: 50%; background: linear-gradient(135deg, #a855f7, #06b6d4); display: flex; align-items: center; justify-content: center; font-size: 12px; font-weight: 700; cursor: pointer; }

  .rw-content { flex: 1; overflow-y: auto; padding: 20px 24px; }
  .rw-content::-webkit-scrollbar { width: 4px; }
  .rw-content::-webkit-scrollbar-track { background: transparent; }
  .rw-content::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.1); border-radius: 2px; }

  .rw-page-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 20px; }
  .rw-page-title { font-size: 22px; font-weight: 800; }
  .rw-page-sub { font-size: 12px; color: var(--text-muted); font-family: var(--mono); margin-top: 3px; }
  .rw-header-actions { display: flex; gap: 8px; }
  .rw-btn { display: flex; align-items: center; gap: 6px; padding: 8px 14px; border-radius: 8px; font-size: 12px; font-weight: 700; cursor: pointer; transition: all 0.2s; border: 1px solid var(--glass-border); font-family: var(--sans); }
  .rw-btn svg { width: 13px; height: 13px; }
  .rw-btn-ghost { background: var(--glass); color: var(--text-muted); }
  .rw-btn-ghost:hover { background: var(--glass-hover); color: var(--text-primary); }
  .rw-btn-primary { background: linear-gradient(135deg, #a855f7, #7c3aed); color: white; border-color: transparent; box-shadow: 0 4px 15px rgba(168,85,247,0.3); }
  .rw-btn-primary:hover { box-shadow: 0 6px 20px rgba(168,85,247,0.45); transform: translateY(-1px); }
  .rw-btn-danger { background: rgba(255,71,87,0.15); color: var(--critical); border-color: rgba(255,71,87,0.3); }
  .rw-btn-danger:hover { background: rgba(255,71,87,0.25); }
  .rw-btn-warning { background: rgba(255,211,42,0.15); color: var(--medium); border-color: rgba(255,211,42,0.3); }
  .rw-btn-warning:hover { background: rgba(255,211,42,0.25); }
  .rw-btn-success { background: rgba(46,213,115,0.15); color: var(--safe); border-color: rgba(46,213,115,0.3); }
  .rw-btn-success:hover { background: rgba(46,213,115,0.25); }

  .rw-metrics-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 20px; }
  .rw-metric-card { background: var(--glass); border: 1px solid var(--glass-border); border-radius: 12px; padding: 16px; position: relative; overflow: hidden; cursor: pointer; transition: all 0.25s; backdrop-filter: blur(10px); }
  .rw-metric-card:hover { background: var(--glass-hover); transform: translateY(-2px); border-color: rgba(255,255,255,0.14); }
  .rw-metric-card::before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 2px; }
  .rw-metric-card.crit::before { background: linear-gradient(90deg, var(--critical), transparent); }
  .rw-metric-card.high::before { background: linear-gradient(90deg, var(--high), transparent); }
  .rw-metric-card.safe::before { background: linear-gradient(90deg, var(--safe), transparent); }
  .rw-metric-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 10px; }
  .rw-metric-icon { width: 32px; height: 32px; border-radius: 8px; display: flex; align-items: center; justify-content: center; }
  .rw-metric-icon svg { width: 15px; height: 15px; }
  .rw-metric-icon.crit { background: rgba(255,71,87,0.15); color: var(--critical); }
  .rw-metric-icon.high { background: rgba(255,107,53,0.15); color: var(--high); }
  .rw-metric-icon.info { background: rgba(6,182,212,0.15); color: var(--accent2); }
  .rw-metric-value { font-size: 30px; font-weight: 800; line-height: 1; margin-bottom: 4px; font-family: var(--mono); }
  .rw-metric-label { font-size: 11px; color: var(--text-muted); font-weight: 600; letter-spacing: 0.03em; }

  .rw-panel { background: var(--glass); border: 1px solid var(--glass-border); border-radius: 12px; margin-bottom: 16px; backdrop-filter: blur(10px); overflow: hidden; }
  .rw-panel-header { display: flex; align-items: center; justify-content: space-between; padding: 14px 18px; border-bottom: 1px solid var(--glass-border); }
  .rw-panel-title-row { display: flex; align-items: center; gap: 10px; }
  .rw-panel-icon { width: 28px; height: 28px; border-radius: 7px; display: flex; align-items: center; justify-content: center; }
  .rw-panel-icon svg { width: 14px; height: 14px; }
  .rw-panel-icon.purple { background: rgba(168,85,247,0.15); color: var(--accent); }
  .rw-panel-icon.cyan { background: rgba(6,182,212,0.15); color: var(--accent2); }
  .rw-panel-icon.red { background: rgba(255,71,87,0.15); color: var(--critical); }
  .rw-panel-icon.green { background: rgba(46,213,115,0.15); color: var(--safe); }
  .rw-panel-title { font-size: 13px; font-weight: 700; }
  .rw-panel-sub { font-size: 11px; color: var(--text-muted); font-family: var(--mono); }

  .rw-scan-controls { padding: 16px 18px; display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }
  .rw-path-input { flex: 1; min-width: 200px; padding: 9px 14px; border-radius: 8px; background: rgba(0,0,0,0.3); border: 1px solid var(--glass-border); color: var(--text-primary); font-family: var(--mono); font-size: 12px; outline: none; }
  .rw-path-input:focus { border-color: rgba(168,85,247,0.5); background: rgba(168,85,247,0.05); }

  .rw-scan-progress { padding: 0 18px 16px; }
  .rw-progress-info { display: flex; justify-content: space-between; margin-bottom: 6px; }
  .rw-progress-label { font-size: 11px; color: var(--text-muted); font-family: var(--mono); }
  .rw-progress-track { height: 4px; background: rgba(255,255,255,0.06); border-radius: 2px; overflow: hidden; }
  .rw-progress-fill { height: 100%; border-radius: 2px; transition: width 0.5s ease; background: linear-gradient(90deg, #a855f7, #06b6d4, #a855f7); background-size: 200% 100%; animation: rw-shimmer 2s infinite; }
  @keyframes rw-shimmer { 0% { background-position: -200% 0; } 100% { background-position: 200% 0; } }

  .rw-panel-body { padding: 0; }
  .rw-table-wrap { overflow-x: auto; }
  .rw-data-table { width: 100%; border-collapse: collapse; font-size: 12px; }
  .rw-data-table thead tr { border-bottom: 1px solid var(--glass-border); }
  .rw-data-table th { padding: 10px 14px; text-align: left; font-size: 10px; font-weight: 700; color: var(--text-dim); font-family: var(--mono); letter-spacing: 0.1em; white-space: nowrap; }
  .rw-data-table th:first-child { padding-left: 18px; }
  .rw-data-table tbody tr { border-bottom: 1px solid rgba(255,255,255,0.03); transition: background 0.15s; cursor: pointer; }
  .rw-data-table tbody tr:hover { background: rgba(255,255,255,0.03); }
  .rw-data-table td { padding: 10px 14px; vertical-align: middle; color: var(--text-muted); }
  .rw-data-table td:first-child { padding-left: 18px; }

  .rw-cell-file { display: flex; align-items: center; gap: 8px; }
  .rw-file-icon { width: 28px; height: 28px; border-radius: 6px; display: flex; align-items: center; justify-content: center; flex-shrink: 0; }
  .rw-file-icon svg { width: 13px; height: 13px; }
  .rw-file-name { font-family: var(--mono); font-size: 12px; color: var(--text-primary); font-weight: 500; }
  .rw-file-path { font-family: var(--mono); font-size: 10px; color: var(--text-dim); margin-top: 1px; max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

  .rw-risk-badge { display: inline-flex; align-items: center; gap: 4px; padding: 3px 9px; border-radius: 10px; font-size: 10px; font-weight: 700; font-family: var(--mono); letter-spacing: 0.05em; white-space: nowrap; }
  .rw-risk-critical { background: rgba(255,71,87,0.15); color: var(--critical); border: 1px solid rgba(255,71,87,0.2); }
  .rw-risk-high { background: rgba(255,107,53,0.15); color: var(--high); border: 1px solid rgba(255,107,53,0.2); }
  .rw-risk-low { background: rgba(46,213,115,0.1); color: var(--safe); border: 1px solid rgba(46,213,115,0.15); }
  .rw-risk-quarantined { background: rgba(168,85,247,0.12); color: var(--accent); border: 1px solid rgba(168,85,247,0.25); }

  .rw-risk-dot { width: 6px; height: 6px; border-radius: 50%; }
  .rw-dot-critical { background: var(--critical); }
  .rw-dot-high { background: var(--high); }
  .rw-dot-low { background: var(--safe); }
  .rw-dot-quarantined { background: var(--accent); animation: rw-pulse-dot 2s infinite; }

  .rw-score-bar-wrap { width: 80px; }
  .rw-score-track { height: 4px; background: rgba(255,255,255,0.06); border-radius: 2px; overflow: hidden; }
  .rw-score-fill { height: 100%; border-radius: 2px; }
  .rw-score-val { font-family: var(--mono); font-size: 11px; font-weight: 600; margin-top: 3px; }

  .rw-action-row { display: flex; gap: 4px; }
  .rw-act-btn { width: 26px; height: 26px; border-radius: 6px; background: var(--glass); border: 1px solid var(--glass-border); display: flex; align-items: center; justify-content: center; cursor: pointer; transition: all 0.15s; color: var(--text-dim); }
  .rw-act-btn:hover { background: var(--glass-hover); color: var(--text-primary); }
  .rw-act-btn.danger:hover { background: rgba(255,71,87,0.15); color: var(--critical); border-color: rgba(255,71,87,0.3); }
  .rw-act-btn.success:hover { background: rgba(46,213,115,0.15); color: var(--safe); border-color: rgba(46,213,115,0.3); }
  .rw-act-btn.warning:hover { background: rgba(255,211,42,0.15); color: var(--medium); border-color: rgba(255,211,42,0.3); }
  .rw-act-btn svg { width: 12px; height: 12px; }

  .rw-threat-name { font-family: var(--mono); font-size: 11px; color: #a78bfa; }
  .rw-timestamp { font-family: var(--mono); font-size: 10px; color: var(--text-dim); }

  .rw-footer-stats { padding: 10px 18px; border-top: 1px solid var(--glass-border); display: flex; gap: 20px; align-items: center; }
  .rw-footer-stat { display: flex; align-items: center; gap: 6px; font-size: 11px; font-family: var(--mono); color: var(--text-dim); }
  .rw-footer-stat strong { color: var(--text-muted); }

  .rw-filter-bar { display: flex; gap: 6px; padding: 0 18px 14px; flex-wrap: wrap; }
  .rw-filter-chip { padding: 4px 10px; border-radius: 20px; font-size: 11px; font-weight: 700; cursor: pointer; transition: all 0.15s; border: 1px solid var(--glass-border); background: var(--glass); color: var(--text-muted); font-family: var(--mono); }
  .rw-filter-chip:hover { background: var(--glass-hover); color: var(--text-primary); }
  .rw-filter-chip.active-all { background: rgba(168,85,247,0.15); color: var(--accent); border-color: rgba(168,85,247,0.3); }
  .rw-filter-chip.active-crit { background: rgba(255,71,87,0.15); color: var(--critical); border-color: rgba(255,71,87,0.3); }
  .rw-filter-chip.active-high { background: rgba(255,107,53,0.15); color: var(--high); border-color: rgba(255,107,53,0.3); }

  .rw-toast-container { position: fixed; bottom: 24px; right: 24px; z-index: 9999; display: flex; flex-direction: column; gap: 8px; }
  .rw-toast { background: rgba(20,24,35,0.95); border: 1px solid rgba(168,85,247,0.4); border-radius: 10px; padding: 12px 16px; backdrop-filter: blur(20px); min-width: 240px; display: flex; align-items: center; gap: 10px; font-size: 12px; box-shadow: 0 8px 30px rgba(0,0,0,0.5); animation: rw-slide-in 0.3s ease; color: var(--text-primary); }
  @keyframes rw-slide-in { from { transform: translateX(20px); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
  .rw-toast-icon { width: 20px; height: 20px; flex-shrink: 0; display: flex; align-items: center; justify-content: center; }
  .rw-toast-close { margin-left: auto; cursor: pointer; color: var(--text-dim); font-size: 16px; line-height: 1; }

  .rw-empty-state { padding: 48px; text-align: center; color: var(--text-dim); }
  .rw-empty-icon { font-size: 40px; margin-bottom: 12px; opacity: 0.3; }
  .rw-empty-label { font-size: 13px; font-family: var(--mono); }

  .rw-live-chip { display: inline-flex; align-items: center; gap: 5px; padding: 3px 10px; border-radius: 20px; background: rgba(46,213,115,0.12); border: 1px solid rgba(46,213,115,0.25); font-size: 10px; font-family: var(--mono); font-weight: 700; color: var(--safe); }
  .rw-live-chip .rw-dot { width: 6px; height: 6px; border-radius: 50%; background: var(--safe); animation: rw-pulse-dot 2s infinite; }

  /* Timeline Graph */
  @keyframes rw-bar-slide { from { height: 0; opacity: 0; } to { height: 100%; opacity: 1; } }
  @keyframes rw-bar-glow { 0%, 100% { box-shadow: 0 0 0 0 currentColor; } 50% { box-shadow: 0 0 8px 2px currentColor; } }
  .rw-timeline-container { padding: 24px 18px; position: relative; }
  
  /* Line Graph */
  .rw-line-graph-container { padding: 24px 18px; position: relative; }
  .rw-line-graph-canvas { width: 100%; height: 100%; display: block; }
  .rw-line-graph-wrapper { position: relative; height: 280px; margin-bottom: 16px; background: linear-gradient(135deg, rgba(168,85,247,0.05), rgba(6,182,212,0.02)); border-radius: 12px; }
  .rw-line-legend { display: flex; gap: 24px; margin-top: 16px; padding: 16px 0; border-top: 1px solid var(--glass-border); font-size: 12px; flex-wrap: wrap; }
  .rw-line-legend-item { display: flex; align-items: center; gap: 8px; color: var(--text-muted); font-weight: 600; }
  .rw-line-legend-dot { width: 10px; height: 10px; border-radius: 50%; }
  .rw-line-legend-item:hover { color: var(--text-primary); }
  .rw-timeline-bg { position: absolute; inset: 0; background: linear-gradient(135deg, rgba(168,85,247,0.05), rgba(6,182,212,0.02)); border-radius: 12px; }
  .rw-timeline-wrapper { display: flex; align-items: flex-end; gap: 6px; height: 160px; position: relative; z-index: 1; }
  .rw-timeline-bar { flex: 1; display: flex; flex-direction: column; align-items: center; justify-content: flex-end; position: relative; min-height: 50px; }
  .rw-timeline-bar-container { width: 100%; display: flex; align-items: flex-end; justify-content: center; height: 100%; position: relative; }
  .rw-timeline-bar-segment { width: 90%; border-radius: 6px 6px 0 0; transition: all 0.4s cubic-bezier(0.34, 1.56, 0.64, 1); position: relative; filter: drop-shadow(0 4px 8px rgba(0,0,0,0.3)); animation: rw-bar-slide 0.6s ease-out; }
  .rw-timeline-bar-segment:hover { transform: scaleY(1.1) translateY(-4px); filter: drop-shadow(0 8px 16px rgba(0,0,0,0.5)) brightness(1.2); z-index: 10; }
  .rw-timeline-bar-segment::after { content: ''; position: absolute; inset: 0; background: linear-gradient(180deg, rgba(255,255,255,0.4), transparent); border-radius: 6px 6px 0 0; opacity: 0; transition: opacity 0.3s; }
  .rw-timeline-bar-segment:hover::after { opacity: 1; }
  .rw-timeline-label { font-size: 10px; font-family: var(--mono); color: var(--text-muted); margin-top: 12px; white-space: nowrap; font-weight: 600; letter-spacing: 0.05em; }
  .rw-timeline-tooltip { position: absolute; bottom: 120%; left: 50%; transform: translateX(-50%) scale(0.9); background: linear-gradient(135deg, rgba(20,24,35,0.98), rgba(30,35,50,0.95)); border: 1px solid rgba(168,85,247,0.3); border-radius: 10px; padding: 10px 14px; font-size: 11px; font-family: var(--mono); color: var(--text-primary); white-space: nowrap; margin-bottom: 12px; opacity: 0; pointer-events: none; transition: all 0.3s cubic-bezier(0.34, 1.56, 0.64, 1); z-index: 20; box-shadow: 0 8px 24px rgba(0,0,0,0.4); font-weight: 700; }
  .rw-timeline-bar-segment:hover .rw-timeline-tooltip { opacity: 1; transform: translateX(-50%) scale(1); }
  .rw-timeline-legend { display: flex; gap: 24px; margin-top: 20px; padding-top: 16px; border-top: 1px solid var(--glass-border); font-size: 12px; flex-wrap: wrap; }
  .rw-timeline-legend-item { display: flex; align-items: center; gap: 8px; color: var(--text-muted); font-weight: 600; }
  .rw-timeline-legend-dot { width: 10px; height: 10px; border-radius: 3px; transition: all 0.3s; box-shadow: 0 0 0 0 currentColor; }
  .rw-timeline-legend-item:hover .rw-timeline-legend-dot { box-shadow: 0 0 12px 2px currentColor; }

  /* Modal */
  .rw-modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.7); backdrop-filter: blur(8px); z-index: 9998; display: flex; align-items: center; justify-content: center; }
  .rw-modal { background: rgba(20,24,35,0.98); border: 1px solid var(--glass-border); border-radius: 16px; width: 90%; max-width: 600px; max-height: 80vh; overflow: hidden; display: flex; flex-direction: column; box-shadow: 0 20px 60px rgba(0,0,0,0.5); }
  .rw-modal-header { display: flex; align-items: center; justify-content: space-between; padding: 16px 20px; border-bottom: 1px solid var(--glass-border); }
  .rw-modal-title { font-size: 16px; font-weight: 700; }
  .rw-modal-close { width: 32px; height: 32px; border-radius: 8px; background: var(--glass); border: 1px solid var(--glass-border); display: flex; align-items: center; justify-content: center; cursor: pointer; color: var(--text-muted); }
  .rw-modal-close:hover { background: var(--glass-hover); color: var(--text-primary); }
  .rw-modal-body { flex: 1; overflow-y: auto; padding: 20px; }
  .rw-modal-footer { display: flex; gap: 8px; padding: 16px 20px; border-top: 1px solid var(--glass-border); justify-content: flex-end; }
  .rw-detail-row { display: flex; padding: 10px 0; border-bottom: 1px solid rgba(255,255,255,0.05); }
  .rw-detail-label { width: 120px; font-size: 11px; font-family: var(--mono); color: var(--text-dim); text-transform: uppercase; flex-shrink: 0; }
  .rw-detail-value { flex: 1; font-size: 12px; font-family: var(--mono); color: var(--text-primary); word-break: break-all; }
  .rw-finding-item { padding: 8px 12px; background: rgba(0,0,0,0.3); border-radius: 8px; margin-bottom: 8px; border-left: 3px solid var(--accent); }
  .rw-finding-desc { font-size: 12px; color: var(--text-primary); }
  .rw-finding-code { font-size: 10px; color: var(--text-dim); font-family: var(--mono); background: rgba(0,0,0,0.3); padding: 4px 8px; border-radius: 4px; margin-top: 4px; overflow-x: auto; }

  /* Export Menu */
  .rw-export-menu { position: relative; }
  .rw-export-dropdown { position: absolute; top: 100%; right: 0; margin-top: 4px; background: rgba(20,24,35,0.98); border: 1px solid var(--glass-border); border-radius: 10px; overflow: hidden; min-width: 150px; z-index: 100; box-shadow: 0 8px 30px rgba(0,0,0,0.5); }
  .rw-export-option { padding: 10px 14px; font-size: 12px; cursor: pointer; display: flex; align-items: center; gap: 8px; color: var(--text-muted); }
  .rw-export-option:hover { background: var(--glass-hover); color: var(--text-primary); }
`;

const ICONS: Record<string, React.ReactNode> = {
  shield: <svg viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>,
  grid: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="3" width="7" height="7" /><rect x="14" y="3" width="7" height="7" /><rect x="14" y="14" width="7" height="7" /><rect x="3" y="14" width="7" height="7" /></svg>,
  terminal: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="16 18 22 12 16 6" /><polyline points="8 6 2 12 8 18" /></svg>,
  archive: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16Z" /></svg>,
  alert: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" /><line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" /></svg>,
  chart: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="20" x2="18" y2="10" /><line x1="12" y1="20" x2="12" y2="4" /><line x1="6" y1="20" x2="6" y2="14" /></svg>,
  settings: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="3" /><path d="M19.07 4.93a10 10 0 0 1 0 14.14M4.93 4.93a10 10 0 0 0 0 14.14" /></svg>,
  search: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="11" cy="11" r="8" /><line x1="21" y1="21" x2="16.65" y2="16.65" /></svg>,
  download: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" /><polyline points="7 10 12 15 17 10" /><line x1="12" y1="15" x2="12" y2="3" /></svg>,
  refresh: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="23 4 23 10 17 10" /><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10" /></svg>,
  play: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><polygon points="5 3 19 12 5 21 5 3" /></svg>,
  stop: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="6" y="4" width="4" height="16" /><rect x="14" y="4" width="4" height="16" /></svg>,
  eye: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" /><circle cx="12" cy="12" r="3" /></svg>,
  quarantine: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16Z" /></svg>,
  trash: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="3 6 5 6 21 6" /><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6" /><path d="M10 11v6" /><path d="M14 11v6" /></svg>,
  file: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z" /><polyline points="13 2 13 9 20 9" /></svg>,
  zap: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" /></svg>,
  x: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" /></svg>,
  json: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><polyline points="14 2 14 8 20 8" /><line x1="16" y1="13" x2="8" y2="13" /><line x1="16" y1="17" x2="8" y2="17" /></svg>,
  csv: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><polyline points="14 2 14 8 20 8" /><line x1="8" y1="13" x2="16" y2="13" /><line x1="8" y1="17" x2="16" y2="17" /></svg>,
  activity: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12" /></svg>,
};

interface Toast { id: number; message: string; type: 'success' | 'info' | 'warning' | 'error'; }
interface ScannedFile { id: number; filename: string; full_path: string; threat_name?: string; risk_level: string; risk_score: number; timestamp?: string; findings?: Array<{ description: string; code?: string; severity?: number; line?: number }>; analysis_type?: string; entropy?: number; blocked?: boolean; quarantined?: boolean; ml_prediction?: string; ml_confidence?: number; }
interface ViewModalData { type: 'scan' | 'quarantine'; file: ScannedFile | any; }

export default function Dashboard() {
  const [data, setData] = useState<ScanResult>({ timestamp: null, files: [] });
  const [quarantinedFiles, setQuarantinedFiles] = useState<QuarantinedFile[]>([]);
  const [viewMode, setViewMode] = useState<ViewMode>("scans");
  const [loading, setLoading] = useState(true);
  const [quarantineLoading, setQuarantineLoading] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [riskFilter, setRiskFilter] = useState<RiskLevel>("ALL");
  const [scanPath, setScanPath] = useState("C:\\Users\\Public\\Documents");
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [currentNav, setCurrentNav] = useState("dashboard");
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [syncTime, setSyncTime] = useState("--:--:--");
  const [quarantineCount, setQuarantineCount] = useState(0);
  const [displayFiles, setDisplayFiles] = useState<ScannedFile[]>([]);
  const [threatIntel, setThreatIntel] = useState<any>(null);
  const [reports, setReports] = useState<any>(null);
  const [showExportMenu, setShowExportMenu] = useState(false);
  const [viewModal, setViewModal] = useState<ViewModalData | null>(null);
  const [timelineDuration, setTimelineDuration] = useState<"1m" | "5m">("1m");
  const styleRef = useRef<HTMLStyleElement | null>(null);
  const lineGraphCanvasRef = useRef<HTMLCanvasElement | null>(null);
  const [detectionHistory, setDetectionHistory] = useState<Array<ScannedFile & { detectedAt: number }>>([]); // Persistent threat history

  useEffect(() => {
    const style = document.createElement("style");
    style.textContent = CSS;
    document.head.appendChild(style);
    styleRef.current = style;
    return () => { if (styleRef.current) document.head.removeChild(styleRef.current); };
  }, []);

  const fetchData = async () => {
    try {
      const res = await fetchResults();
      setData(res);
      const mappedFiles: ScannedFile[] = res.files.map((f: any, idx: number) => ({
        id: idx + 1,
        filename: f.filename || f.name || "Unknown",
        full_path: f.full_path || f.path || "/",
        threat_name: f.threat_name || f.findings?.[0]?.description || (f.risk_level && f.risk_level !== "CLEARED" && f.risk_level !== "LOW" ? "Suspicious File" : "Clean File"),
        risk_level: f.risk_level || "LOW",
        risk_score: f.risk_score || 0,
        timestamp: f.timestamp || new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
        findings: f.findings || [],
        analysis_type: f.analysis_type,
        entropy: f.entropy,
        blocked: f.blocked || f.quarantined,
        quarantined: f.quarantined,
        ml_prediction: f.ml_prediction,
        ml_confidence: f.ml_confidence,
      }));

      // Add critical and high risk files to detection history with timestamp
      const threatFiles = mappedFiles.filter(f => ["CRITICAL", "HIGH"].includes(f.risk_level));
      const now = Date.now();

      // Add new threats to history
      setDetectionHistory(prev => {
        // Keep existing history items younger than 10 minutes (600000 ms)
        const recentHistory = prev.filter(item => now - item.detectedAt < 600000);

        // Add new threats that aren't already in history
        const existingPaths = new Set(recentHistory.map(h => h.full_path));
        const newThreats = threatFiles
          .filter(f => !existingPaths.has(f.full_path))
          .map(f => ({ ...f, detectedAt: now }));

        return [...recentHistory, ...newThreats];
      });

      setDisplayFiles(mappedFiles);
      setLoading(false);
      updateTime();
    } catch { setLoading(false); }
  };

  const loadQuarantinedFiles = async () => {
    setQuarantineLoading(true);
    try {
      const files = await fetchQuarantinedFiles();
      setQuarantinedFiles(files);
      setQuarantineCount(files.length);
    } catch { showToast("Failed to load quarantined files", "error"); }
    finally { setQuarantineLoading(false); }
  };

  const loadThreatIntel = async () => { try { setThreatIntel(await getThreatIntel()); } catch { } };
  const loadReports = async () => { try { setReports(await getReports()); } catch { } };

  useEffect(() => { fetchData(); const interval = setInterval(fetchData, 2000); return () => clearInterval(interval); }, []);
  useEffect(() => {
    if (viewMode === "quarantine") loadQuarantinedFiles();
    if (viewMode === "threats") loadThreatIntel();
    if (viewMode === "reports") loadReports();
  }, [viewMode]);

  const updateTime = () => setSyncTime(new Date().toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit" }));
  useEffect(() => { const interval = setInterval(updateTime, 1000); return () => clearInterval(interval); }, []);

  const showToast = (message: string, type: Toast["type"] = "info") => {
    const id = Date.now();
    setToasts(prev => [...prev, { id, message, type }]);
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 3500);
  };

  const handleRunScan = async () => {
    setIsScanning(true); setScanProgress(0); showToast(`Scan initiated on ${scanPath}`, "success");
    try {
      await scanFolder(scanPath);
      let progress = 0;
      const interval = setInterval(() => {
        progress = Math.min(100, progress + Math.random() * 15);
        setScanProgress(Math.round(progress));
        if (progress >= 100) { clearInterval(interval); setIsScanning(false); showToast("Scan complete", "success"); fetchData(); }
      }, 200);
    } catch { setIsScanning(false); showToast("Scan failed", "error"); }
  };

  const filteredFiles = useMemo(() => {
    let files: ScannedFile[] = viewMode === "scans" ? displayFiles : quarantinedFiles.map((f, idx) => ({
      id: idx + 1, filename: f.filename || "Unknown", full_path: f.original_path || f.quarantine_path || "/",
      threat_name: f.threat_name || "Quarantined File", risk_level: "QUARANTINED", risk_score: 100, timestamp: f.quarantine_date || "",
    }));

    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      files = files.filter(f => f.filename?.toLowerCase().includes(query) || f.full_path?.toLowerCase().includes(query) || f.threat_name?.toLowerCase().includes(query));
    }
    if (riskFilter !== "ALL") files = files.filter(f => f.risk_level === riskFilter);
    return files;
  }, [displayFiles, quarantinedFiles, searchQuery, riskFilter, viewMode]);

  const criticalCount = displayFiles.filter(f => f.risk_level === "CRITICAL").length;
  const highCount = displayFiles.filter(f => f.risk_level === "HIGH").length;
  const mediumCount = displayFiles.filter(f => f.risk_level === "MEDIUM").length;
  const totalScanned = displayFiles.length;

  const getTimelineData = () => {
    // Prioritize detection history for threat timeline
    const threatSource = detectionHistory.length > 0 ? detectionHistory : displayFiles.filter(f => ["CRITICAL", "HIGH"].includes(f.risk_level));

    if (threatSource.length === 0) {
      // Return empty buckets if no threats
      const timeline: Record<string, { total: number; critical: number; high: number; medium: number; low: number; cleared: number }> = {};
      const now = new Date();

      // Create 5 empty buckets
      for (let i = 4; i >= 0; i--) {
        const time = new Date(now.getTime() - i * 60 * 1000);
        const min = time.getMinutes().toString().padStart(2, '0');
        timeline[`${min}m`] = { total: 0, critical: 0, high: 0, medium: 0, low: 0, cleared: 0 };
      }
      return Object.entries(timeline).map(([time, data]) => ({ time, ...data }));
    }

    const timeline: Record<string, { total: number; critical: number; high: number; medium: number; low: number; cleared: number }> = {};
    const now = new Date();

    let buckets = 0;
    let bucketsData: string[] = [];

    // Generate bucket keys based on duration
    if (timelineDuration === "1m") {
      buckets = 12;
      for (let i = 11; i >= 0; i--) {
        const time = new Date(now.getTime() - i * 5 * 1000);
        const min = time.getMinutes().toString().padStart(2, '0');
        const sec = (Math.floor(time.getSeconds() / 5) * 5).toString().padStart(2, '0');
        const key = `${min}:${sec}`;
        bucketsData.push(key);
        timeline[key] = { total: 0, critical: 0, high: 0, medium: 0, low: 0, cleared: 0 };
      }
    } else if (timelineDuration === "5m") {
      buckets = 5;
      for (let i = 4; i >= 0; i--) {
        const time = new Date(now.getTime() - i * 60 * 1000);
        const min = time.getMinutes().toString().padStart(2, '0');
        const key = `${min}m`;
        bucketsData.push(key);
        timeline[key] = { total: 0, critical: 0, high: 0, medium: 0, low: 0, cleared: 0 };
      }
    } else if (timelineDuration === "1h") {
      buckets = 12;
      for (let i = 11; i >= 0; i--) {
        const time = new Date(now.getTime() - i * 5 * 60 * 1000);
        const hour = time.getHours().toString().padStart(2, '0');
        const min = (Math.floor(time.getMinutes() / 5) * 5).toString().padStart(2, '0');
        const key = `${hour}:${min}`;
        bucketsData.push(key);
        timeline[key] = { total: 0, critical: 0, high: 0, medium: 0, low: 0, cleared: 0 };
      }
    } else {
      buckets = 12;
      for (let i = 11; i >= 0; i--) {
        const time = new Date(now.getTime() - i * 60 * 60 * 1000);
        const hour = time.getHours().toString().padStart(2, '0');
        const key = `${hour}:00`;
        bucketsData.push(key);
        timeline[key] = { total: 0, critical: 0, high: 0, medium: 0, low: 0, cleared: 0 };
      }
    }

    // For detection history, use the detectedAt timestamps
    const allFiles = detectionHistory.length > 0
      ? detectionHistory.map(f => ({ ...f, timestamp: new Date(f.detectedAt).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' }) }))
      : [
        ...displayFiles,
        ...quarantinedFiles.map((f, idx) => ({
          id: -(idx + 1),
          filename: f.filename || "Unknown",
          full_path: f.original_path || f.quarantine_path || "/",
          threat_name: f.threat_name || "Quarantined",
          risk_level: "CRITICAL",
          risk_score: 100,
          timestamp: f.quarantine_date || new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
        }))
      ];

    allFiles.forEach(file => {
      if (!file.timestamp) return;

      const timeParts = file.timestamp.split(":");
      if (timeParts.length < 2) return;

      const fileHour = parseInt(timeParts[0]);
      const fileMin = parseInt(timeParts[1]);
      const fileSec = parseInt(timeParts[2]) || 0;

      let timeKey = "";

      if (timelineDuration === "1m") {
        const sec = (Math.floor(fileSec / 5) * 5).toString().padStart(2, '0');
        timeKey = `${fileMin.toString().padStart(2, '0')}:${sec}`;
      } else if (timelineDuration === "5m") {
        timeKey = `${fileMin.toString().padStart(2, '0')}m`;
      } else if (timelineDuration === "1h") {
        const fiveMin = (Math.floor(fileMin / 5) * 5).toString().padStart(2, '0');
        timeKey = `${fileHour.toString().padStart(2, '0')}:${fiveMin}`;
      } else {
        timeKey = `${fileHour.toString().padStart(2, '0')}:00`;
      }

      if (timeline[timeKey]) {
        timeline[timeKey].total++;
        if (file.risk_level === "CRITICAL") timeline[timeKey].critical++;
        else if (file.risk_level === "HIGH") timeline[timeKey].high++;
        else if (file.risk_level === "MEDIUM") timeline[timeKey].medium++;
        else if (file.risk_level === "LOW") timeline[timeKey].low++;
        else if (file.risk_level === "CLEARED") timeline[timeKey].cleared++;
        // Add normal = low + cleared
        timeline[timeKey].normal = (timeline[timeKey].low || 0) + (timeline[timeKey].cleared || 0);
      }
    });

    return bucketsData.map(time => ({
      time,
      total: timeline[time]?.total || 0,
      critical: timeline[time]?.critical || 0,
      high: timeline[time]?.high || 0,
      medium: timeline[time]?.medium || 0,
      normal: (timeline[time]?.low || 0) + (timeline[time]?.cleared || 0)
    }));
  };

  const drawLineGraph = () => {
    if (!lineGraphCanvasRef.current) return;

    const canvas = lineGraphCanvasRef.current;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const timelineData = getTimelineData();

    // Set canvas size
    const dpr = window.devicePixelRatio || 1;
    canvas.width = canvas.offsetWidth * dpr;
    canvas.height = canvas.offsetHeight * dpr;
    ctx.scale(dpr, dpr);

    const width = canvas.offsetWidth;
    const height = canvas.offsetHeight;
    const padding = 50;
    const graphWidth = width - padding * 2;
    const graphHeight = height - padding * 1.5;

    // Draw background grid
    ctx.strokeStyle = "rgba(255,255,255,0.05)";
    ctx.lineWidth = 1;
    const gridLines = 5;
    for (let i = 0; i <= gridLines; i++) {
      const y = padding + (graphHeight / gridLines) * i;
      ctx.beginPath();
      ctx.moveTo(padding, y);
      ctx.lineTo(width - padding, y);
      ctx.stroke();
    }

    // Find max value for scaling
    const maxCount = Math.max(...timelineData.map(d => d.total), 1);

    // Helper function to draw line
    const drawLine = (dataKey: keyof Omit<typeof timelineData[0], 'time' | 'total'>, color: string, lineWidth: number = 2) => {
      if (timelineData.every(d => d[dataKey] === 0)) return;

      ctx.strokeStyle = color;
      ctx.lineWidth = lineWidth;
      ctx.lineCap = "round";
      ctx.lineJoin = "round";

      ctx.beginPath();
      timelineData.forEach((data, idx) => {
        const x = padding + (graphWidth / (timelineData.length - 1 || 1)) * idx;
        const y = height - padding * 0.5 - (graphHeight * (data[dataKey] as number)) / maxCount;

        if (idx === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      });
      ctx.stroke();
    };

    // Helper function to draw area under line
    const drawArea = (dataKey: keyof Omit<typeof timelineData[0], 'time' | 'total'>, color: string, alpha: number = 0.1) => {
      if (timelineData.every(d => d[dataKey] === 0)) return;

      ctx.fillStyle = color.replace("rgb", "rgba").replace(")", `, ${alpha})`);
      ctx.beginPath();

      timelineData.forEach((data, idx) => {
        const x = padding + (graphWidth / (timelineData.length - 1 || 1)) * idx;
        const y = height - padding * 0.5 - (graphHeight * (data[dataKey] as number)) / maxCount;

        if (idx === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      });

      ctx.lineTo(width - padding, height - padding * 0.5);
      ctx.lineTo(padding, height - padding * 0.5);
      ctx.closePath();
      ctx.fill();
    };

// Draw areas first (background)
    drawArea("normal", "rgb(46,213,115)", 0.08);
    drawArea("medium", "rgb(255,211,42)", 0.06);
    drawArea("high", "rgb(255,107,53)", 0.06);
    drawArea("critical", "rgb(255,71,87)", 0.08);

// Draw lines
    drawLine("critical", "rgb(255,71,87)", 2.5);
    drawLine("high", "rgb(255,107,53)", 2.5);
    drawLine("medium", "rgb(255,211,42)", 2.5);
    drawLine("normal", "rgb(46,213,115)", 2.5);

    // Draw axes
    ctx.strokeStyle = "rgba(255,255,255,0.15)";
    ctx.lineWidth = 2;
    ctx.beginPath();
    ctx.moveTo(padding, padding);
    ctx.lineTo(padding, height - padding * 0.5);
    ctx.lineTo(width - padding, height - padding * 0.5);
    ctx.stroke();

    // Draw Y-axis labels
    ctx.fillStyle = "rgba(240,240,245,0.45)";
    ctx.font = '11px JetBrains Mono';
    ctx.textAlign = "right";
    for (let i = 0; i <= gridLines; i++) {
      const value = Math.round((maxCount / gridLines) * i);
      const y = padding + (graphHeight / gridLines) * (gridLines - i);
      ctx.fillText(value.toString(), padding - 10, y + 4);
    }

    // Draw X-axis labels
    ctx.textAlign = "center";
    ctx.fillStyle = "rgba(240,240,245,0.45)";
    timelineData.forEach((data, idx) => {
      if (timelineData.length > 8 && idx % Math.ceil(timelineData.length / 8) !== 0) return;
      const x = padding + (graphWidth / (timelineData.length - 1 || 1)) * idx;
      const y = height - padding * 0.5 + 20;
      ctx.fillText(data.time, x, y);
    });
  };

  useEffect(() => {
    drawLineGraph();
  }, [timelineDuration, detectionHistory, displayFiles, quarantinedFiles]);

  const getRiskColor = (risk: string) => ({ CRITICAL: "#ff4757", HIGH: "#ff6b35", MEDIUM: "#ffd32a", LOW: "#2ed573", QUARANTINED: "#a855f7", CLEARED: "#2ed573" }[risk] || "#888");
  const getScoreGradient = (score: number) => score >= 80 ? "linear-gradient(90deg,#ff4757,#c0392b)" : score >= 60 ? "linear-gradient(90deg,#ff6b35,#e55a2b)" : "linear-gradient(90deg,#2ed573,#27ae60)";

  const handleNav = (nav: string) => {
    setCurrentNav(nav);
    const viewMap: Record<string, ViewMode> = { dashboard: "scans", scans: "scans", quarantine: "quarantine", threats: "threats", reports: "reports" };
    setViewMode(viewMap[nav] || "scans");
    setRiskFilter("ALL"); // Reset filter when changing views
  };

  const handleView = (file: ScannedFile) => setViewModal({ type: viewMode === "quarantine" ? "quarantine" : "scan", file });

  const handleQuarantineFile = async (file: ScannedFile) => {
    try { await quarantineFile(file.full_path); showToast(`${file.filename} moved to Quarantine`, "warning"); fetchData(); }
    catch { showToast(`Failed to quarantine ${file.filename}`, "error"); }
  };

  const handleDeleteFile = async (file: ScannedFile) => {
    if (window.confirm(`Permanently delete "${file.filename}"?`)) {
      try { await deleteFromQuarantine(file.filename); showToast(`${file.filename} permanently deleted`, "error"); loadQuarantinedFiles(); }
      catch { showToast(`Failed to delete ${file.filename}`, "error"); }
    }
  };

  const handleRestoreFile = async (file: ScannedFile) => {
    try {
      // Use original_path if available, else prompt for destination
      const originalPath = file.original_path || file.full_path;
      const destination = prompt(`Restore "${file.filename}" to (Enter path or press OK for original):`, originalPath);
      if (destination) {
        await restoreFromQuarantine(file.filename, destination);
        showToast(`${file.filename} restored to ${destination}`, "success"); 
        loadQuarantinedFiles();
      }
    }
    catch (error) { 
      console.error("Restore error:", error);
      showToast(`Failed to restore ${file.filename}`, "error"); 
    }
  };

  const handleExportJSON = () => {
    const dataToExport = viewMode === "scans" ? displayFiles : quarantinedFiles;
    const blob = new Blob([JSON.stringify(dataToExport, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a"); a.href = url; a.download = `reconware-${viewMode}-${Date.now()}.json`; a.click();
    URL.revokeObjectURL(url);
    showToast("Exported as JSON", "success");
    setShowExportMenu(false);
  };

  const handleExportCSV = () => {
    const dataToExport = viewMode === "scans" ? displayFiles : quarantinedFiles;
    if (dataToExport.length === 0) { showToast("No data to export", "warning"); setShowExportMenu(false); return; }
    const headers = ["Filename", "Path", "Threat", "Risk Level", "Score", "Timestamp"];
    const rows = dataToExport.map((f: any) => [f.filename, f.full_path, f.threat_name, f.risk_level, f.risk_score, f.timestamp || ""]);
    const csv = [headers.join(","), ...rows.map(r => r.map((v: any) => `"${v || ""}"`).join(","))].join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a"); a.href = url; a.download = `reconware-${viewMode}-${Date.now()}.csv`; a.click();
    URL.revokeObjectURL(url);
    showToast("Exported as CSV", "success");
    setShowExportMenu(false);
  };

  const toastColors: Record<string, string> = { success: '#2ed573', info: '#06b6d4', warning: '#ffd32a', error: '#ff4757' };

  const renderModal = () => {
    if (!viewModal) return null;
    const { type, file } = viewModal;
    return (
      <div className="rw-modal-overlay" onClick={() => setViewModal(null)}>
        <div className="rw-modal" onClick={e => e.stopPropagation()}>
          <div className="rw-modal-header">
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <div className={`rw-panel-icon ${type === "quarantine" ? "red" : "cyan"}`}>{ICONS.eye}</div>
              <span className="rw-modal-title">File Details</span>
            </div>
            <button className="rw-modal-close" onClick={() => setViewModal(null)}>{ICONS.x}</button>
          </div>
          <div className="rw-modal-body">
            <div className="rw-detail-row"><span className="rw-detail-label">Filename</span><span className="rw-detail-value">{file.filename}</span></div>
            <div className="rw-detail-row"><span className="rw-detail-label">Path</span><span className="rw-detail-value">{file.full_path}</span></div>
            <div className="rw-detail-row"><span className="rw-detail-label">Threat</span><span className="rw-detail-value" style={{ color: "#a78bfa" }}>{file.threat_name}</span></div>
            <div className="rw-detail-row"><span className="rw-detail-label">Risk Level</span><span className="rw-detail-value"><span className={`rw-risk-badge rw-risk-${file.risk_level.toLowerCase()}`}>{file.risk_level}</span></span></div>
            <div className="rw-detail-row"><span className="rw-detail-label">Risk Score</span><span className="rw-detail-value">{file.risk_score}/100</span></div>
            {file.entropy && <div className="rw-detail-row"><span className="rw-detail-label">Entropy</span><span className="rw-detail-value">{file.entropy}</span></div>}
            {file.ml_prediction && <div className="rw-detail-row"><span className="rw-detail-label">ML Prediction</span><span className="rw-detail-value">{file.ml_prediction} ({file.ml_confidence}%)</span></div>}
            {file.analysis_type && <div className="rw-detail-row"><span className="rw-detail-label">Analysis Type</span><span className="rw-detail-value">{file.analysis_type}</span></div>}
            <div className="rw-detail-row"><span className="rw-detail-label">Blocked</span><span className="rw-detail-value">{file.blocked ? "Yes" : "No"}</span></div>
            {file.findings && file.findings.length > 0 && (
              <div style={{ marginTop: 16 }}>
                <div style={{ fontSize: 11, fontFamily: "var(--mono)", color: "var(--text-dim)", marginBottom: 8 }}>FINDINGS ({file.findings.length})</div>
                {file.findings.map((finding: any, idx: number) => (
                  <div key={idx} className="rw-finding-item">
                    <div className="rw-finding-desc">{finding.description}</div>
                    {finding.line && <div style={{ fontSize: 10, color: "var(--text-dim)", fontFamily: "var(--mono)" }}>Line {finding.line}</div>}
                    {finding.severity && <div style={{ fontSize: 10, color: "var(--accent)", fontFamily: "var(--mono)" }}>Severity: {finding.severity}</div>}
                    {finding.code && <div className="rw-finding-code">{finding.code}</div>}
                  </div>
                ))}
              </div>
            )}
          </div>
          <div className="rw-modal-footer">
            <button className="rw-btn rw-btn-ghost" onClick={() => setViewModal(null)}>Close</button>
            {type === "scan" && <button className="rw-btn rw-btn-warning" onClick={() => { handleQuarantineFile(file); setViewModal(null); }}>{ICONS.quarantine} Quarantine</button>}
            {type === "scan" && <button className="rw-btn rw-btn-danger" onClick={() => { setViewModal(null); showToast(`${file.filename} permanently deleted`, "error"); }}>{ICONS.trash} Delete</button>}
            {type === "quarantine" && <button className="rw-btn rw-btn-success" onClick={() => { handleRestoreFile(file); setViewModal(null); }}>{ICONS.refresh} Restore</button>}
            {type === "quarantine" && <button className="rw-btn rw-btn-danger" onClick={() => { handleDeleteFile(file); setViewModal(null); }}>{ICONS.trash} Delete</button>}
          </div>
        </div>
      </div>
    );
  };

  const renderMainContent = () => {
    if (viewMode === "threats") return renderThreatIntel();
    if (viewMode === "reports") return renderReports();
    return renderScanContent();
  };

  const renderDetectedVirusFiles = () => {
    // Show critical and high risk files from both active scans and quarantine
    // This ensures threats remain visible even after quarantine for graph continuity
    const activeThreatFiles = displayFiles
      .filter(f => ["CRITICAL", "HIGH"].includes(f.risk_level))
      .map(f => ({ ...f, status: "active" }));

    // Include quarantined files that were critical or high risk
    const quarantinedThreatFiles = quarantinedFiles
      .filter(f => ["CRITICAL", "HIGH"].includes(f.threat_name?.includes("Ransom") || f.threat_name ? "CRITICAL" : "HIGH"))
      .map((f, idx) => ({
        id: -(idx + 1), // Use negative IDs to distinguish from active files
        filename: f.filename || "Unknown",
        full_path: f.original_path || f.quarantine_path || "/",
        threat_name: f.threat_name || "Quarantined Threat",
        risk_level: "CRITICAL" as const,
        risk_score: 100,
        timestamp: f.quarantine_date || "",
        status: "quarantined"
      }));

    // Combine and sort by timestamp (most recent first), limit to 10
    const allThreatFiles = [...activeThreatFiles, ...quarantinedThreatFiles]
      .sort((a, b) => {
        const aTime = a.timestamp ? new Date(`1970/01/01 ${a.timestamp}`).getTime() : 0;
        const bTime = b.timestamp ? new Date(`1970/01/01 ${b.timestamp}`).getTime() : 0;
        return bTime - aTime;
      })
      .slice(0, 10);

    
  };

  const renderTimelineLineGraph = () => {
    const cleanCount = displayFiles.filter(f => ["LOW", "CLEARED"].includes(f.risk_level)).length;
    const durationLabels = { "1m": "Last Minute", "5m": "Last 5 Minutes", "1h": "Last Hour", "12h": "Last 12 Hours" };

    return (
      <div className="rw-panel" style={{ marginBottom: 16, position: "relative", overflow: "hidden" }}>
        <div className="rw-panel-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 16 }}>
          <div className="rw-panel-title-row">
            <div className="rw-panel-icon cyan">{ICONS.activity}</div>
            <div>
              <div className="rw-panel-title">Detection Trends</div>
              <div className="rw-panel-sub">File detection trends {durationLabels[timelineDuration]} - Real-time tracking</div>
            </div>
          </div>
          <div style={{ display: "flex", gap: 6, flexShrink: 0 }}>
            {(["1m", "5m"] as const).map((dur) => (
              <button
                key={dur}
                onClick={() => setTimelineDuration(dur)}
                style={{
                  padding: "6px 12px",
                  border: "1px solid " + (timelineDuration === dur ? "rgba(168,85,247,0.5)" : "rgba(255,255,255,0.09)"),
                  background: timelineDuration === dur ? "rgba(168,85,247,0.15)" : "rgba(255,255,255,0.04)",
                  color: timelineDuration === dur ? "#a855f7" : "rgba(240,240,245,0.45)",
                  borderRadius: 6,
                  fontSize: 11,
                  fontWeight: 700,
                  cursor: "pointer",
                  backdropFilter: "blur(20px)",
                  transition: "all 0.2s",
                  fontFamily: "var(--mono)"
                }}
              >
                {dur}
              </button>
            ))}
          </div>
        </div>
        <div className="rw-line-graph-container">
          <div className="rw-line-graph-wrapper">
            <canvas ref={lineGraphCanvasRef} className="rw-line-graph-canvas"></canvas>
          </div>
          <div className="rw-line-legend">
            <div className="rw-line-legend-item">
              <div className="rw-line-legend-dot" style={{ background: "rgb(255,71,87)", boxShadow: "0 0 8px rgba(255,71,87,0.5)" }}></div>
              <span>Critical ({criticalCount})</span>
            </div>
            <div className="rw-line-legend-item">
              <div className="rw-line-legend-dot" style={{ background: "rgb(255,107,53)", boxShadow: "0 0 8px rgba(255,107,53,0.5)" }}></div>
              <span>High ({highCount})</span>
            </div>
            <div className="rw-line-legend-item">
              <div className="rw-line-legend-dot" style={{ background: "rgb(255,211,42)", boxShadow: "0 0 8px rgba(255,211,42,0.5)" }}></div>
              <span>Medium ({mediumCount})</span>
            </div>
            <div className="rw-line-legend-item">
              <div className="rw-line-legend-dot" style={{ background: "rgb(46,213,115)", boxShadow: "0 0 8px rgba(46,213,115,0.5)" }}></div>
              <span>Normal ({cleanCount})</span>
            </div>
          </div>
        </div>
      </div>
    );
  };

  const renderTimelineGraph = () => {
    const timelineData = getTimelineData();
    const maxTotal = Math.max(...timelineData.map(d => d.total), 1);
    const cleanCount = displayFiles.filter(f => ["LOW", "CLEARED"].includes(f.risk_level)).length;

    const durationLabels = { "1m": "Last Minute", "5m": "Last 5 Minutes", "1h": "Last Hour", "12h": "Last 12 Hours" };

    return (
      <div className="rw-panel" style={{ marginBottom: 16, position: "relative", overflow: "hidden" }}>
        <div className="rw-panel-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 16 }}>
          <div className="rw-panel-title-row">
            <div className="rw-panel-icon cyan">{ICONS.chart}</div>
            <div>
              <div className="rw-panel-title">Activity Timeline</div>
              <div className="rw-panel-sub">File detection patterns {durationLabels[timelineDuration]} - Real-time updates</div>
            </div>
          </div>
          <div style={{ display: "flex", gap: 6, flexShrink: 0 }}>
            {(["1m", "5m"] as const).map((dur) => (
              <button
                key={dur}
                onClick={() => setTimelineDuration(dur)}
                style={{
                  padding: "6px 12px",
                  border: "1px solid " + (timelineDuration === dur ? "rgba(168,85,247,0.5)" : "rgba(255,255,255,0.09)"),
                  background: timelineDuration === dur ? "rgba(168,85,247,0.15)" : "rgba(255,255,255,0.04)",
                  color: timelineDuration === dur ? "#a855f7" : "rgba(240,240,245,0.45)",
                  borderRadius: 6,
                  fontSize: 11,
                  fontWeight: 700,
                  cursor: "pointer",
                  backdropFilter: "blur(20px)",
                  transition: "all 0.2s",
                  fontFamily: "var(--mono)"
                }}
              >
                {dur}
              </button>
            ))}
          </div>
        </div>
        <div className="rw-timeline-container">
          <div className="rw-timeline-bg"></div>
          <div className="rw-timeline-wrapper">
            {timelineData.map((data, idx) => {
              const totalHeight = Math.max(5, (data.total / maxTotal) * 100);

              // Calculate percentages of total files in this hour
              const critPercent = data.critical > 0 ? (data.critical / data.total) * 100 : 0;
              const highPercent = data.high > 0 ? (data.high / data.total) * 100 : 0;
              const medPercent = data.medium > 0 ? (data.medium / data.total) * 100 : 0;
              const lowPercent = data.low > 0 ? (data.low / data.total) * 100 : 0;
              const clearedPercent = data.cleared > 0 ? (data.cleared / data.total) * 100 : 0;

              return (
                <div key={idx} className="rw-timeline-bar">
                  <div className="rw-timeline-bar-container">
                    {/* Stacked bar with all risk levels - bottom to top: Cleared → Low → Medium → High → Critical */}
                    {data.total > 0 && (
                      <div style={{
                        width: "85%",
                        height: `${totalHeight}%`,
                        display: "flex",
                        flexDirection: "column",
                        justifyContent: "flex-end",
                        position: "relative"
                      }}>
                        {/* Cleared/Clean files - bottom layer (green) */}
                        {clearedPercent > 0 && (
                          <div className="rw-timeline-bar-segment" style={{
                            height: `${clearedPercent}%`,
                            background: "linear-gradient(180deg, #2ed573 0%, #27ae60 100%)"
                          }}>
                            <div className="rw-timeline-tooltip">{data.cleared} Clean</div>
                          </div>
                        )}
                        {/* Low risk files - second layer (green-yellow) */}
                        {lowPercent > 0 && (
                          <div className="rw-timeline-bar-segment" style={{
                            height: `${lowPercent}%`,
                            background: "linear-gradient(180deg, #ffd32a 0%, #27ae60 100%)"
                          }}>
                            <div className="rw-timeline-tooltip">{data.low} Low</div>
                          </div>
                        )}
                        {/* Medium risk files - third layer (yellow) */}
                        {medPercent > 0 && (
                          <div className="rw-timeline-bar-segment" style={{
                            height: `${medPercent}%`,
                            background: "linear-gradient(180deg, #ffd32a 0%, #ffe066 100%)"
                          }}>
                            <div className="rw-timeline-tooltip">{data.medium} Medium</div>
                          </div>
                        )}
                        {/* High risk files - fourth layer (orange) */}
                        {highPercent > 0 && (
                          <div className="rw-timeline-bar-segment" style={{
                            height: `${highPercent}%`,
                            background: "linear-gradient(180deg, #ff6b35 0%, #ff8a50 100%)"
                          }}>
                            <div className="rw-timeline-tooltip">{data.high} High</div>
                          </div>
                        )}
                        {/* Critical files - top layer (red) */}
                        {critPercent > 0 && (
                          <div className="rw-timeline-bar-segment" style={{
                            height: `${critPercent}%`,
                            background: "linear-gradient(180deg, #ff4757 0%, #ff6b6b 100%)"
                          }}>
                            <div className="rw-timeline-tooltip">{data.critical} Critical</div>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                  <div className="rw-timeline-label">{data.time}</div>
                </div>
              );
            })}
          </div>
          <div className="rw-timeline-legend">
            <div className="rw-timeline-legend-item">
              <div className="rw-timeline-legend-dot" style={{ background: "linear-gradient(180deg, #ff4757, #ff6b6b)" }}></div>
              <span>Critical ({criticalCount})</span>
            </div>
            <div className="rw-timeline-legend-item">
              <div className="rw-timeline-legend-dot" style={{ background: "linear-gradient(180deg, #ff6b35, #ff8a50)" }}></div>
              <span>High ({highCount})</span>
            </div>
            <div className="rw-timeline-legend-item">
              <div className="rw-timeline-legend-dot" style={{ background: "linear-gradient(180deg, #ffd32a, #ffe066)" }}></div>
              <span>Medium ({mediumCount})</span>
            </div>
            <div className="rw-timeline-legend-item">
              <div className="rw-timeline-legend-dot" style={{ background: "linear-gradient(180deg, #2ed573, #27ae60)" }}></div>
              <span>Clean ({cleanCount})</span>
            </div>
          </div>
        </div>
      </div>
    );
  };

  const renderScanMetrics = () => (
    <div className="rw-metrics-grid">
      <div className="rw-metric-card crit" onClick={() => setRiskFilter(riskFilter === "CRITICAL" ? "ALL" : "CRITICAL")}>
        <div className="rw-metric-header">
          <div className="rw-metric-icon crit">{ICONS.alert}</div>
        </div>
        <div className="rw-metric-value" style={{ color: "#ff4757" }}>{criticalCount}</div>
        <div className="rw-metric-label">Critical Threats</div>
      </div>
      <div className="rw-metric-card high" onClick={() => setRiskFilter(riskFilter === "HIGH" ? "ALL" : "HIGH")}>
        <div className="rw-metric-header">
          <div className="rw-metric-icon high">{ICONS.zap}</div>
        </div>
        <div className="rw-metric-value" style={{ color: "#ff6b35" }}>{highCount}</div>
        <div className="rw-metric-label">High Risk</div>
      </div>
      <div className="rw-metric-card" onClick={() => setRiskFilter(riskFilter === "MEDIUM" ? "ALL" : "MEDIUM")}>
        <div className="rw-metric-header">
          <div className="rw-metric-icon info">{ICONS.chart}</div>
        </div>
        <div className="rw-metric-value" style={{ color: "#ffd32a" }}>{mediumCount}</div>
        <div className="rw-metric-label">Medium Risk</div>
      </div>
      <div className="rw-metric-card safe">
        <div className="rw-metric-header">
          <div className="rw-metric-icon info">{ICONS.terminal}</div>
        </div>
        <div className="rw-metric-value" style={{ color: "#06b6d4" }}>{totalScanned}</div>
        <div className="rw-metric-label">Files Scanned</div>
      </div>
    </div>
  );

  const renderQuarantineMetrics = () => (
    <div className="rw-metrics-grid">
      <div className="rw-metric-card crit">
        <div className="rw-metric-header">
          <div className="rw-metric-icon crit">{ICONS.archive}</div>
        </div>
        <div className="rw-metric-value" style={{ color: "#ff4757" }}>{quarantineCount}</div>
        <div className="rw-metric-label">Quarantined</div>
      </div>
      <div className="rw-metric-card high">
        <div className="rw-metric-header">
          <div className="rw-metric-icon high">{ICONS.trash}</div>
        </div>
        <div className="rw-metric-value" style={{ color: "#ff6b35" }}>{quarantinedFiles.filter(f => f.threat_name?.includes("Ransom")).length}</div>
        <div className="rw-metric-label">Ransomware</div>
      </div>
      <div className="rw-metric-card">
        <div className="rw-metric-header">
          <div className="rw-metric-icon info">{ICONS.file}</div>
        </div>
        <div className="rw-metric-value" style={{ color: "#06b6d4" }}>{quarantinedFiles.filter(f => f.quarantine_date?.includes(new Date().toLocaleDateString())).length}</div>
        <div className="rw-metric-label">Today</div>
      </div>
      <div className="rw-metric-card safe">
        <div className="rw-metric-header">
          <div className="rw-metric-icon info">{ICONS.refresh}</div>
        </div>
        <div className="rw-metric-value" style={{ color: "#2ed573" }}>{quarantinedFiles.filter(f => f.restored).length}</div>
        <div className="rw-metric-label">Restored</div>
      </div>
    </div>
  );

  const renderThreatIntel = () => (
    <>
      <div className="rw-page-header">
        <div>
          <div className="rw-page-title">Threat Intelligence</div>
          <div className="rw-page-sub">File type analysis from scanned directories</div>
        </div>
      </div>

      {viewMode === "threats" && (
        <div className="rw-metrics-grid">
          <div className="rw-metric-card crit">
            <div className="rw-metric-header">
              <div className="rw-metric-icon crit">{ICONS.alert}</div>
            </div>
            <div className="rw-metric-value" style={{ color: "#ff4757" }}>{threatIntel?.threat_count || 0}</div>
            <div className="rw-metric-label">Total Threats</div>
          </div>
          <div className="rw-metric-card">
            <div className="rw-metric-header">
              <div className="rw-metric-icon info">{ICONS.file}</div>
            </div>
            <div className="rw-metric-value" style={{ color: "#06b6d4" }}>{threatIntel?.total_files || 0}</div>
            <div className="rw-metric-label">Files Scanned</div>
          </div>
          <div className="rw-metric-card safe">
            <div className="rw-metric-header">
              <div className="rw-metric-icon info">{ICONS.chart}</div>
            </div>
            <div className="rw-metric-value" style={{ color: "#2ed573" }}>{threatIntel?.risk_distribution?.CLEARED || 0}</div>
            <div className="rw-metric-label">Clean Files</div>
          </div>
          <div className="rw-metric-card">
            <div className="rw-metric-header">
              <div className="rw-metric-icon info">{ICONS.zap}</div>
            </div>
            <div className="rw-metric-value" style={{ color: "#a855f7" }}>{Object.keys(threatIntel?.file_types || {}).length}</div>
            <div className="rw-metric-label">File Types</div>
          </div>
        </div>
      )}

      {renderTimelineLineGraph()}

      <div className="rw-panel">
        <div className="rw-panel-header">
          <div className="rw-panel-title-row">
            <div className="rw-panel-icon purple">{ICONS.file}</div>
            <div>
              <div className="rw-panel-title">File Types Detected</div>
              <div className="rw-panel-sub">Distribution of scanned file extensions</div>
            </div>
          </div>
        </div>
        <div style={{ padding: 16, display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12 }}>
          {threatIntel?.file_types && Object.entries(threatIntel.file_types).sort((a: any, b: any) => (b[1] as number) - (a[1] as number)).slice(0, 8).map(([type, count]: [string, any]) => (
            <div key={type} style={{ padding: 12, background: "rgba(0,0,0,0.2)", borderRadius: 8, border: "1px solid var(--glass-border)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <span style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--accent)" }}>{type}</span>
              <span style={{ fontFamily: "var(--mono)", fontSize: 14, fontWeight: 700, color: "var(--text-primary)" }}>{count}</span>
            </div>
          ))}
        </div>
      </div>
    </>
  );

  const renderReports = () => (
    <>
      <div className="rw-page-header">
        <div>
          <div className="rw-page-title">Quarantine Reports</div>
          <div className="rw-page-sub">Daily breakdown of quarantined threats</div>
        </div>
        <div className="rw-header-actions">
          <button className="rw-btn rw-btn-ghost" onClick={() => { loadReports(); showToast("Reports refreshed", "info"); }}>{ICONS.refresh} Refresh</button>
        </div>
      </div>

      {viewMode === "reports" && (
        <div className="rw-metrics-grid">
          <div className="rw-metric-card crit">
            <div className="rw-metric-header">
              <div className="rw-metric-icon crit">{ICONS.archive}</div>
            </div>
            <div className="rw-metric-value" style={{ color: "#ff4757" }}>{reports?.total_quarantined || 0}</div>
            <div className="rw-metric-label">Total Quarantined</div>
          </div>
          <div className="rw-metric-card">
            <div className="rw-metric-header">
              <div className="rw-metric-icon info">{ICONS.file}</div>
            </div>
            <div className="rw-metric-value" style={{ color: "#06b6d4" }}>{reports?.daily_reports?.length || 0}</div>
            <div className="rw-metric-label">Active Days</div>
          </div>
          <div className="rw-metric-card high">
            <div className="rw-metric-header">
              <div className="rw-metric-icon high">{ICONS.zap}</div>
            </div>
            <div className="rw-metric-value" style={{ color: "#ff6b35" }}>{(reports?.total_size_bytes / 1024 / 1024).toFixed(1) || 0} MB</div>
            <div className="rw-metric-label">Quarantine Size</div>
          </div>
          <div className="rw-metric-card safe">
            <div className="rw-metric-header">
              <div className="rw-metric-icon info">{ICONS.chart}</div>
            </div>
            <div className="rw-metric-value" style={{ color: "#2ed573" }}>{reports?.summary?.by_type ? Object.keys(reports.summary.by_type).length : 0}</div>
            <div className="rw-metric-label">Threat Types</div>
          </div>
        </div>
      )}

      {renderTimelineLineGraph()}

      <div className="rw-panel">
        <div className="rw-panel-header">
          <div className="rw-panel-title-row">
            <div className="rw-panel-icon cyan">{ICONS.chart}</div>
            <div>
              <div className="rw-panel-title">Daily Quarantine Log</div>
              <div className="rw-panel-sub">Threats detected per day</div>
            </div>
          </div>
        </div>
        <div className="rw-panel-body">
          {reports?.daily_reports?.length > 0 ? (
            <table className="rw-data-table">
              <thead>
                <tr>
                  <th>DATE</th>
                  <th>COUNT</th>
                  <th>FILE TYPES</th>
                  <th>THREATS</th>
                </tr>
              </thead>
              <tbody>
                {reports.daily_reports.map((day: any) => (
                  <tr key={day.date}>
                    <td><span className="rw-timestamp">{day.date}</span></td>
                    <td><span style={{ fontFamily: "var(--mono)", fontSize: 14, fontWeight: 700, color: "#ff4757" }}>{day.count}</span></td>
                    <td>
                      {Object.entries(day.file_types).map(([t, c]: [string, any]) => (
                        <span key={t} style={{ marginRight: 4, padding: "2px 6px", borderRadius: 4, fontSize: 10, fontFamily: "var(--mono)", background: "rgba(168,85,247,0.15)", color: "var(--accent)" }}>
                          {t}: {c}
                        </span>
                      ))}
                    </td>
                    <td><span className="rw-threat-name">{day.threats.slice(0, 3).join(", ")}{day.threats.length > 3 ? "..." : ""}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : <div className="rw-empty-state"><div className="rw-empty-icon">◎</div><div className="rw-empty-label">No quarantine records yet</div></div>}
        </div>
      </div>
    </>
  );

  const renderScanContent = () => (
    <>
      <div className="rw-page-header">
        <div>
          <div className="rw-page-title">{viewMode === "scans" ? "Detection Log" : "Quarantined Files"}</div>
          <div className="rw-page-sub">Monitoring filesystem activity in real-time</div>
        </div>
        <div className="rw-header-actions">
          <button className="rw-btn rw-btn-ghost" onClick={() => { fetchData(); showToast("Refreshing...", "info"); }}>{ICONS.refresh} Refresh</button>
          <div className="rw-export-menu">
            <button className="rw-btn rw-btn-ghost" onClick={() => setShowExportMenu(!showExportMenu)}>{ICONS.download} Export</button>
            {showExportMenu && (
              <div className="rw-export-dropdown">
                <div className="rw-export-option" onClick={handleExportJSON}>{ICONS.json} JSON</div>
                <div className="rw-export-option" onClick={handleExportCSV}>{ICONS.csv} CSV</div>
              </div>
            )}
          </div>
          {viewMode === "scans" && (
            <button className="rw-btn rw-btn-primary" onClick={handleRunScan} disabled={isScanning}>
              {ICONS.play} Run Scan
            </button>
          )}
        </div>
      </div>

      {/* Show metrics only for scans/quarantine views */}
      {(viewMode === "scans" || viewMode === "quarantine") && (
        viewMode === "scans" ? renderScanMetrics() : renderQuarantineMetrics()
      )}

      {/* Detected virus files for scans view */}
      {viewMode === "scans" && renderDetectedVirusFiles()}

      {/* Line graph for scans view */}
      {viewMode === "scans" && renderTimelineLineGraph()}

      {viewMode === "scans" && (
        <div className="rw-panel">
          <div className="rw-panel-header">
            <div className="rw-panel-title-row">
              <div className="rw-panel-icon purple">{ICONS.terminal}</div>
              <div>
                <div className="rw-panel-title">Scan Controls</div>
                <div className="rw-panel-sub">Configure and launch filesystem scans</div>
              </div>
            </div>
            <div className="rw-live-chip">
              <div className="rw-dot"></div>
              {isScanning ? "SCANNING" : "READY"}
            </div>
          </div>
          <div className="rw-scan-controls">
            <input
              className="rw-path-input"
              value={scanPath}
              onChange={e => setScanPath(e.target.value)}
              placeholder="Enter folder path to scan..."
            />
            <button className="rw-btn rw-btn-primary" onClick={handleRunScan} disabled={isScanning}>
              {ICONS.play} Start Scan
            </button>
            <button className="rw-btn rw-btn-ghost" onClick={() => setIsScanning(false)} disabled={!isScanning}>
              {ICONS.stop} Stop
            </button>
          </div>
          {isScanning && (
            <div className="rw-scan-progress">
              <div className="rw-progress-info">
                <span className="rw-progress-label">Scanning: {scanPath}</span>
                <span className="rw-progress-label">{scanProgress}%</span>
              </div>
              <div className="rw-progress-track">
                <div className="rw-progress-fill" style={{ width: `${scanProgress}%` }}></div>
              </div>
            </div>
          )}
        </div>
      )}

      <div className="rw-panel">
        <div className="rw-panel-header">
          <div className="rw-panel-title-row">
            <div className="rw-panel-icon cyan">{ICONS.activity}</div>
            <div>
              <div className="rw-panel-title">{viewMode === "scans" ? "Detection Log" : "Quarantined Files"}</div>
              <div className="rw-panel-sub">
                {filteredFiles.length} files · Updated {syncTime}
              </div>
            </div>
          </div>
          {riskFilter !== "ALL" && (
            <button className="rw-btn rw-btn-ghost" onClick={() => setRiskFilter("ALL")} style={{ padding: "5px 10px", fontSize: 11 }}>
              Clear Filter
            </button>
          )}
        </div>

        <div className="rw-filter-bar">
          <div className={`rw-filter-chip ${riskFilter === "ALL" ? "active-all" : ""}`} onClick={() => setRiskFilter("ALL")}>All</div>
          <div className={`rw-filter-chip ${riskFilter === "CRITICAL" ? "active-crit" : ""}`} onClick={() => setRiskFilter("CRITICAL")}>Critical</div>
          <div className={`rw-filter-chip ${riskFilter === "HIGH" ? "active-high" : ""}`} onClick={() => setRiskFilter("HIGH")}>High</div>
          <div className={`rw-filter-chip ${riskFilter === "MEDIUM" ? "" : ""}`} onClick={() => setRiskFilter("MEDIUM")}>Medium</div>
          <div className={`rw-filter-chip ${riskFilter === "LOW" ? "" : ""}`} onClick={() => setRiskFilter("LOW")}>Low</div>
          <div className={`rw-filter-chip ${riskFilter === "CLEARED" ? "" : ""}`} onClick={() => setRiskFilter("CLEARED")}>Clean</div>
        </div>

        <div className="rw-panel-body">
          <div className="rw-table-wrap">
            {loading ? (
              <div className="rw-empty-state">
                <div className="rw-empty-icon">O</div>
                <div className="rw-empty-label">Loading files...</div>
              </div>
            ) : filteredFiles.length === 0 ? (
              <div className="rw-empty-state">
                <div className="rw-empty-icon">✓</div>
                <div className="rw-empty-label">
                  {viewMode === "scans" ? "No files match current filters" : "No quarantined files"}
                </div>
              </div>
            ) : (
              <table className="rw-data-table">
                <thead>
                  <tr>
                    <th>FILE</th>
                    <th>THREAT</th>
                    <th>RISK</th>
                    <th>SCORE</th>
                    <th>ACTIONS</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredFiles.map(file => (
                    <tr key={file.id} onClick={() => handleView(file)}>
                      <td>
                        <div className="rw-cell-file">
                          <div className="rw-file-icon" style={{ background: `${getRiskColor(file.risk_level)}22` }}>
                            <span style={{ color: getRiskColor(file.risk_level) }}>{ICONS.file}</span>
                          </div>
                          <div>
                            <div className="rw-file-name">{file.filename}</div>
                            <div className="rw-file-path">{file.full_path}</div>
                          </div>
                        </div>
                      </td>
                      <td><span className="rw-threat-name">{file.threat_name}</span></td>
                      <td>
                        <span className={`rw-risk-badge ${file.blocked || file.quarantined ? 'rw-risk-quarantined' : `rw-risk-${file.risk_level.toLowerCase()}`}`}>
                          <span className={`rw-risk-dot ${file.blocked || file.quarantined ? 'rw-dot-quarantined' : `rw-dot-${file.risk_level.toLowerCase()}`}`}></span>
                          {file.blocked || file.quarantined ? "QUARANTINED" : file.risk_level}
                        </span>
                      </td>
                      <td>
                        <div className="rw-score-bar-wrap">
                          <div className="rw-score-track">
                            <div className="rw-score-fill" style={{ width: `${file.risk_score}%`, background: getScoreGradient(file.risk_score) }}></div>
                          </div>
                          <div className="rw-score-val" style={{ color: getRiskColor(file.risk_level) }}>{file.risk_score}</div>
                        </div>
                      </td>
                      <td>
                        <div className="rw-action-row" onClick={e => e.stopPropagation()}>
                          <div className="rw-act-btn" onClick={() => handleView(file)} title="View Details">{ICONS.eye}</div>
                          {viewMode === "scans" && (
                            <div className="rw-act-btn warning" onClick={() => handleQuarantineFile(file)} title="Quarantine">{ICONS.quarantine}</div>
                          )}
                          {viewMode === "quarantine" && (
                            <div className="rw-act-btn success" onClick={() => handleRestoreFile(file)} title="Restore">{ICONS.refresh}</div>
                          )}
                          <div
                            className="rw-act-btn danger"
                            onClick={() => viewMode === "quarantine" ? handleDeleteFile(file) : handleQuarantineFile(file)}
                            title={viewMode === "quarantine" ? "Delete Permanently" : "Quarantine"}
                          >
                            {ICONS.trash}
                          </div>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
          <div className="rw-footer-stats">
            <div className="rw-footer-stat"><strong>{filteredFiles.length}</strong> suspicious files</div>
            <div className="rw-footer-stat"><strong>{criticalCount}</strong> critical</div>
            <div className="rw-footer-stat"><strong>{highCount}</strong> high</div>
            <div className="rw-footer-stat" style={{ marginLeft: "auto", fontSize: 10, display: "flex", alignItems: "center", gap: 6 }}>
              {ICONS.refresh} Auto-refresh 2s
            </div>
          </div>
        </div>
      </div>
    </>
  );

  return (
    <>
      {renderModal()}
      <div className="rw-app">
        <div className="rw-bg-orbs">
          <div className="rw-orb rw-orb-1"></div>
          <div className="rw-orb rw-orb-2"></div>
          <div className="rw-orb rw-orb-3"></div>
        </div>
        <div className="rw-scanline"></div>
        <div className="rw-main-app">
          <div className="rw-sidebar">
            <div className="rw-brand">
              <div className="rw-brand-icon">{ICONS.shield}</div>
              <div className="rw-brand-name">RECONWARE</div>
              <div className="rw-brand-tagline">THREAT DETECTION v2.0.1</div>
            </div>
            <div className="rw-nav-section">
              <div className="rw-nav-label">MONITOR</div>
              <div className={`rw-nav-item ${currentNav === "dashboard" ? "active" : ""}`} onClick={() => handleNav("dashboard")}>
                {ICONS.grid} Dashboard
              </div>
              <div className={`rw-nav-item ${currentNav === "scans" ? "active" : ""}`} onClick={() => handleNav("scans")}>
                {ICONS.terminal} Live Scans
                {criticalCount > 0 && <span className="rw-nav-badge">{criticalCount}</span>}
              </div>
              <div className={`rw-nav-item ${currentNav === "quarantine" ? "active" : ""}`} onClick={() => handleNav("quarantine")}>
                {ICONS.archive} Quarantine
                {quarantineCount > 0 && <span className="rw-nav-badge">{quarantineCount}</span>}
              </div>
            </div>
            <div className="rw-nav-section">
              <div className="rw-nav-label">ANALYSE</div>
              <div className={`rw-nav-item ${currentNav === "threats" ? "active" : ""}`} onClick={() => handleNav("threats")}>
                {ICONS.alert} Threat Intel
              </div>
              <div className={`rw-nav-item ${currentNav === "reports" ? "active" : ""}`} onClick={() => handleNav("reports")}>
                {ICONS.chart} Reports
              </div>
            </div>

            <div className="rw-sidebar-status">
              <div className="rw-status-row">
                <div className="rw-dot-live"></div>
                <span className="rw-status-text">ENGINE ONLINE</span>
              </div>
              <div className="rw-status-detail">Auto-scan every 2000ms</div>
              <div className="rw-status-detail" style={{ marginTop: 4 }}>Last sync: {syncTime}</div>
            </div>
          </div>

          <div className="rw-main">
            <div className="rw-topbar">
              <div className="rw-search-wrap">
                {ICONS.search}
                <input
                  className="rw-search-input"
                  value={searchQuery}
                  onChange={e => setSearchQuery(e.target.value)}
                  placeholder="Search files, threats, paths..."
                />
              </div>
              <div className="rw-topbar-actions">
                <div className="rw-live-chip">
                  <div className="rw-dot"></div>
                  LIVE
                </div>
                <div className="rw-view-toggle">
                  <button className={`rw-view-btn ${viewMode === "scans" || viewMode === "quarantine" ? "active" : ""}`} onClick={() => handleNav("scans")}>
                    Scans
                  </button>
                  <button className={`rw-view-btn ${viewMode === "threats" ? "active" : ""}`} onClick={() => handleNav("threats")}>
                    Intel
                  </button>
                  <button className={`rw-view-btn ${viewMode === "reports" ? "active" : ""}`} onClick={() => handleNav("reports")}>
                    Reports
                  </button>
                </div>
                <div className="rw-avatar">AK</div>
              </div>
            </div>
            <div className="rw-content">{renderMainContent()}</div>
          </div>
        </div>
      </div>
      <div className="rw-toast-container">
        {toasts.map(toast => (
          <div key={toast.id} className="rw-toast" style={{ borderColor: `${toastColors[toast.type]}55` }}>
            <span className="rw-toast-icon" style={{ color: toastColors[toast.type] }}>
              {toast.type === "success" ? "✓" : toast.type === "info" ? "i" : toast.type === "warning" ? "!" : "✕"}
            </span>
            <span>{toast.message}</span>
            <span className="rw-toast-close" onClick={() => setToasts(prev => prev.filter(t => t.id !== toast.id))}>×</span>
          </div>
        ))}
      </div>
    </>
  );
}