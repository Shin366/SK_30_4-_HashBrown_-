import type { Severity } from '@/types';

/** 안정적인 짧은 ID 생성 (Math.random 없이 카운터 기반) */
let _idCounter = 0;
export function makeId(prefix = 'id'): string {
  _idCounter += 1;
  return `${prefix}_${_idCounter.toString(36)}`;
}

export function resetIdCounter(): void {
  _idCounter = 0;
}

const SEV_RANK: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

export function severityRank(s: Severity): number {
  return SEV_RANK[s] ?? 0;
}

export function maxSeverity(list: Severity[], fallback: Severity = 'info'): Severity {
  if (list.length === 0) return fallback;
  return list.reduce((acc, s) => (severityRank(s) > severityRank(acc) ? s : acc), 'info' as Severity);
}

export function severityColorVar(s: Severity): string {
  return `var(--sev-${s})`;
}

export function severityLabelKo(s: Severity): string {
  switch (s) {
    case 'critical': return '심각';
    case 'high': return '높음';
    case 'medium': return '중간';
    case 'low': return '낮음';
    default: return '정보';
  }
}

export function formatBytes(n: number): string {
  if (!n || n < 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v.toFixed(v >= 10 || i === 0 ? 0 : 1)} ${units[i]}`;
}

export function formatNumber(n: number): string {
  return n.toLocaleString('en-US');
}

export function formatTimestamp(iso: string | null): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const pad = (x: number) => x.toString().padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(
    d.getMinutes(),
  )}:${pad(d.getSeconds())}`;
}

export function formatTimeShort(iso: string | null): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const pad = (x: number) => x.toString().padStart(2, '0');
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

export function truncate(s: string, max = 80): string {
  if (s.length <= max) return s;
  return `${s.slice(0, max - 1)}…`;
}

export function pct(n: number, digits = 0): string {
  return `${(n * 100).toFixed(digits)}%`;
}
