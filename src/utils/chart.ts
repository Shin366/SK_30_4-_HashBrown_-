import type { Severity } from '@/types';

// Recharts 는 CSS 변수를 직접 못 읽으므로 hex 상수로 제공 (index.css 와 동기화)
// Clean / Violet on White (v4) 팔레트.
export const SEVERITY_HEX: Record<Severity, string> = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#d97706',
  low: '#16a34a',
  info: '#2563eb',
};

export const CHART_GRID = '#ececf2';
export const CHART_AXIS = '#6b6b76';
export const ACCENT = '#6d28d9';
export const ACCENT_2 = '#0ea5e9';

export function countBySeverity<T extends { severity: Severity }>(items: T[]): Record<Severity, number> {
  const base: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const it of items) base[it.severity] += 1;
  return base;
}

export interface ChartTooltipProps {
  active?: boolean;
  payload?: Array<{ name?: string; value?: number | string; payload?: Record<string, unknown> }>;
  label?: string | number;
}
