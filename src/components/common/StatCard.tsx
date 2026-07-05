import type { CSSProperties, ReactNode } from 'react';
import type { Severity } from '@/types';

interface StatCardProps {
  label: string;
  value: ReactNode;
  hint?: string;
  accent?: Severity | 'accent';
  icon?: ReactNode;
  className?: string;
  style?: CSSProperties;
}

export function StatCard({ label, value, hint, accent = 'accent', icon, className, style }: StatCardProps) {
  const color = accent === 'accent' ? 'var(--accent)' : `var(--sev-${accent})`;
  const merged = { '--kpi-accent': color, ...style } as CSSProperties;

  return (
    <div className={`kpi ${className ?? ''}`} style={merged}>
      <div className="kpi-top">
        <span className="kpi-label">{label}</span>
        {icon && <span className="kpi-icon">{icon}</span>}
      </div>
      <div className="kpi-value">{value}</div>
      {hint && <span className="kpi-hint">{hint}</span>}
    </div>
  );
}
