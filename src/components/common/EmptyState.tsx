import type { ReactNode } from 'react';

export function EmptyState({ title, hint, icon }: { title: string; hint?: ReactNode; icon?: ReactNode }) {
  return (
    <div className="empty-state">
      {icon && <div style={{ fontSize: 32, opacity: 0.5 }}>{icon}</div>}
      <div style={{ fontWeight: 600, color: 'var(--text-1)' }}>{title}</div>
      {hint && <div className="text-sm">{hint}</div>}
    </div>
  );
}
