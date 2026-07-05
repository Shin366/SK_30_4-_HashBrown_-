import type { CSSProperties, ReactNode } from 'react';

interface CardProps {
  title?: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  bodyClassName?: string;
  className?: string;
  style?: CSSProperties;
}

export function Card({ title, subtitle, actions, children, bodyClassName, className, style }: CardProps) {
  return (
    <section className={`card ${className ?? ''}`} style={style}>
      {(title || actions) && (
        <header className="card-head">
          <div className="col" style={{ gap: 2 }}>
            {title && <div className="card-title">{title}</div>}
            {subtitle && <div className="card-subtitle">{subtitle}</div>}
          </div>
          {actions}
        </header>
      )}
      <div className={bodyClassName ?? 'card-pad'}>{children}</div>
    </section>
  );
}
