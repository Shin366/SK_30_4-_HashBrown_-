import type { ConfidenceKind, Severity } from '@/types';
import { severityLabelKo } from '@/utils/format';

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`badge badge-${severity}`}>{severityLabelKo(severity)}</span>;
}

/** REQ-NF-002: 사실(Fact) / 추정(Assessment) 구분 태그 */
export function ConfidenceTag({ kind }: { kind: ConfidenceKind }) {
  return kind === 'fact' ? (
    <span className="tag-fact" title="패턴 직접 매칭 등 관측된 사실">FACT</span>
  ) : (
    <span className="tag-assessment" title="규칙/AI 기반 해석 — 분석가 검증 필요">ASSESS</span>
  );
}
