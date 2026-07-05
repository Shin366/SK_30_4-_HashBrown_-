import { useMemo, useState, type CSSProperties } from 'react';
import type { AnalysisResult, Severity } from '@/types';
import { Card } from '@/components/common/Card';
import { StatCard } from '@/components/common/StatCard';
import { SeverityBadge, ConfidenceTag } from '@/components/common/Badge';
import { EmptyState } from '@/components/common/EmptyState';
import { severityRank, formatTimeShort } from '@/utils/format';
import { countBySeverity } from '@/utils/chart';

const SEV_FILTERS: Array<Severity | 'all'> = ['all', 'critical', 'high', 'medium', 'low'];

export function LogAnalysisPanel({ result }: { result: AnalysisResult }) {
  const [sev, setSev] = useState<Severity | 'all'>('all');
  const [q, setQ] = useState('');
  const counts = countBySeverity(result.anomalies);

  const anomalies = useMemo(() => {
    return [...result.anomalies]
      .filter((a) => (sev === 'all' ? true : a.severity === sev))
      .filter((a) =>
        q.trim()
          ? (a.category + a.evidence + (a.sourceIp ?? '')).toLowerCase().includes(q.toLowerCase())
          : true,
      )
      .sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
  }, [result.anomalies, sev, q]);

  const logSample = useMemo(() => {
    if (!q.trim()) return result.logs.slice(0, 60);
    return result.logs.filter((l) => l.raw.toLowerCase().includes(q.toLowerCase())).slice(0, 60);
  }, [result.logs, q]);

  return (
    <div className="col" style={{ gap: 18 }}>
      <div className="grid grid-4">
        <StatCard label="총 로그 라인" value={result.logs.length.toLocaleString()} hint={result.fileName} />
        <StatCard label="이상징후" value={result.anomalies.length} accent={counts.critical ? 'critical' : 'high'} />
        <StatCard label="고유 출발지 IP" value={new Set(result.logs.map((l) => l.sourceIp).filter(Boolean)).size} accent="info" />
        <StatCard label="타임스탬프 인식" value={`${Math.round((result.logs.filter((l) => l.timestamp).length / Math.max(1, result.logs.length)) * 100)}%`} accent="low" />
      </div>

      <Card
        title="탐지된 이상징후"
        subtitle="패턴 매칭(FACT) · 빈도 기반 해석(ASSESS) 을 구분 표기"
        actions={
          <input
            placeholder="카테고리·근거·IP 검색…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            style={searchStyle}
          />
        }
        bodyClassName=""
      >
        <div className="row wrap" style={{ gap: 6, padding: '12px 16px', borderBottom: '1px solid var(--surface-border)' }}>
          {SEV_FILTERS.map((s) => (
            <button
              key={s}
              className="pill"
              onClick={() => setSev(s)}
              style={{
                cursor: 'pointer',
                background: sev === s ? 'var(--accent-soft)' : 'var(--bg-2)',
                borderColor: sev === s ? 'var(--accent)' : 'var(--surface-border)',
                color: sev === s ? 'var(--text-0)' : 'var(--text-1)',
              }}
            >
              {s === 'all' ? '전체' : s} {s !== 'all' && `(${counts[s]})`}
            </button>
          ))}
        </div>

        {anomalies.length === 0 ? (
          <EmptyState title="조건에 맞는 이상징후 없음" />
        ) : (
          <div style={{ maxHeight: 420, overflowY: 'auto' }}>
            <table className="tbl">
              <thead>
                <tr>
                  <th style={{ width: 70 }}>심각도</th>
                  <th style={{ width: 64 }}>근거</th>
                  <th style={{ width: 60 }}>라인</th>
                  <th style={{ width: 80 }}>시각</th>
                  <th>분류 / 근거 스니펫</th>
                  <th style={{ width: 120 }}>출발지</th>
                </tr>
              </thead>
              <tbody>
                {anomalies.map((a) => (
                  <tr key={a.id}>
                    <td><SeverityBadge severity={a.severity} /></td>
                    <td><ConfidenceTag kind={a.confidence} /></td>
                    <td className="mono dim">L{a.lineNumber}</td>
                    <td className="mono text-xs">{formatTimeShort(a.timestamp)}</td>
                    <td>
                      <div style={{ fontWeight: 600 }}>{a.category}</div>
                      <div className="text-xs muted mono" style={{ marginTop: 2, wordBreak: 'break-all' }}>{a.evidence}</div>
                    </td>
                    <td className="mono text-xs">{a.sourceIp ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <Card title="원본 로그 미리보기" subtitle={`${logSample.length}건 표시${q ? ' (검색 일치)' : ' (상위 60건)'}`} bodyClassName="">
        <div style={{ maxHeight: 360, overflowY: 'auto', padding: '8px 0' }}>
          {logSample.map((l) => (
            <div key={l.id} className="row" style={{ gap: 10, padding: '4px 16px', alignItems: 'baseline' }}>
              <span className="mono dim text-xs" style={{ width: 44, flexShrink: 0, textAlign: 'right' }}>{l.lineNumber}</span>
              <span className="mono text-xs" style={{ color: 'var(--text-1)', wordBreak: 'break-all', whiteSpace: 'pre-wrap' }}>{l.raw}</span>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}

const searchStyle: CSSProperties = {
  background: 'var(--bg-2)',
  border: '1px solid var(--surface-border)',
  borderRadius: 8,
  padding: '7px 11px',
  color: 'var(--text-0)',
  fontSize: 13,
  width: 220,
  outline: 'none',
};
