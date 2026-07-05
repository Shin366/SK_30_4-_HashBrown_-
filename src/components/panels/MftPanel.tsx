import { useMemo, useState } from 'react';
import type { CSSProperties } from 'react';
import type { AnalysisResult, Severity } from '@/types';
import { Card } from '@/components/common/Card';
import { StatCard } from '@/components/common/StatCard';
import { SeverityBadge, ConfidenceTag } from '@/components/common/Badge';
import { EmptyState } from '@/components/common/EmptyState';
import { IconAlert } from '@/components/common/icons';
import { severityRank, formatTimestamp, formatNumber } from '@/utils/format';
import { SEVERITY_HEX } from '@/utils/chart';

const SEV_FILTERS: Array<Severity | 'all'> = ['all', 'critical', 'high', 'medium', 'low'];
const delay = (ms: number): CSSProperties => ({ animationDelay: `${ms}ms` });

export function MftPanel({ result }: { result: AnalysisResult }) {
  const m = result.mft!;
  const [sev, setSev] = useState<Severity | 'all'>('all');
  const [q, setQ] = useState('');

  const findings = useMemo(() => {
    return [...m.findings]
      .filter((f) => (sev === 'all' ? true : f.severity === sev))
      .filter((f) => (q.trim() ? (f.path + f.category + f.fileName).toLowerCase().includes(q.toLowerCase()) : true))
      .sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
  }, [m.findings, sev, q]);

  const counts = useMemo(() => {
    const c: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of m.findings) c[f.severity] += 1;
    return c;
  }, [m.findings]);

  return (
    <div className="col" style={{ gap: 18 }}>
      {/* KPI */}
      <div className="grid grid-4">
        <StatCard className="reveal" style={delay(0)} label="총 MFT 레코드" value={formatNumber(m.totalRecords)} hint={`파일 ${formatNumber(m.fileCount)} · 폴더 ${formatNumber(m.folderCount)}`} />
        <StatCard className="reveal" style={delay(70)} label="삭제 정황(Inactive)" value={formatNumber(m.inactiveCount)} accent="medium" hint={`활성 ${formatNumber(m.activeCount)}`} />
        <StatCard className="reveal" style={delay(140)} label="의심 파일 탐지" value={m.findings.length} accent={counts.critical ? 'critical' : counts.high ? 'high' : 'low'} hint={`심각 ${counts.critical} · 높음 ${counts.high}`} icon={<IconAlert />} />
        <StatCard className="reveal" style={delay(210)} label="타임스탬프 보유" value={`${Math.round((m.datedRecords / Math.max(1, m.totalRecords)) * 100)}%`} accent="info" hint={`${formatNumber(m.datedRecords)} 레코드`} />
      </div>

      {/* 의심 유형별 + 타임스탬프 정합성 (2열 정렬) */}
      <div className="grid grid-2" style={{ alignItems: 'stretch' }}>
        <Card className="reveal" style={delay(260)} title="의심 유형별 집계" subtitle="탐지 규칙별 건수">
          {m.findingsByCategory.length === 0 ? (
            <EmptyState title="의심 파일 없음" hint="정상 베이스라인일 수 있음 (분석가 검증)" />
          ) : (
            <div className="col" style={{ gap: 0 }}>
              {m.findingsByCategory.map((c) => (
                <div key={c.category} className="spread" style={{ padding: '10px 0', borderBottom: '1px solid var(--surface-border)' }}>
                  <span className="row text-sm" style={{ gap: 9, minWidth: 0 }}>
                    <span style={{ width: 8, height: 8, borderRadius: '50%', background: SEVERITY_HEX[c.severity], flexShrink: 0 }} />
                    <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{c.category}</span>
                  </span>
                  <strong className="num">{formatNumber(c.count)}</strong>
                </div>
              ))}
            </div>
          )}
        </Card>

        <Card className="reveal" style={delay(320)} title="타임스탬프 정합성 (정보성)" subtitle="단독 변조 근거 아님 — 교차검증 시에만 의미">
          <div className="col" style={{ gap: 12 }}>
            <div style={{ background: 'var(--bg-2)', borderRadius: 'var(--r-md)', padding: '12px 14px' }}>
              <div className="spread">
                <span className="text-sm muted">$SI 생성 &lt; $FN 생성</span>
                <strong className="num" style={{ fontSize: 20, color: 'var(--sev-medium)' }}>{formatNumber(m.siFnMismatchCount)}</strong>
              </div>
              <div className="text-xs dim mt-8">파일 복사·프로비저닝 시에도 정상 발생. Timestomp(T1070.006)와 MFT 만으로는 구분 불가.</div>
            </div>
            <div style={{ background: 'var(--bg-2)', borderRadius: 'var(--r-md)', padding: '12px 14px' }}>
              <div className="spread">
                <span className="text-sm muted">$SI 생성 &gt; $SI 수정</span>
                <strong className="num" style={{ fontSize: 20, color: 'var(--sev-medium)' }}>{formatNumber(m.tsLogicAnomalyCount)}</strong>
              </div>
              <div className="text-xs dim mt-8">논리 모순처럼 보이나 복사 파일에서도 흔함. 의심 실행파일에 한해 보강 근거로만 활용.</div>
            </div>
            <div className="row text-xs muted" style={{ gap: 7 }}>
              <ConfidenceTag kind="assessment" /> 위 수치는 <strong>경보로 올리지 않는</strong> 정보성 항목입니다.
            </div>
          </div>
        </Card>
      </div>

      {/* 의심 파일 상세 */}
      <Card
        className="reveal"
        style={delay(380)}
        title="의심 파일 상세"
        subtitle={`${m.findings.length}건 · 사실(FACT)/추정(ASSESS) 구분`}
        actions={<input placeholder="경로·파일명·유형 검색…" value={q} onChange={(e) => setQ(e.target.value)} style={searchStyle} />}
        bodyClassName=""
      >
        <div className="row wrap" style={{ gap: 6, padding: '12px 20px', borderBottom: '1px solid var(--surface-border)' }}>
          {SEV_FILTERS.map((s) => (
            <button key={s} className="pill" onClick={() => setSev(s)} style={pillSel(sev === s)}>
              {s === 'all' ? '전체' : s} {s !== 'all' && `(${counts[s]})`}
            </button>
          ))}
        </div>
        {findings.length === 0 ? (
          <EmptyState title="조건에 맞는 의심 파일 없음" hint="치명적 지표가 없거나 정상 베이스라인일 수 있습니다 (분석가 검증)." />
        ) : (
          <div style={{ maxHeight: 480, overflowY: 'auto' }}>
            <table className="tbl">
              <thead>
                <tr>
                  <th style={{ width: 64 }}>심각도</th>
                  <th style={{ width: 60 }}>근거</th>
                  <th style={{ width: 64 }}>상태</th>
                  <th>유형 / 파일 · 경로</th>
                  <th style={{ width: 96 }}>$SI 생성</th>
                  <th style={{ width: 96 }}>$FN 생성</th>
                </tr>
              </thead>
              <tbody>
                {findings.map((f) => (
                  <tr key={f.id}>
                    <td><SeverityBadge severity={f.severity} /></td>
                    <td><ConfidenceTag kind={f.confidence} /></td>
                    <td><span className={`badge ${f.active ? 'badge-info' : 'badge-medium'}`}>{f.active ? '활성' : '삭제'}</span></td>
                    <td>
                      <div style={{ fontWeight: 600 }}>{f.category}</div>
                      <div className="text-sm">{f.fileName}</div>
                      <div className="text-xs muted mono" style={{ wordBreak: 'break-all', marginTop: 2 }}>{f.path}</div>
                      {f.description && (
                        <div className="text-xs muted" style={{ marginTop: 3, lineHeight: 1.45 }}>{f.description}</div>
                      )}
                    </td>
                    <td className="mono text-xs">{f.siCreated ? formatTimestamp(f.siCreated).slice(0, 10) : '—'}</td>
                    <td className="mono text-xs">{f.fnCreated ? formatTimestamp(f.fnCreated).slice(0, 10) : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}

function pillSel(active: boolean): CSSProperties {
  return {
    cursor: 'pointer',
    background: active ? 'var(--accent-soft)' : 'var(--bg-2)',
    borderColor: active ? 'var(--accent)' : 'var(--surface-border)',
    color: active ? 'var(--accent)' : 'var(--text-1)',
  };
}

const searchStyle: CSSProperties = {
  background: 'var(--bg-1)', border: '1px solid var(--surface-border-strong)', borderRadius: 'var(--r-md)',
  padding: '7px 11px', color: 'var(--text-0)', fontSize: 13, width: 220, outline: 'none', fontFamily: 'var(--font-sans)',
};
