import type { CSSProperties } from 'react';
import type { AnalysisResult } from '@/types';
import { Card } from '@/components/common/Card';
import { SeverityBadge, ConfidenceTag } from '@/components/common/Badge';
import { EmptyState } from '@/components/common/EmptyState';
import { SEVERITY_HEX } from '@/utils/chart';
import { formatTimestamp } from '@/utils/format';

const delay = (ms: number): CSSProperties => ({ animationDelay: `${ms}ms` });
const accent = (hex: string) => ({ '--kpi-accent': hex } as CSSProperties);

export function TimelinePanel({ result }: { result: AnalysisResult }) {
  const { timeline, attackFlow, intrusion } = result;

  return (
    <div className="col" style={{ gap: 18 }}>
      {/* AI 추정 침입 경로 (Assessment) */}
      {intrusion && (
        <Card
          className="reveal"
          title="AI 추정 침입 경로"
          subtitle="탐지 지표를 kill-chain 순으로 재구성한 공격자 침입 시나리오 (추정 · 사실 아님)"
        >
          <div className="col" style={{ gap: 14 }}>
            {/* 요약 배너 */}
            <div
              className="col"
              style={{
                gap: 8,
                padding: '12px 14px',
                background: 'var(--bg-1)',
                borderRadius: 8,
                borderLeft: `3px solid ${SEVERITY_HEX.high}`,
              }}
            >
              <div className="row" style={{ gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
                <span className="eyebrow" style={{ fontSize: 10 }}>초기 침투 경로 추정</span>
                <ConfidenceTag kind={intrusion.confidence} />
              </div>
              <div style={{ fontFamily: 'var(--font-display)', fontWeight: 600, fontSize: 14.5, lineHeight: 1.4 }}>
                {intrusion.entryVector}
              </div>
              <div className="row" style={{ gap: 6, flexWrap: 'wrap', marginTop: 2 }}>
                {intrusion.timeSpan && <span className="pill text-xs">🕑 {intrusion.timeSpan}</span>}
                {intrusion.topSourceIp && <span className="pill text-xs mono">📍 {intrusion.topSourceIp}</span>}
                <span className="pill text-xs">👤 {intrusion.actorProfile}</span>
              </div>
            </div>

            {/* 종합 서사 */}
            <p className="text-sm" style={{ margin: 0, lineHeight: 1.7 }}>{intrusion.narrative}</p>

            {/* 단계별 재구성 */}
            <div className="col" style={{ gap: 10 }}>
              {intrusion.steps.map((s) => (
                <div key={s.order} className="row" style={{ gap: 10, alignItems: 'flex-start' }}>
                  <span
                    className="mono"
                    style={{
                      flexShrink: 0,
                      width: 26,
                      height: 26,
                      display: 'grid',
                      placeItems: 'center',
                      borderRadius: '50%',
                      background: SEVERITY_HEX[s.severity],
                      color: '#0b0e14',
                      fontWeight: 700,
                      fontSize: 12,
                    }}
                  >
                    {s.order}
                  </span>
                  <div className="col" style={{ gap: 3, minWidth: 0, flex: 1 }}>
                    <div className="row" style={{ gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
                      <span style={{ fontWeight: 650, fontSize: 13 }}>{s.title}</span>
                      <span className="pill text-xs">{s.phase}</span>
                      <SeverityBadge severity={s.severity} />
                      {s.techniqueIds.map((id) => (
                        <span key={id} className="mono text-xs dim">{id}</span>
                      ))}
                    </div>
                    <div className="text-sm muted" style={{ lineHeight: 1.5 }}>{s.narrative}</div>
                    {s.evidence && (
                      <div className="mono text-xs dim" style={{ wordBreak: 'break-all' }}>근거: {s.evidence}</div>
                    )}
                  </div>
                </div>
              ))}
            </div>

            {/* 한계·불확실성 */}
            <div className="text-xs muted" style={{ lineHeight: 1.6, borderTop: '1px solid var(--surface-border)', paddingTop: 10 }}>
              <b>추정의 한계</b>
              <ul style={{ margin: '6px 0 0', paddingLeft: 18 }}>
                {intrusion.caveats.map((c, i) => (
                  <li key={i} style={{ marginBottom: 2 }}>{c}</li>
                ))}
              </ul>
            </div>
          </div>
        </Card>
      )}

      {/* 공격 흐름도 (kill-chain) */}
      <Card className="reveal" style={delay(0)} title="공격 흐름도" subtitle="탐지 기법을 MITRE ATT&CK kill-chain 단계로 재구성 (AI 자동 생성)">
        {attackFlow.nodes.length === 0 ? (
          <EmptyState title="흐름도 생성 불가" hint="매핑된 기법이 없습니다." />
        ) : (
          <div className="flow">
            {attackFlow.nodes.map((n, i) => (
              <div key={n.id} className="row reveal" style={{ ...delay(120 + i * 90), gap: 0, flexShrink: 0 }}>
                <div className="flow-node" style={accent(SEVERITY_HEX[n.severity])}>
                  <div className="row" style={{ gap: 6, marginBottom: 6 }}>
                    <span className="eyebrow" style={{ fontSize: 9 }}>{String(i + 1).padStart(2, '0')}</span>
                    <span className="mono text-xs" style={{ color: 'var(--text-3-solid)' }}>{n.techniqueId}</span>
                  </div>
                  <div style={{ fontFamily: 'var(--font-display)', fontWeight: 600, fontSize: 13.5, lineHeight: 1.25 }}>{n.label}</div>
                  <div className="text-xs muted" style={{ marginTop: 4 }}>{n.phase}</div>
                </div>
                {i < attackFlow.nodes.length - 1 && <div className="flow-arrow">→</div>}
              </div>
            ))}
          </div>
        )}
      </Card>

      {/* 타임라인 (수직 레일, 순차 등장) */}
      <Card className="reveal" style={delay(150)} title="공격 타임라인" subtitle={`${timeline.length}개 이벤트 · 시간순`} bodyClassName="card-pad">
        {timeline.length === 0 ? (
          <EmptyState title="타임라인 이벤트 없음" />
        ) : (
          <div className="timeline">
            <div className="timeline-rail" />
            {timeline.map((ev, i) => (
              <div key={ev.id} className="tl-row reveal" style={delay(250 + i * 75)}>
                <span className="tl-time">
                  {ev.timestamp ? formatTimestamp(ev.timestamp).split(' ')[1] ?? formatTimestamp(ev.timestamp) : `#${ev.order}`}
                </span>
                <span className="tl-dot" style={{ color: SEVERITY_HEX[ev.severity], background: SEVERITY_HEX[ev.severity] }} />
                <div className="tl-card">
                  <div className="spread" style={{ marginBottom: 4, gap: 8 }}>
                    <span className="row" style={{ gap: 8, minWidth: 0 }}>
                      <strong style={{ fontFamily: 'var(--font-display)', fontSize: 14 }}>{ev.title}</strong>
                      <span className="pill text-xs">{ev.phase}</span>
                    </span>
                    <span className="row" style={{ gap: 6, flexShrink: 0 }}>
                      <ConfidenceTag kind={ev.confidence} />
                      <SeverityBadge severity={ev.severity} />
                    </span>
                  </div>
                  <div className="text-sm muted" style={{ lineHeight: 1.5 }}>{ev.description}</div>
                  {ev.sourceIp && <div className="mono text-xs dim mt-8">출발지: {ev.sourceIp}</div>}
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}
