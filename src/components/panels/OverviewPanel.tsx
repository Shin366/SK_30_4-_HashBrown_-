import {
  Bar,
  BarChart,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import type { CSSProperties } from 'react';
import type { AnalysisResult, Severity } from '@/types';
import { Card } from '@/components/common/Card';
import { SeverityBadge, ConfidenceTag } from '@/components/common/Badge';
import { EmptyState } from '@/components/common/EmptyState';
import { useAnalysis, type ViewKey } from '@/context/AnalysisContext';
import { CHART_AXIS, SEVERITY_HEX, countBySeverity } from '@/utils/chart';
import { formatTimeShort, severityLabelKo } from '@/utils/format';

const SEV_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const delay = (ms: number): CSSProperties => ({ animationDelay: `${ms}ms` });

export function OverviewPanel({ result }: { result: AnalysisResult }) {
  const { setActiveView } = useAnalysis();
  const isMft = result.kind === 'mft';
  const sevCounts = countBySeverity(result.anomalies);
  const total = result.anomalies.length;
  const sevRows = SEV_ORDER.filter((s) => s !== 'info' || sevCounts[s] > 0);
  const maxCount = Math.max(1, ...sevRows.map((s) => sevCounts[s]));

  const topTraffic = result.traffic.slice(0, 6).map((t) => ({
    ip: t.sourceIp,
    score: Math.round(t.anomalyScore * 100),
    classification: t.classification,
  }));

  const go = (v: ViewKey) => () => setActiveView(v);
  const engineLabel = result.report.engine === 'ai' ? '생성형 AI' : '로컬 규칙기반';

  return (
    <div className="col" style={{ gap: 18 }}>
      {/* ── 행 A : 심각도 · ATT&CK · CVE (3등분, 한눈에) ── */}
      <div className="grid grid-3" style={{ alignItems: 'stretch' }}>
        {/* 심각도 분포 */}
        <Card className="reveal" style={delay(0)} title="심각도 분포" subtitle={`${isMft ? '의심 파일' : '이상징후'} 집계`}>
          {total === 0 ? (
            <EmptyState title="이상징후 없음" />
          ) : (
            <div className="col" style={{ gap: 14 }}>
              <div className="row" style={{ alignItems: 'flex-end', gap: 9 }}>
                <span style={{ fontFamily: 'var(--font-display)', fontSize: 40, fontWeight: 700, lineHeight: 0.9, letterSpacing: '-0.03em' }}>{total}</span>
                <span className="eyebrow" style={{ paddingBottom: 5 }}>Total</span>
              </div>
              <div style={{ display: 'flex', height: 8, borderRadius: 999, overflow: 'hidden', background: 'var(--bg-3)' }}>
                {sevRows.filter((s) => sevCounts[s] > 0).map((s) => (
                  <div key={s} style={{ width: `${(sevCounts[s] / total) * 100}%`, background: SEVERITY_HEX[s] }} title={`${severityLabelKo(s)} ${sevCounts[s]}`} />
                ))}
              </div>
              <div className="col" style={{ gap: 7 }}>
                {sevRows.map((s) => {
                  const c = sevCounts[s];
                  return (
                    <div key={s} className="row" style={{ gap: 10, alignItems: 'center', opacity: c === 0 ? 0.45 : 1 }}>
                      <span style={{ width: 8, height: 8, borderRadius: '50%', background: c ? SEVERITY_HEX[s] : 'var(--surface-border-strong)', flexShrink: 0 }} />
                      <span className="text-sm" style={{ width: 40, flexShrink: 0 }}>{severityLabelKo(s)}</span>
                      <div style={{ flex: 1, height: 5, background: 'var(--bg-3)', borderRadius: 999, overflow: 'hidden' }}>
                        <div style={{ width: `${(c / maxCount) * 100}%`, height: '100%', background: SEVERITY_HEX[s], borderRadius: 999 }} />
                      </div>
                      <strong className="num" style={{ width: 28, textAlign: 'right', fontSize: 14, color: c ? SEVERITY_HEX[s] : 'var(--text-3-solid)' }}>{c}</strong>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </Card>

        {/* 주요 ATT&CK 기법 */}
        <Card className="reveal" style={delay(80)} title="주요 ATT&CK 기법" subtitle={`${result.techniques.length}개 · kill-chain 순`} actions={<button className="btn btn-ghost" onClick={go('threats')}>전체 →</button>}>
          {result.techniques.length === 0 ? (
            <EmptyState title="매핑된 기법 없음" />
          ) : (
            <div className="col" style={{ gap: 0 }}>
              {result.techniques.slice(0, 5).map((t) => (
                <div key={t.id} className="row" style={{ gap: 10, padding: '9px 0', borderBottom: '1px solid var(--surface-border)' }}>
                  <span className="mono" style={{ width: 64, flexShrink: 0, color: 'var(--accent)', fontSize: 11 }}>{t.id}</span>
                  <span className="text-sm" style={{ flex: 1, minWidth: 0, fontWeight: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{t.name}</span>
                  <SeverityBadge severity={t.severity} />
                </div>
              ))}
            </div>
          )}
        </Card>

        {/* 관련 CVE — 추가됨 */}
        <Card className="reveal" style={delay(160)} title="관련 CVE" subtitle={`${result.cves.length}건 · CVSS 순`} actions={<button className="btn btn-ghost" onClick={go('threats')}>전체 →</button>}>
          {result.cves.length === 0 ? (
            <EmptyState title="연관 CVE 없음" hint={isMft ? 'MFT 분석은 CVE 매핑 비대상' : '해당 시그니처 미탐지'} />
          ) : (
            <div className="col" style={{ gap: 0 }}>
              {result.cves.slice(0, 5).map((c) => (
                <div key={c.id} className="col" style={{ gap: 3, padding: '9px 0', borderBottom: '1px solid var(--surface-border)' }}>
                  <div className="row" style={{ gap: 8 }}>
                    <span className="mono" style={{ fontSize: 11.5, fontWeight: 600, color: 'var(--accent)' }}>{c.id}</span>
                    <span className="num" style={{ fontSize: 11, color: 'var(--text-2)' }}>CVSS {c.cvss.toFixed(1)}</span>
                    <span style={{ flex: 1 }} />
                    <SeverityBadge severity={c.severity} />
                  </div>
                  <span className="text-xs muted" style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{c.description}</span>
                </div>
              ))}
            </div>
          )}
        </Card>
      </div>

      {/* ── 행 B : 분석 요약 · 트래픽/유형 ── */}
      <div className="grid grid-2" style={{ alignItems: 'stretch' }}>
        <Card className="reveal" style={delay(240)} title="분석 요약" subtitle={`엔진: ${engineLabel}`} actions={<button className="btn btn-ghost" onClick={go('report')}>가이드 보고서 →</button>}>
          <p style={{ margin: 0, color: 'var(--text-1)', lineHeight: 1.7, fontSize: 14 }}>{result.report.narrative}</p>
          <div className="row wrap" style={{ gap: 8, borderTop: '1px solid var(--surface-border)', paddingTop: 13, marginTop: 14 }}>
            <ConfidenceTag kind="fact" /> <span className="text-xs muted" style={{ marginRight: 8 }}>관측된 사실</span>
            <ConfidenceTag kind="assessment" /> <span className="text-xs muted">규칙/AI 추정</span>
          </div>
        </Card>

        {isMft ? (
          <Card className="reveal" style={delay(320)} title="의심 파일 유형별" subtitle="탐지 규칙별 건수" actions={<button className="btn btn-ghost" onClick={go('logs')}>MFT 분석 →</button>}>
            {result.mft!.findingsByCategory.length === 0 ? (
              <EmptyState title="의심 파일 없음" hint="정상 베이스라인일 수 있음" />
            ) : (
              <div className="col" style={{ gap: 0 }}>
                {result.mft!.findingsByCategory.slice(0, 6).map((c) => (
                  <div key={c.category} className="spread" style={{ padding: '9px 0', borderBottom: '1px solid var(--surface-border)' }}>
                    <span className="row text-sm" style={{ gap: 9, minWidth: 0 }}>
                      <span style={{ width: 8, height: 8, borderRadius: '50%', background: SEVERITY_HEX[c.severity], flexShrink: 0 }} />
                      <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{c.category}</span>
                    </span>
                    <strong className="num">{c.count.toLocaleString()}</strong>
                  </div>
                ))}
              </div>
            )}
          </Card>
        ) : (
          <Card className="reveal" style={delay(320)} title="비정상 의심 트래픽 Top" subtitle="출발지 IP 별 이상 확률(%)" actions={<button className="btn btn-ghost" onClick={go('traffic')}>전체 →</button>}>
            {topTraffic.length === 0 ? (
              <EmptyState title="IP 기반 트래픽 없음" />
            ) : (
              <div style={{ width: '100%', height: 218 }}>
                <ResponsiveContainer>
                  <BarChart data={topTraffic} layout="vertical" margin={{ left: 8, right: 18 }}>
                    <XAxis type="number" domain={[0, 100]} stroke={CHART_AXIS} fontSize={11} />
                    <YAxis type="category" dataKey="ip" width={112} stroke={CHART_AXIS} fontSize={11} />
                    <Tooltip contentStyle={tooltipStyle} cursor={{ fill: 'rgba(109,40,217,0.05)' }} />
                    <Bar dataKey="score" radius={[0, 5, 5, 0]} name="이상확률%">
                      {topTraffic.map((d) => (
                        <Cell key={d.ip} fill={d.classification === 'abnormal' ? SEVERITY_HEX.critical : SEVERITY_HEX.low} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            )}
          </Card>
        )}
      </div>

      {/* ── 행 C : 타임라인 (순차 등장) ── */}
      <Card className="reveal" style={delay(400)} title="공격 타임라인 (최근)" subtitle="시간순 이상징후" actions={<button className="btn btn-ghost" onClick={go('timeline')}>전체 타임라인 →</button>}>
        {result.timeline.length === 0 ? (
          <EmptyState title="타임라인 이벤트 없음" />
        ) : (
          <div className="col" style={{ gap: 0 }}>
            {result.timeline.slice(0, 7).map((ev, i) => (
              <div key={ev.id} className="row reveal" style={{ ...delay(460 + i * 70), gap: 13, padding: '10px 0', borderBottom: '1px solid var(--surface-border)' }}>
                <span className="num text-xs" style={{ width: 64, color: 'var(--text-2)', flexShrink: 0 }}>{formatTimeShort(ev.timestamp)}</span>
                <span style={{ width: 8, height: 8, borderRadius: '50%', background: SEVERITY_HEX[ev.severity], flexShrink: 0 }} />
                <span className="text-sm" style={{ flex: 1, minWidth: 0, fontWeight: 500 }}>{ev.title}</span>
                <ConfidenceTag kind={ev.confidence} />
                <SeverityBadge severity={ev.severity} />
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}

const tooltipStyle: CSSProperties = {
  background: 'var(--bg-1)',
  border: '1px solid var(--surface-border-strong)',
  borderRadius: 8,
  fontSize: 12,
  color: 'var(--text-0)',
  boxShadow: 'var(--shadow-2)',
};
