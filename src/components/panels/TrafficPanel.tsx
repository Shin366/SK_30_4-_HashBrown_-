import {
  Bar,
  BarChart,
  Cell,
  LabelList,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import type { AnalysisResult } from '@/types';
import { Card } from '@/components/common/Card';
import { StatCard } from '@/components/common/StatCard';
import { ConfidenceTag } from '@/components/common/Badge';
import { EmptyState } from '@/components/common/EmptyState';
import { CHART_AXIS, SEVERITY_HEX, type ChartTooltipProps } from '@/utils/chart';
import { formatBytes, pct } from '@/utils/format';

function TrafficTooltip({ active, payload }: ChartTooltipProps) {
  if (!active || !payload?.length) return null;
  const p = payload[0].payload as { ip: string; score: number; reasons: string };
  return (
    <div className="card card-pad" style={{ maxWidth: 280 }}>
      <div className="mono" style={{ fontWeight: 650, marginBottom: 4 }}>{p.ip}</div>
      <div className="text-sm" style={{ color: 'var(--sev-high)', marginBottom: 4 }}>이상 확률 {p.score}%</div>
      <div className="text-xs muted">{p.reasons}</div>
    </div>
  );
}

export function TrafficPanel({ result }: { result: AnalysisResult }) {
  // MFT(파일시스템 기록)에는 네트워크 출발지/트래픽이 없어 분석 비대상 — 안내 화면 표시
  if (result.kind === 'mft') {
    return (
      <Card title="트래픽 분석" subtitle="네트워크 출발지 기반 이상탐지 (REQ-F-004)">
        <EmptyState
          title="MFT 분석은 트래픽 비대상"
          hint="MFT(NTFS 파일시스템 기록)에는 네트워크 출발지 IP·요청 정보가 없어 트래픽 분석을 수행하지 않습니다. 트래픽 분석은 웹·인증·시스템 로그처럼 출발지 IP가 있는 로그에서 제공됩니다."
        />
      </Card>
    );
  }

  const { traffic } = result;
  const abnormal = traffic.filter((t) => t.classification === 'abnormal');
  const totalReq = traffic.reduce((s, t) => s + t.requests, 0);

  const chartData = traffic.slice(0, 14).map((t) => ({
    ip: t.sourceIp,
    score: Math.round(t.anomalyScore * 100),
    classification: t.classification,
    reasons: t.reasons.join(', '),
  }));

  return (
    <div className="col" style={{ gap: 18 }}>
      <div className="grid grid-4">
        <StatCard label="분석 출발지 IP" value={traffic.length} hint={`총 ${totalReq.toLocaleString()} 요청`} />
        <StatCard label="비정상 추정" value={abnormal.length} accent="critical" hint="score ≥ 50%" />
        <StatCard label="정상 추정" value={traffic.length - abnormal.length} accent="low" />
        <StatCard
          label="최고 위험 IP"
          value={<span className="mono" style={{ fontSize: 18 }}>{traffic[0]?.sourceIp ?? '—'}</span>}
          accent="high"
          hint={traffic[0] ? `score ${pct(traffic[0].anomalyScore)}` : undefined}
        />
      </div>

      <Card title="출발지별 이상 트래픽 확률 (순위 기반)" subtitle="AI 확률 스코어 0~100% · 빨강=비정상 추정">
        {chartData.length === 0 ? (
          <EmptyState title="IP 기반 트래픽 데이터 없음" hint="로그에 출발지 IP가 없습니다." />
        ) : (
          <div style={{ width: '100%', height: Math.max(220, chartData.length * 34) }}>
            <ResponsiveContainer>
              <BarChart data={chartData} layout="vertical" margin={{ left: 12, right: 48, top: 4, bottom: 4 }}>
                <XAxis type="number" domain={[0, 100]} stroke={CHART_AXIS} fontSize={11} tickFormatter={(v) => `${v}%`} />
                <YAxis type="category" dataKey="ip" width={120} stroke={CHART_AXIS} fontSize={11.5} />
                <Tooltip content={<TrafficTooltip />} cursor={{ fill: 'rgba(255,255,255,0.04)' }} />
                <Bar dataKey="score" radius={[0, 5, 5, 0]} barSize={18}>
                  {chartData.map((d) => (
                    <Cell key={d.ip} fill={d.classification === 'abnormal' ? SEVERITY_HEX.critical : SEVERITY_HEX.low} />
                  ))}
                  <LabelList dataKey="score" position="right" formatter={(v: number) => `${v}%`} style={{ fill: 'var(--text-1)', fontSize: 11 }} />
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}
      </Card>

      <Card title="트래픽 상세 분석" subtitle="확률 산출 근거 · 분류는 임계값 기반 추정(ASSESS)" bodyClassName="">
        {traffic.length === 0 ? (
          <EmptyState title="데이터 없음" />
        ) : (
          <div style={{ maxHeight: 420, overflowY: 'auto' }}>
            <table className="tbl">
              <thead>
                <tr>
                  <th style={{ width: 130 }}>출발지 IP</th>
                  <th style={{ width: 90 }}>분류</th>
                  <th style={{ width: 110 }}>이상 확률</th>
                  <th style={{ width: 70 }}>요청</th>
                  <th style={{ width: 80 }}>오류율</th>
                  <th style={{ width: 90 }}>전송량</th>
                  <th>산출 근거</th>
                </tr>
              </thead>
              <tbody>
                {traffic.map((t) => (
                  <tr key={t.id}>
                    <td className="mono">{t.sourceIp}</td>
                    <td>
                      <span className={`badge ${t.classification === 'abnormal' ? 'badge-critical' : 'badge-low'}`}>
                        {t.classification === 'abnormal' ? '비정상' : '정상'}
                      </span>
                    </td>
                    <td>
                      <div className="row" style={{ gap: 6 }}>
                        <div style={{ flex: 1, height: 6, background: 'var(--bg-3)', borderRadius: 3, overflow: 'hidden' }}>
                          <div style={{ width: `${t.anomalyScore * 100}%`, height: '100%', background: t.classification === 'abnormal' ? SEVERITY_HEX.critical : SEVERITY_HEX.low }} />
                        </div>
                        <span className="mono text-xs" style={{ width: 38 }}>{pct(t.anomalyScore)}</span>
                      </div>
                    </td>
                    <td className="mono">{t.requests}</td>
                    <td className="mono">{pct(t.errorRate)}</td>
                    <td className="mono text-xs">{formatBytes(t.bytes)}</td>
                    <td className="text-xs muted">
                      {t.reasons.join(' · ')} <ConfidenceTag kind={t.confidence} />
                    </td>
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
