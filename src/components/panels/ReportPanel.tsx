import type { CSSProperties } from 'react';
import type { AnalysisResult } from '@/types';
import { Card } from '@/components/common/Card';
import { SeverityBadge } from '@/components/common/Badge';
import { IconDownload } from '@/components/common/icons';
import { downloadReport } from '@/services/reportExport';

const delay = (ms: number): CSSProperties => ({ animationDelay: `${ms}ms` });

export function ReportPanel({ result }: { result: AnalysisResult }) {
  const { report } = result;

  return (
    <div className="col" style={{ gap: 18 }}>
      <Card
        className="reveal"
        style={delay(0)}
        title="분석 가이드 보고서"
        subtitle={`엔진: ${report.engine === 'ai' ? '생성형 AI' : '로컬 규칙기반'} · 생성 ${new Date(report.generatedAt).toLocaleString('ko-KR')}`}
        actions={
          <button className="btn btn-primary" onClick={() => downloadReport(result)}>
            <IconDownload /> Word 문서 다운로드
          </button>
        }
      >
        <p style={{ margin: 0, color: 'var(--text-1)', lineHeight: 1.75, fontSize: 14.5 }}>{report.narrative}</p>
      </Card>

      {/* Fact vs Assessment (REQ-NF-002) */}
      <div className="grid grid-2" style={{ alignItems: 'stretch' }}>
        <Card className="reveal" style={delay(90)} title="사실 (Fact)" subtitle="관측·집계된 데이터">
          <div className="col" style={{ gap: 9 }}>
            {report.factsVsAssessments.facts.map((f, i) => (
              <div key={i} className="row" style={{ gap: 9, alignItems: 'flex-start' }}>
                <span className="tag-fact" style={{ marginTop: 2, flexShrink: 0 }}>FACT</span>
                <span className="text-sm" style={{ color: 'var(--text-1)', lineHeight: 1.55 }}>{f}</span>
              </div>
            ))}
          </div>
        </Card>
        <Card className="reveal" style={delay(150)} title="추정 (Assessment)" subtitle="분석가 검증 필요">
          <div className="col" style={{ gap: 9 }}>
            {report.factsVsAssessments.assessments.map((a, i) => (
              <div key={i} className="row" style={{ gap: 9, alignItems: 'flex-start' }}>
                <span className="tag-assessment" style={{ marginTop: 2, flexShrink: 0 }}>ASSESS</span>
                <span className="text-sm" style={{ color: 'var(--text-1)', lineHeight: 1.55 }}>{a}</span>
              </div>
            ))}
          </div>
        </Card>
      </div>

      {/* 단계별 가이드 */}
      <Card className="reveal" style={delay(210)} title="단계별 분석 가이드라인" subtitle="어떤 순서로 무엇을 분석할지 (REQ-F-005)">
        <div className="col" style={{ gap: 12 }}>
          {report.steps.map((s, i) => (
            <div
              key={s.step}
              className="reveal"
              style={{ ...delay(280 + i * 70), background: 'var(--bg-2)', border: '1px solid var(--surface-border)', borderRadius: 'var(--r-md)', padding: 16 }}
            >
              <div className="spread" style={{ marginBottom: 8 }}>
                <div className="row" style={{ gap: 11 }}>
                  <span
                    style={{
                      width: 30, height: 30, borderRadius: '50%',
                      background: 'var(--accent)', color: '#fff',
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                      fontFamily: 'var(--font-display)', fontWeight: 700, fontSize: 14, flexShrink: 0,
                    }}
                  >
                    {s.step}
                  </span>
                  <strong style={{ fontFamily: 'var(--font-display)', fontSize: 15.5 }}>{s.title}</strong>
                </div>
                <SeverityBadge severity={s.priority} />
              </div>
              <div className="text-sm muted" style={{ marginBottom: 10, paddingLeft: 41, lineHeight: 1.55 }}>{s.rationale}</div>
              <ul style={{ margin: 0, paddingLeft: 58 }}>
                {s.actions.map((a, j) => (
                  <li key={j} className="text-sm" style={{ color: 'var(--text-1)', marginBottom: 4 }}>{a}</li>
                ))}
              </ul>
              <div className="row wrap" style={{ gap: 4, paddingLeft: 41, marginTop: 10 }}>
                {s.relatedRequirements.map((r) => (
                  <span key={r} className="pill mono text-xs">{r}</span>
                ))}
              </div>
            </div>
          ))}
        </div>
      </Card>

      <div className="card card-pad reveal" style={{ ...delay(360), background: 'var(--accent-soft)', borderColor: 'var(--accent-line)' }}>
        <span className="text-sm" style={{ color: 'var(--text-1)' }}>
          ⚠ 본 보고서는 AI/규칙 기반 분석 <strong>보조 산출물</strong>입니다. 최종 판단은 분석가의 교차검증을
          병행해야 합니다. (REQ 제약사항 · REQ-NF-002)
        </span>
      </div>
    </div>
  );
}
