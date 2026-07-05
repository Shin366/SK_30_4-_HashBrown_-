import type { AnalysisResult } from '@/types';
import { Card } from '@/components/common/Card';
import { StatCard } from '@/components/common/StatCard';
import { EmptyState } from '@/components/common/EmptyState';
import { pct } from '@/utils/format';
import { SEVERITY_HEX } from '@/utils/chart';

// =====================================================================
// 머신러닝 분석 패널 — 비지도 이상탐지(IF) · 지도 분류(NB) · 군집(K-Means)
// 규칙기반 엔진과 병행하는 하이브리드 ML 계층의 결과를 시각화한다.
// =====================================================================

function scoreColor(s: number): string {
  if (s >= 0.75) return SEVERITY_HEX.critical;
  if (s >= 0.65) return SEVERITY_HEX.high;
  return SEVERITY_HEX.medium;
}

export function MlPanel({ result }: { result: AnalysisResult }) {
  const ml = result.ml;
  if (!ml || !ml.trained) {
    return (
      <Card title="머신러닝 분석" subtitle="비지도 이상탐지 · 지도 분류 · 군집화">
        <EmptyState
          title="ML 분석 대상 아님"
          hint="표본 수가 부족하거나(로그 5건·MFT 8건 미만) 지원되지 않는 형식입니다. 로그/MFT를 업로드하면 브라우저 내에서 즉시 모델을 학습·추론합니다."
        />
      </Card>
    );
  }

  const attackRatio = ml.classification
    .filter((c) => c.label !== 'benign')
    .reduce((s, c) => s + c.ratio, 0);
  const maxClass = Math.max(1, ...ml.classification.map((c) => c.count));

  return (
    <div className="col" style={{ gap: 18 }}>
      <div className="grid grid-4">
        <StatCard label="ML 투입 표본" value={ml.sampleCount.toLocaleString()} hint={`특징 ${ml.featureNames.length}차원`} />
        <StatCard
          label={ml.target === 'mft' ? '위험 후보 (하이브리드)' : '위험 라인 (하이브리드)'}
          value={ml.metrics.flaggedCount.toLocaleString()}
          accent="critical"
          hint={`전체의 ${pct(ml.contamination)} · 트리 ${ml.metrics.iforestTrees}`}
        />
        <StatCard
          label={ml.target === 'log' ? 'NB 분류 정확도' : '군집 실루엣'}
          value={ml.target === 'log' ? pct(ml.metrics.nbAccuracy) : ml.metrics.silhouette.toFixed(2)}
          accent="info"
          hint={ml.target === 'log' ? `어휘 ${ml.metrics.nbVocab}개 학습` : `군집 ${ml.clusters.length}개`}
        />
        <StatCard
          label={ml.target === 'log' ? '공격성 분류 비중' : '엔트로피 플래그'}
          value={ml.target === 'log' ? pct(attackRatio) : String(ml.entropyFlags.length)}
          accent="high"
          hint={ml.target === 'log' ? 'benign 외 범주' : '난독/인코딩 후보'}
        />
      </div>

      <Card title="적용된 머신러닝 모델" subtitle="규칙기반 시그니처와 병행하는 하이브리드 계층 · 전량 브라우저 로컬 학습/추론">
        <div className="row" style={{ gap: 8, flexWrap: 'wrap', marginBottom: 12 }}>
          {ml.models.map((m) => (
            <span key={m} className="badge badge-info" style={{ fontSize: 12 }}>◆ {m}</span>
          ))}
        </div>
        <div className="text-xs muted" style={{ lineHeight: 1.6 }}>
          <b>입력 특징({ml.featureNames.length}):</b> {ml.featureNames.join(' · ')}
          <br />
          <b>재현성:</b> 난수 시드를 입력 데이터에서 유도 — 동일 파일은 항상 동일한 이상치·군집 결과를 산출합니다.
        </div>
      </Card>

      {ml.classification.length > 0 && (
        <Card title="공격 범주 분류 분포 (Multinomial Naive Bayes)" subtitle={`지도학습 · 5겹 교차검증 정확도 ${pct(ml.metrics.nbAccuracy)} · 저신뢰(<30%)는 정상으로 흡수`}>
          <div className="col" style={{ gap: 8 }}>
            {ml.classification.map((c) => (
              <div key={c.label} className="row" style={{ gap: 10, alignItems: 'center' }}>
                <span style={{ width: 130, fontSize: 13 }} className={c.label === 'benign' ? 'muted' : ''}>
                  {c.labelKo}
                </span>
                <div style={{ flex: 1, height: 16, background: 'var(--bg-3)', borderRadius: 4, overflow: 'hidden' }}>
                  <div
                    style={{
                      width: `${(c.count / maxClass) * 100}%`,
                      height: '100%',
                      background: c.label === 'benign' ? SEVERITY_HEX.low : SEVERITY_HEX.high,
                      borderRadius: 4,
                    }}
                  />
                </div>
                <span className="mono text-xs" style={{ width: 92, textAlign: 'right' }}>
                  {c.count.toLocaleString()} ({pct(c.ratio)})
                </span>
              </div>
            ))}
          </div>
        </Card>
      )}

      <Card
        title={ml.target === 'mft' ? '위험 후보 상세 (Isolation Forest + 위협신호 하이브리드)' : '위험 라인 상세 (Isolation Forest + NB 공격분류 하이브리드)'}
        subtitle={
          ml.target === 'mft'
            ? '위험 점수 = 위협신호(의심위치·이중확장자·삭제·실행확장자·타임스톰프)와 IF 통계이상을 노이즈-OR 결합 · 지표가 겹칠수록 1에 근접 · 점수↑=위험 · 동일 프로파일은 대표 1건으로 접음(외 N건)'
            : '위험 점수 = IF 통계이상 + NB 공격분류 신뢰도 + 엔트로피를 노이즈-OR 결합 · 통계적으로 튀고 공격으로도 분류될수록 1에 근접 · 점수↑=위험 · 동일 프로파일은 대표 1건으로 접음(외 N건)'
        }
      >
        {ml.anomalies.length === 0 ? (
          <EmptyState title="이상치 없음" hint="설정 임계값 이상으로 표시된 표본이 없습니다." />
        ) : (
          <div style={{ maxHeight: 420, overflowY: 'auto' }}>
            <table className="tbl">
              <thead>
                <tr>
                  <th style={{ width: 150 }}>대상</th>
                  <th style={{ width: 130 }}>이상 점수</th>
                  <th style={{ width: 220 }}>기여 특징(근거)</th>
                  <th>스니펫</th>
                </tr>
              </thead>
              <tbody>
                {ml.anomalies.map((a) => (
                  <tr key={a.id}>
                    <td className="mono text-xs">
                      {a.ref}
                      {a.dupes ? (
                        <div style={{ marginTop: 3 }}>
                          <span className="badge badge-medium" style={{ fontSize: 10 }}>외 {a.dupes.toLocaleString()}건 유사</span>
                        </div>
                      ) : null}
                    </td>
                    <td>
                      <div className="row" style={{ gap: 6 }}>
                        <div style={{ flex: 1, height: 6, background: 'var(--bg-3)', borderRadius: 3, overflow: 'hidden' }}>
                          <div style={{ width: `${a.score * 100}%`, height: '100%', background: scoreColor(a.score) }} />
                        </div>
                        <span className="mono text-xs" style={{ width: 48 }}>{a.score.toFixed(3)}</span>
                      </div>
                    </td>
                    <td className="text-xs">
                      {a.reasons.length ? (
                        a.reasons.map((r) => (
                          <span key={r} className="badge badge-high" style={{ fontSize: 10.5, marginRight: 4, marginBottom: 3, display: 'inline-block' }}>{r}</span>
                        ))
                      ) : (
                        <span className="muted">복합 요인</span>
                      )}
                    </td>
                    <td className="text-xs muted mono">
                      <div
                        title={a.snippet}
                        style={{
                          wordBreak: 'break-all',
                          display: '-webkit-box',
                          WebkitLineClamp: 2,
                          WebkitBoxOrient: 'vertical',
                          overflow: 'hidden',
                          lineHeight: 1.4,
                        }}
                      >
                        {a.snippet}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <div className="grid grid-2" style={{ gap: 18 }}>
        <Card title="행위 군집 (K-Means)" subtitle={`TF-IDF/특징 벡터 군집화 · 실루엣 ${ml.metrics.silhouette.toFixed(2)} · 소수 군집=드문 행위`}>
          {ml.clusters.length === 0 ? (
            <EmptyState title="군집 없음" />
          ) : (
            <div className="col" style={{ gap: 10 }}>
              {ml.clusters.map((c) => (
                <div key={c.id} className="card card-pad" style={{ background: 'var(--bg-1)' }}>
                  <div className="spread" style={{ marginBottom: 6 }}>
                    <span style={{ fontWeight: 650, fontSize: 13 }}>
                      군집 #{c.id}
                      {c.rare && <span className="badge badge-critical" style={{ marginLeft: 8, fontSize: 10 }}>희소</span>}
                    </span>
                    <span className="mono text-xs muted">{c.size.toLocaleString()}건 ({pct(c.ratio)})</span>
                  </div>
                  <div className="row" style={{ gap: 5, flexWrap: 'wrap' }}>
                    {c.keywords.length ? (
                      c.keywords.map((k) => (
                        <span key={k} className="badge badge-low" style={{ fontSize: 10.5 }}>{k}</span>
                      ))
                    ) : (
                      <span className="text-xs muted">대표 토큰 없음</span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </Card>

        <Card title="엔트로피 기반 난독/인코딩 탐지 (Shannon)" subtitle="고엔트로피 문자열 = Base64·암호화·패킹·DGA 후보">
          {ml.entropyFlags.length === 0 ? (
            <EmptyState title="고엔트로피 문자열 없음" hint="엔트로피 임계값(4.3 bit/char) 이상의 의심 토큰이 없습니다." />
          ) : (
            <div style={{ maxHeight: 360, overflowY: 'auto' }}>
              <table className="tbl">
                <thead>
                  <tr>
                    <th style={{ width: 90 }}>대상</th>
                    <th>문자열</th>
                    <th style={{ width: 70 }}>엔트로피</th>
                    <th style={{ width: 130 }}>판정</th>
                  </tr>
                </thead>
                <tbody>
                  {ml.entropyFlags.map((f, i) => (
                    <tr key={i}>
                      <td className="mono text-xs">{f.ref}</td>
                      <td className="mono text-xs" style={{ wordBreak: 'break-all' }}>{f.value}</td>
                      <td className="mono text-xs">{f.entropy}</td>
                      <td className="text-xs">
                        <span className="badge badge-medium" style={{ fontSize: 10.5 }}>{f.note}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>

      <Card title="ML 요약" subtitle="하이브리드 분석 결론">
        <p style={{ margin: 0, lineHeight: 1.7 }}>{ml.summary}</p>
      </Card>
    </div>
  );
}
