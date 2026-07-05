import { useState } from 'react';
import type { CSSProperties } from 'react';
import type { AnalysisResult, IOCType } from '@/types';
import { Card } from '@/components/common/Card';
import { SeverityBadge, ConfidenceTag } from '@/components/common/Badge';
import { EmptyState } from '@/components/common/EmptyState';
import { IconExternal } from '@/components/common/icons';
import { SEVERITY_HEX } from '@/utils/chart';
import { formatTimeShort } from '@/utils/format';

const IOC_LABELS: Record<IOCType, string> = {
  ip: 'IP',
  domain: '도메인',
  url: 'URL',
  'hash-md5': 'MD5',
  'hash-sha1': 'SHA1',
  'hash-sha256': 'SHA256',
  email: '이메일',
  cve: 'CVE',
  filepath: '파일경로',
};

const delay = (ms: number): CSSProperties => ({ animationDelay: `${ms}ms` });
const accent = (hex: string) => ({ '--kpi-accent': hex } as CSSProperties);

export function ThreatMappingPanel({ result }: { result: AnalysisResult }) {
  const [iocType, setIocType] = useState<IOCType | 'all'>('all');
  const iocTypes = Array.from(new Set(result.iocs.map((i) => i.type)));
  const iocs = result.iocs.filter((i) => (iocType === 'all' ? true : i.type === iocType));

  return (
    <div className="col" style={{ gap: 18 }}>
      {/* ATT&CK 기법 */}
      <Card className="reveal" style={delay(0)} title="MITRE ATT&CK 기법 매핑" subtitle={`${result.techniques.length}개 기법 · kill-chain 정렬 · 근거 동반`}>
        {result.techniques.length === 0 ? (
          <EmptyState title="매핑된 ATT&CK 기법 없음" hint="탐지된 공격 시그니처가 없습니다." />
        ) : (
          <div className="grid" style={{ gridTemplateColumns: 'repeat(auto-fill, minmax(min(100%, 330px), 1fr))', gap: 14 }}>
            {result.techniques.map((t, i) => (
              <div
                key={t.id}
                className="reveal"
                style={{
                  ...delay(60 + i * 55),
                  ...accent(SEVERITY_HEX[t.severity]),
                  background: 'var(--bg-1)',
                  border: '1px solid var(--surface-border)',
                  borderTop: '3px solid var(--kpi-accent)',
                  borderRadius: 'var(--r-md)',
                  padding: 15,
                }}
              >
                <div className="spread" style={{ marginBottom: 7 }}>
                  <span className="row" style={{ gap: 8 }}>
                    <span className="mono" style={{ color: 'var(--accent)', fontWeight: 600, fontSize: 12.5 }}>{t.id}</span>
                    <a href={t.url} target="_blank" rel="noreferrer" className="row text-xs muted" style={{ gap: 3 }}>ATT&CK <IconExternal /></a>
                  </span>
                  <SeverityBadge severity={t.severity} />
                </div>
                <div style={{ fontFamily: 'var(--font-display)', fontWeight: 600, fontSize: 15, marginBottom: 3 }}>{t.name}</div>
                <div className="row text-xs muted mb-8" style={{ gap: 6 }}>
                  <span className="pill">{t.tacticId}</span>{t.tactic}
                </div>
                <div className="text-sm muted" style={{ lineHeight: 1.5, marginBottom: 8 }}>{t.description}</div>
                {t.relatedCves.length > 0 && (
                  <div className="row wrap" style={{ gap: 4, marginBottom: 8 }}>
                    {t.relatedCves.map((c) => (
                      <span key={c} className="badge badge-critical">{c}</span>
                    ))}
                  </div>
                )}
                <details>
                  <summary className="text-xs" style={{ cursor: 'pointer', color: 'var(--text-2)' }}>
                    근거 {t.matchedEvidence.length}건 <ConfidenceTag kind={t.confidence} />
                  </summary>
                  <div className="col" style={{ gap: 3, marginTop: 6 }}>
                    {t.matchedEvidence.map((e, j) => (
                      <code key={j} className="mono text-xs" style={{ color: 'var(--text-2)', wordBreak: 'break-all' }}>{e}</code>
                    ))}
                  </div>
                </details>
              </div>
            ))}
          </div>
        )}
      </Card>

      {/* 관련 CVE — 큰 CVSS 카드로 전면 배치 */}
      <Card className="reveal" style={delay(120)} title="관련 CVE" subtitle={`${result.cves.length}건 · CVSS 순 · NVD 레퍼런스`}>
        {result.cves.length === 0 ? (
          <EmptyState title="연관 CVE 없음" hint="탐지된 시그니처에 매핑된 알려진 취약점이 없습니다." />
        ) : (
          <div className="grid" style={{ gridTemplateColumns: 'repeat(auto-fill, minmax(min(100%, 300px), 1fr))', gap: 14 }}>
            {result.cves.map((c, i) => (
              <div
                key={c.id}
                className="reveal"
                style={{
                  ...delay(180 + i * 55),
                  ...accent(SEVERITY_HEX[c.severity]),
                  background: 'var(--bg-1)',
                  border: '1px solid var(--surface-border)',
                  borderLeft: '4px solid var(--kpi-accent)',
                  borderRadius: 'var(--r-md)',
                  padding: 15,
                }}
              >
                <div className="row" style={{ gap: 14, alignItems: 'flex-start' }}>
                  <div className="col" style={{ alignItems: 'center', gap: 1, flexShrink: 0, width: 56 }}>
                    <span style={{ fontFamily: 'var(--font-display)', fontWeight: 700, fontSize: 26, lineHeight: 1, color: 'var(--kpi-accent)' }}>{c.cvss.toFixed(1)}</span>
                    <span className="eyebrow" style={{ fontSize: 8.5 }}>CVSS</span>
                  </div>
                  <div className="col" style={{ gap: 5, flex: 1, minWidth: 0 }}>
                    <div className="spread">
                      <a href={c.url} target="_blank" rel="noreferrer" className="row mono" style={{ gap: 4, fontWeight: 600, fontSize: 12.5 }}>
                        {c.id} <IconExternal />
                      </a>
                      <SeverityBadge severity={c.severity} />
                    </div>
                    <div className="text-sm muted" style={{ lineHeight: 1.5 }}>{c.description}</div>
                    {c.matchedTechniques.length > 0 && (
                      <div className="row wrap text-xs muted" style={{ gap: 4, marginTop: 2 }}>
                        연관 기법: {c.matchedTechniques.map((m) => <span key={m} className="pill mono">{m}</span>)}
                      </div>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>

      {/* IOC 테이블 */}
      <Card className="reveal" style={delay(240)} title="추출된 IOC" subtitle={`${result.iocs.length}종 · VirusTotal/NVD 참고링크`} bodyClassName="">
        <div className="row wrap" style={{ gap: 6, padding: '12px 20px', borderBottom: '1px solid var(--surface-border)' }}>
          <button className="pill" onClick={() => setIocType('all')} style={pillSel(iocType === 'all')}>전체 ({result.iocs.length})</button>
          {iocTypes.map((tp) => (
            <button key={tp} className="pill" onClick={() => setIocType(tp)} style={pillSel(iocType === tp)}>
              {IOC_LABELS[tp]} ({result.iocs.filter((i) => i.type === tp).length})
            </button>
          ))}
        </div>
        {iocs.length === 0 ? (
          <EmptyState title="추출된 IOC 없음" />
        ) : (
          <div style={{ maxHeight: 420, overflowY: 'auto' }}>
            <table className="tbl">
              <thead>
                <tr>
                  <th style={{ width: 104 }}>유형</th>
                  <th>값</th>
                  <th style={{ width: 56 }}>빈도</th>
                  <th style={{ width: 72 }}>심각도</th>
                  <th style={{ width: 48 }}>조회</th>
                </tr>
              </thead>
              <tbody>
                {iocs.map((i) => (
                  <tr key={i.id}>
                    <td><span className="pill text-xs" style={{ whiteSpace: 'nowrap' }}>{IOC_LABELS[i.type]}</span></td>
                    <td className="mono text-xs" style={{ wordBreak: 'break-all' }}>{i.value}</td>
                    <td className="mono num">{i.count}</td>
                    <td><SeverityBadge severity={i.severity} /></td>
                    <td>
                      <a href={i.vtReference} target="_blank" rel="noreferrer" title="VirusTotal/NVD 조회"><IconExternal /></a>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <span className="text-xs dim" style={{ paddingLeft: 4 }}>
        ※ {formatTimeShort(result.parsedAt)} 기준 로컬 규칙 DB 매핑. CVSS/심각도는 정적 스냅샷이며 최신 NVD 확인 권장.
      </span>
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
