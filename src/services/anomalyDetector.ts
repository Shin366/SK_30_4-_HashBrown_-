import type { AnomalyEvent, LogEntry } from '@/types';
import { SIGNATURES } from '@/data/mitreAttack';
import { makeId, truncate } from '@/utils/format';

// =====================================================================
// 이상징후 탐지 (REQ-F-001)
// 시그니처 기반 매칭 → AnomalyEvent. 매칭은 사실(fact),
// 분류명/심각도는 규칙 기반 추정이지만 근거(evidence)를 함께 제시.
// =====================================================================

export function detectAnomalies(logs: LogEntry[]): AnomalyEvent[] {
  const anomalies: AnomalyEvent[] = [];

  for (const log of logs) {
    const haystack = log.raw || log.message;
    for (const sig of SIGNATURES) {
      const hit = sig.patterns.some((p) => p.test(haystack));
      if (hit) {
        anomalies.push({
          id: makeId('anom'),
          logId: log.id,
          lineNumber: log.lineNumber,
          timestamp: log.timestamp,
          category: sig.category,
          description: sig.description,
          severity: sig.severity,
          // 패턴 직접 매칭은 관측된 사실
          confidence: 'fact',
          evidence: truncate(haystack.trim(), 240),
          sourceIp: log.sourceIp,
        });
      }
    }
  }

  // 행위 기반(빈도) 탐지: 동일 IP 의 다수 4xx/5xx → 무차별 대입/스캐닝 추정
  const byIp = new Map<string, LogEntry[]>();
  for (const log of logs) {
    if (!log.sourceIp) continue;
    const arr = byIp.get(log.sourceIp) ?? [];
    arr.push(log);
    byIp.set(log.sourceIp, arr);
  }

  for (const [ip, entries] of byIp) {
    const failures = entries.filter((e) => e.statusCode && (e.statusCode === 401 || e.statusCode === 403));
    if (failures.length >= 5) {
      const first = failures[0];
      anomalies.push({
        id: makeId('anom'),
        logId: first.id,
        lineNumber: first.lineNumber,
        timestamp: first.timestamp,
        category: '반복 인증 실패 (행위 기반)',
        description: `${ip} 에서 ${failures.length}건의 401/403 응답 관측 — 무차별 대입/권한 우회 시도로 추정.`,
        severity: failures.length >= 20 ? 'high' : 'medium',
        // 빈도 기반 해석은 추정(assessment)
        confidence: 'assessment',
        evidence: `${ip}: ${failures.length}× (401/403)`,
        sourceIp: ip,
      });
    }
    const notFound = entries.filter((e) => e.statusCode === 404);
    if (notFound.length >= 15) {
      const first = notFound[0];
      anomalies.push({
        id: makeId('anom'),
        logId: first.id,
        lineNumber: first.lineNumber,
        timestamp: first.timestamp,
        category: '자원 열거 (행위 기반)',
        description: `${ip} 에서 ${notFound.length}건의 404 — 디렉터리/파일 스캐닝으로 추정.`,
        severity: 'medium',
        confidence: 'assessment',
        evidence: `${ip}: ${notFound.length}× (404)`,
        sourceIp: ip,
      });
    }
  }

  return anomalies;
}
