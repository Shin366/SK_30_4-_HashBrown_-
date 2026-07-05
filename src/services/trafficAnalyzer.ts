import type { LogEntry, TrafficScore } from '@/types';
import { isPrivateIp } from '@/data/iocPatterns';
import { makeId } from '@/utils/format';

// =====================================================================
// 트래픽 정상/비정상 확률 분석 (REQ-F-004)
// 출발지 IP 별로 다수 특징을 가중합한 이상 확률(0..1) 산출.
// 수치 = 사실 기반 집계, 분류(정상/비정상) = 임계값 기반 추정.
// =====================================================================

const ABNORMAL_THRESHOLD = 0.5;

function clamp01(n: number): number {
  return Math.max(0, Math.min(1, n));
}

export function analyzeTraffic(logs: LogEntry[]): TrafficScore[] {
  const withIp = logs.filter((l) => l.sourceIp);
  if (withIp.length === 0) return [];

  const byIp = new Map<string, LogEntry[]>();
  for (const log of withIp) {
    const arr = byIp.get(log.sourceIp!) ?? [];
    arr.push(log);
    byIp.set(log.sourceIp!, arr);
  }

  const totalReq = withIp.length;
  const ipCount = byIp.size;
  const avgPerIp = totalReq / ipCount;

  const scores: TrafficScore[] = [];

  for (const [ip, entries] of byIp) {
    const requests = entries.length;
    const errors = entries.filter((e) => e.statusCode && e.statusCode >= 400).length;
    const errorRate = requests > 0 ? errors / requests : 0;
    const bytes = entries.reduce((s, e) => s + (e.bytes ?? 0), 0);

    // 특징(feature) 별 점수와 사유 누적
    const reasons: string[] = [];
    let score = 0;

    // 1) 요청 폭주 (평균 대비)
    const volRatio = avgPerIp > 0 ? requests / avgPerIp : 1;
    if (volRatio > 3) {
      score += 0.28;
      reasons.push(`요청량 평균 대비 ${volRatio.toFixed(1)}배`);
    } else if (volRatio > 1.8) {
      score += 0.12;
      reasons.push(`요청량 다소 높음 (평균 ${volRatio.toFixed(1)}배)`);
    }

    // 2) 오류율
    if (errorRate > 0.5) {
      score += 0.3;
      reasons.push(`오류율 ${(errorRate * 100).toFixed(0)}% (높음)`);
    } else if (errorRate > 0.25) {
      score += 0.15;
      reasons.push(`오류율 ${(errorRate * 100).toFixed(0)}%`);
    }

    // 3) 인증 실패(401/403) 비중
    const auth = entries.filter((e) => e.statusCode === 401 || e.statusCode === 403).length;
    if (auth >= 5) {
      score += 0.22;
      reasons.push(`인증거부 ${auth}건`);
    }

    // 4) URL 다양성(스캐닝 특성)
    const uniqueUrls = new Set(entries.map((e) => e.url).filter(Boolean)).size;
    if (uniqueUrls >= 20 && uniqueUrls / requests > 0.7) {
      score += 0.18;
      reasons.push(`고유 경로 ${uniqueUrls}개 (스캐닝 의심)`);
    }

    // 5) 스캐너/봇 User-Agent
    const ua = entries.map((e) => e.userAgent ?? '').join(' ');
    if (/sqlmap|nikto|nmap|masscan|curl|python-requests|go-http|bot|scan/i.test(ua)) {
      score += 0.2;
      reasons.push('자동화 도구/봇 User-Agent');
    }

    // 6) 외부 IP 가산 (사설망 제외)
    if (!isPrivateIp(ip) && score > 0) {
      score += 0.05;
    }

    score = clamp01(score);
    const classification = score >= ABNORMAL_THRESHOLD ? 'abnormal' : 'normal';
    if (reasons.length === 0) reasons.push('특이사항 없음');

    scores.push({
      id: makeId('traf'),
      sourceIp: ip,
      requests,
      anomalyScore: Number(score.toFixed(3)),
      classification,
      // 분류 라벨은 임계값 기반 추정
      confidence: 'assessment',
      reasons,
      bytes,
      errorRate: Number(errorRate.toFixed(3)),
    });
  }

  return scores.sort((a, b) => b.anomalyScore - a.anomalyScore);
}
