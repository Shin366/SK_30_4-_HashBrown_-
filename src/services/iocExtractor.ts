import type { IOC, IOCType, LogEntry, Severity } from '@/types';
import { IOC_PATTERNS, isPrivateIp, virusTotalUrl } from '@/data/iocPatterns';
import { makeId } from '@/utils/format';

// =====================================================================
// IOC 추출 (REQ-F-002)
// 로그 본문에서 IP/도메인/URL/해시/CVE/이메일/파일경로를 추출하고
// 빈도·최초/최종 관측시각·VirusTotal 참고링크를 집계한다.
// =====================================================================

// 해시 타입 우선순위: 긴 것부터 매칭하여 중복 카운트 방지
const HASH_ORDER: IOCType[] = ['hash-sha256', 'hash-sha1', 'hash-md5'];

function severityForIoc(type: IOCType, value: string): Severity {
  if (type === 'cve') return 'high';
  if (type.startsWith('hash')) return 'medium';
  if (type === 'ip') return isPrivateIp(value) ? 'info' : 'low';
  if (type === 'filepath') return 'medium';
  return 'low';
}

export function extractIocs(logs: LogEntry[]): IOC[] {
  const map = new Map<string, IOC>(); // key: type|value

  // 정규식은 라인마다 재컴파일하지 않고 한 번만 생성한다(대용량 파일 성능).
  // 재사용 시 각 텍스트 전에 lastIndex 를 리셋한다(/g exec 루프 상태 초기화).
  const compiled = IOC_PATTERNS.map((pat) => ({ pat, re: new RegExp(pat.regex.source, pat.regex.flags) }));

  for (const log of logs) {
    const text = log.raw || log.message;
    const consumedHashSpans: Array<[number, number]> = [];

    for (const { pat, re } of compiled) {
      re.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = re.exec(text)) !== null) {
        const value = m[0];
        const start = m.index;
        const end = start + value.length;

        // 해시: 더 긴 해시에 포함된 부분문자열 중복 제거
        if (pat.type.startsWith('hash')) {
          if (HASH_ORDER.indexOf(pat.type) > 0) {
            const overlap = consumedHashSpans.some(([s, e]) => start >= s && end <= e);
            if (overlap) continue;
          }
          consumedHashSpans.push([start, end]);
        }

        if (pat.isNoise?.(value)) continue;

        const key = `${pat.type}|${value.toLowerCase()}`;
        const existing = map.get(key);
        if (existing) {
          existing.count += 1;
          if (!existing.relatedLogIds.includes(log.id)) existing.relatedLogIds.push(log.id);
          if (log.timestamp) {
            if (!existing.firstSeen || log.timestamp < existing.firstSeen) existing.firstSeen = log.timestamp;
            if (!existing.lastSeen || log.timestamp > existing.lastSeen) existing.lastSeen = log.timestamp;
          }
        } else {
          map.set(key, {
            id: makeId('ioc'),
            type: pat.type,
            value,
            count: 1,
            firstSeen: log.timestamp,
            lastSeen: log.timestamp,
            severity: severityForIoc(pat.type, value),
            relatedLogIds: [log.id],
            vtReference: virusTotalUrl(pat.type, value),
          });
        }
      }
    }
  }

  return Array.from(map.values()).sort((a, b) => b.count - a.count);
}
