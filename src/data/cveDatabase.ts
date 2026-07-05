import type { Severity } from '@/types';

// =====================================================================
// CVE 참조 DB (REQ-F-002) — 시그니처가 참조하는 알려진 취약점.
// cvss/severity 는 NVD 공개 정보 기준의 정적 스냅샷.
//
// 출처/검증: 모든 CVE 의 CVSS v3.1 base score·severity·요약은
//   NVD 공식(https://nvd.nist.gov/vuln/detail/<CVE-ID>) 기준으로
//   2026-06-21 교차검증 완료. (예: Log4Shell 10.0, PHPUnit RCE 9.8 등)
// =====================================================================

export interface CveEntry {
  id: string;
  description: string;
  cvss: number;
  severity: Severity;
  /** 추가 직접 탐지 패턴 (로그 본문에서 직접 매칭) */
  patterns?: RegExp[];
}

export const CVE_DB: Record<string, CveEntry> = {
  'CVE-2021-44228': {
    id: 'CVE-2021-44228',
    description: 'Apache Log4j2 JNDI 원격코드실행 (Log4Shell). 신뢰되지 않은 입력의 JNDI 룩업으로 RCE 가능.',
    cvss: 10.0,
    severity: 'critical',
    patterns: [/\$\{jndi:/i, /log4j/i],
  },
  'CVE-2021-45046': {
    id: 'CVE-2021-45046',
    description: 'Apache Log4j2 불완전 패치 후속 취약점. 특정 비기본 설정에서 RCE/DoS 가능.',
    cvss: 9.0,
    severity: 'critical',
  },
  'CVE-2017-9841': {
    id: 'CVE-2017-9841',
    description: 'PHPUnit eval-stdin.php 원격코드실행. 노출된 PHPUnit 경로 통한 임의 PHP 실행.',
    cvss: 9.8,
    severity: 'critical',
    patterns: [/eval-stdin\.php/i, /phpunit/i],
  },
  'CVE-2014-6271': {
    id: 'CVE-2014-6271',
    description: 'Bash Shellshock — 환경변수 통한 임의 명령 실행.',
    cvss: 9.8,
    severity: 'critical',
    patterns: [/\(\)\s*\{\s*:;\s*\}/, /shellshock/i],
  },
  'CVE-2019-0708': {
    id: 'CVE-2019-0708',
    description: 'Windows RDP 원격코드실행 (BlueKeep). 인증 전 RCE.',
    cvss: 9.8,
    severity: 'critical',
    patterns: [/bluekeep/i, /\bms_t120\b/i],
  },
  'CVE-2020-1472': {
    id: 'CVE-2020-1472',
    description: 'Netlogon 권한상승 (Zerologon). 도메인 컨트롤러 장악 가능.',
    cvss: 10.0,
    severity: 'critical',
    patterns: [/zerologon/i, /netlogon/i],
  },
  'CVE-2021-34527': {
    id: 'CVE-2021-34527',
    description: 'Windows Print Spooler 원격코드실행 (PrintNightmare).',
    cvss: 8.8,
    severity: 'high',
    patterns: [/printnightmare/i, /spoolsv\.exe/i],
  },
};

export function cveEntry(id: string): CveEntry | undefined {
  return CVE_DB[id];
}

/** 로그 본문에서 CVE 직접 탐지용 패턴 목록 */
export function cvePatternList(): { id: string; pattern: RegExp }[] {
  const out: { id: string; pattern: RegExp }[] = [];
  for (const entry of Object.values(CVE_DB)) {
    for (const p of entry.patterns ?? []) {
      out.push({ id: entry.id, pattern: p });
    }
  }
  return out;
}
