import type { IOCType } from '@/types';

// =====================================================================
// IOC 추출 정규식 패턴 (REQ-F-002)
// 로컬에서만 동작 — 외부 조회는 하지 않고, VirusTotal "참고 링크"만 생성.
// =====================================================================

export interface IocPattern {
  type: IOCType;
  label: string;
  regex: RegExp;
  /** 추출값이 노이즈인지 검사 (true 면 버림) */
  isNoise?: (value: string) => boolean;
}

// 사설/예약 IP 대역 — 외부 위협 IOC 에서 제외 후보로 표시
const PRIVATE_IP =
  /^(10\.|127\.|0\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.|255\.|22[4-9]\.|23\d\.)/;

export function isPrivateIp(ip: string): boolean {
  return PRIVATE_IP.test(ip);
}

export const IOC_PATTERNS: IocPattern[] = [
  {
    type: 'ip',
    label: 'IPv4 주소',
    regex: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g,
  },
  {
    type: 'hash-sha256',
    label: 'SHA-256 해시',
    regex: /\b[a-fA-F0-9]{64}\b/g,
  },
  {
    type: 'hash-sha1',
    label: 'SHA-1 해시',
    regex: /\b[a-fA-F0-9]{40}\b/g,
  },
  {
    type: 'hash-md5',
    label: 'MD5 해시',
    regex: /\b[a-fA-F0-9]{32}\b/g,
  },
  {
    type: 'cve',
    label: 'CVE 식별자',
    regex: /\bCVE-\d{4}-\d{4,7}\b/gi,
  },
  {
    type: 'email',
    label: '이메일',
    regex: /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g,
  },
  {
    type: 'url',
    label: 'URL',
    regex: /\bhttps?:\/\/[^\s"'<>]+/gi,
    // 정적 자원 URL(.png/.js/.css 등)은 IOC 노이즈이므로 제외. (도메인 패턴에
    // 붙어 있던 이 필터는 도메인 매치가 항상 TLD 로 끝나 확장자와 겹칠 수 없어
    // 사문화 상태였다 — 실제로 확장자가 나타나는 URL 패턴으로 옮겼다.)
    isNoise: (v) => /\.(png|jpg|jpeg|gif|css|js|svg|ico|woff2?)(\?|#|$)/i.test(v),
  },
  {
    type: 'domain',
    label: '도메인',
    regex: /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|ru|cn|kr|info|biz|xyz|top|cc|tk|gq)\b/gi,
  },
  {
    type: 'filepath',
    label: '파일 경로',
    regex: /\b[a-zA-Z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]+\.(?:exe|dll|ps1|bat|vbs|js|jar|sh|bin|scr)\b/gi,
  },
];

/** VirusTotal 참고용 조회 URL 생성 (REQ-F-001: "VirusTotal참고") */
export function virusTotalUrl(type: IOCType, value: string): string {
  const enc = encodeURIComponent(value);
  switch (type) {
    case 'ip':
      return `https://www.virustotal.com/gui/ip-address/${enc}`;
    case 'domain':
      return `https://www.virustotal.com/gui/domain/${enc}`;
    case 'url':
      return `https://www.virustotal.com/gui/search/${enc}`;
    case 'hash-md5':
    case 'hash-sha1':
    case 'hash-sha256':
      return `https://www.virustotal.com/gui/file/${enc}`;
    case 'cve':
      return `https://nvd.nist.gov/vuln/detail/${enc}`;
    default:
      return `https://www.virustotal.com/gui/search/${enc}`;
  }
}
