import type { Severity } from '@/types';

// =====================================================================
// MITRE ATT&CK 탐지 시그니처 DB (REQ-F-002, REQ-F-003)
// 로그 패턴 → 이상행위 카테고리 → ATT&CK 전술/기법 → 관련 CVE 매핑.
// 로컬 규칙 기반(오프라인). 근거(evidence) 기반 제시.
//
// 출처/검증: 모든 기법 ID·명칭·전술, 전술 ID(TA####)는
//   MITRE ATT&CK Enterprise 공식(https://attack.mitre.org) 기준으로
//   2026-06-21 교차검증 완료. 각 기법 레퍼런스 URL 은 techniqueUrl() 로 생성.
// =====================================================================

export interface AttackTactic {
  id: string; // TAxxxx
  name: string;
  /** kill-chain 순서 (타임라인/흐름도 정렬용) */
  order: number;
}

export const TACTICS: Record<string, AttackTactic> = {
  TA0043: { id: 'TA0043', name: 'Reconnaissance', order: 1 },
  TA0001: { id: 'TA0001', name: 'Initial Access', order: 2 },
  TA0002: { id: 'TA0002', name: 'Execution', order: 3 },
  TA0003: { id: 'TA0003', name: 'Persistence', order: 4 },
  TA0004: { id: 'TA0004', name: 'Privilege Escalation', order: 5 },
  TA0005: { id: 'TA0005', name: 'Defense Evasion', order: 6 },
  TA0006: { id: 'TA0006', name: 'Credential Access', order: 7 },
  TA0007: { id: 'TA0007', name: 'Discovery', order: 8 },
  TA0008: { id: 'TA0008', name: 'Lateral Movement', order: 9 },
  TA0009: { id: 'TA0009', name: 'Collection', order: 10 },
  TA0011: { id: 'TA0011', name: 'Command and Control', order: 11 },
  TA0010: { id: 'TA0010', name: 'Exfiltration', order: 12 },
  TA0040: { id: 'TA0040', name: 'Impact', order: 13 },
};

export interface DetectionSignature {
  sigId: string;
  category: string; // 이상행위 분류명
  description: string;
  /** 하나라도 매칭되면 탐지 */
  patterns: RegExp[];
  techniqueId: string;
  techniqueName: string;
  tacticId: keyof typeof TACTICS;
  severity: Severity;
  cveIds: string[];
}

const T = (id: string) => `https://attack.mitre.org/techniques/${id.replace('.', '/')}/`;
export const techniqueUrl = T;

export const SIGNATURES: DetectionSignature[] = [
  // --- Reconnaissance ---
  {
    sigId: 'recon-scanner',
    category: '스캐너 / 자동화 도구 탐지',
    description: '알려진 취약점 스캐너 User-Agent 또는 도구 시그니처가 관측됨.',
    patterns: [/sqlmap/i, /nikto/i, /nmap/i, /masscan/i, /dirbuster/i, /gobuster/i, /wpscan/i, /acunetix/i, /nessus/i, /\bzgrab\b/i],
    techniqueId: 'T1595',
    techniqueName: 'Active Scanning',
    tacticId: 'TA0043',
    severity: 'medium',
    cveIds: [],
  },
  {
    sigId: 'recon-enum',
    category: '디렉터리/자원 열거',
    description: '존재하지 않는 경로에 대한 반복적 404 또는 관리자 경로 탐색.',
    patterns: [/\/(admin|wp-admin|phpmyadmin|\.git|\.env|backup|config)\b/i, /\/(login|administrator)\/?\s/i],
    techniqueId: 'T1595.003',
    techniqueName: 'Wordlist Scanning',
    tacticId: 'TA0043',
    severity: 'low',
    cveIds: [],
  },

  // --- Initial Access / Exploit ---
  {
    sigId: 'sqli',
    category: 'SQL 인젝션',
    description: "SQL 구문 조작 시도 (UNION SELECT, OR 1=1, 주석 등) 가 요청에 포함됨.",
    patterns: [
      /union\s+select/i,
      /'\s*or\s*'?1'?\s*=\s*'?1/i,
      /\b(select|insert|update|delete)\b.+\bfrom\b/i,
      /information_schema/i,
      /sleep\(\d+\)/i,
      /benchmark\(/i,
      /--\s|;--/,
    ],
    techniqueId: 'T1190',
    techniqueName: 'Exploit Public-Facing Application',
    tacticId: 'TA0001',
    severity: 'high',
    cveIds: ['CVE-2017-9841'],
  },
  {
    sigId: 'xss',
    category: 'XSS (크로스사이트 스크립팅)',
    description: '스크립트 삽입 패턴(<script>, onerror=, javascript:) 이 요청 파라미터에 존재.',
    patterns: [/<script\b/i, /onerror\s*=/i, /onload\s*=/i, /javascript:/i, /document\.cookie/i, /%3cscript/i],
    techniqueId: 'T1059.007',
    techniqueName: 'JavaScript',
    tacticId: 'TA0002',
    severity: 'medium',
    cveIds: [],
  },
  {
    sigId: 'path-traversal',
    category: '경로 탐색 / LFI',
    description: '디렉터리 상위 이동(../) 또는 민감 파일 접근 시도.',
    patterns: [/\.\.[\\/]\.\./, /\/etc\/passwd/i, /\/etc\/shadow/i, /boot\.ini/i, /win\.ini/i, /%2e%2e%2f/i, /\.\.%2f/i],
    techniqueId: 'T1083',
    techniqueName: 'File and Directory Discovery',
    tacticId: 'TA0007',
    severity: 'high',
    cveIds: [],
  },
  {
    sigId: 'log4shell',
    category: 'Log4Shell (JNDI 인젝션)',
    description: 'Log4j JNDI 룩업 페이로드(${jndi:ldap://...}) 가 관측됨.',
    patterns: [/\$\{jndi:(ldap|ldaps|rmi|dns|nis|iiop|corba|nds|http)/i, /\$\{.*lower:.*j.*n.*d.*i/i],
    techniqueId: 'T1190',
    techniqueName: 'Exploit Public-Facing Application',
    tacticId: 'TA0001',
    severity: 'critical',
    cveIds: ['CVE-2021-44228', 'CVE-2021-45046'],
  },
  {
    sigId: 'cmd-injection',
    category: '명령어 인젝션',
    description: 'OS 명령 주입 패턴(; | && 와 whoami/cat/wget 등) 탐지.',
    patterns: [/;\s*(cat|whoami|id|uname|wget|curl|nc|bash|sh)\b/i, /\|\s*(whoami|id|nc|bash)\b/i, /\$\(.*\)/, /`[^`]+`/, /&&\s*(curl|wget)\b/i],
    techniqueId: 'T1059',
    techniqueName: 'Command and Scripting Interpreter',
    tacticId: 'TA0002',
    severity: 'high',
    cveIds: [],
  },

  // --- Credential Access ---
  {
    sigId: 'brute-force',
    category: '무차별 대입 / 인증 실패',
    description: '동일 출처의 반복적 로그인 실패 — 무차별 대입 정황.',
    patterns: [
      /failed\s+(password|login|logon)/i,
      /authentication\s+fail/i,
      /invalid\s+(user|credentials|password)/i,
      /login\s+failed/i,
      /\b(401|403)\b.*\/(login|signin|auth|admin)/i,
      /로그인\s*실패/,
      /event\s*id[:=\s]*4625/i,
    ],
    techniqueId: 'T1110',
    techniqueName: 'Brute Force',
    tacticId: 'TA0006',
    severity: 'high',
    cveIds: [],
  },
  {
    sigId: 'cred-dump',
    category: '자격증명 덤프',
    description: 'LSASS 접근 / mimikatz / SAM 추출 등 자격증명 탈취 정황.',
    patterns: [/mimikatz/i, /lsass\.exe/i, /sekurlsa/i, /\bsamdump\b/i, /reg\s+save\s+hklm\\sam/i, /procdump.*lsass/i],
    techniqueId: 'T1003',
    techniqueName: 'OS Credential Dumping',
    tacticId: 'TA0006',
    severity: 'critical',
    cveIds: [],
  },

  // --- Execution / Persistence ---
  {
    sigId: 'powershell-enc',
    category: '난독화 PowerShell 실행',
    description: 'Base64 인코딩/숨김 옵션을 사용한 PowerShell 실행.',
    patterns: [/powershell.*-enc(odedcommand)?\b/i, /powershell.*-nop(rofile)?\b.*-w(indowstyle)?\s+hidden/i, /iex\s*\(/i, /downloadstring/i, /frombase64string/i],
    techniqueId: 'T1059.001',
    techniqueName: 'PowerShell',
    tacticId: 'TA0002',
    severity: 'high',
    cveIds: [],
  },
  {
    sigId: 'webshell',
    category: '웹쉘 업로드/실행',
    description: '업로드된 스크립트(.php/.jsp/.asp)에 명령 실행 함수 포함.',
    patterns: [/(eval|system|exec|passthru|shell_exec|assert)\s*\(\s*\$?_(GET|POST|REQUEST)/i, /cmd\.(jsp|aspx?)/i, /c99|r57|wso\s*shell/i, /\.(php|jsp|aspx?)\?(cmd|exec)=/i],
    techniqueId: 'T1505.003',
    techniqueName: 'Web Shell',
    tacticId: 'TA0003',
    severity: 'critical',
    cveIds: [],
  },
  {
    sigId: 'persistence-reg',
    category: '레지스트리 자동실행 등록',
    description: 'Run 키 등 자동실행 위치에 항목 추가.',
    patterns: [/reg\s+add.*\\(current)?version\\run/i, /schtasks\s+\/create/i, /new-scheduledtask/i, /\\startup\\/i],
    techniqueId: 'T1547.001',
    techniqueName: 'Registry Run Keys / Startup Folder',
    tacticId: 'TA0003',
    severity: 'high',
    cveIds: [],
  },

  // --- Privilege Escalation ---
  {
    sigId: 'privesc',
    category: '권한 상승 시도',
    description: 'sudo/runas/토큰 조작 등 권한 상승 정황.',
    patterns: [/\bsudo\s+(su|-i|bash)/i, /runas\s+\/user:administrator/i, /getsystem/i, /\bsedebugprivilege\b/i, /\b(privilege escalat)/i],
    techniqueId: 'T1068',
    techniqueName: 'Exploitation for Privilege Escalation',
    tacticId: 'TA0004',
    severity: 'high',
    cveIds: [],
  },

  // --- Defense Evasion ---
  {
    sigId: 'log-clear',
    category: '로그 삭제 / 흔적 제거',
    description: '이벤트 로그 삭제(wevtutil cl) 또는 히스토리 삭제.',
    patterns: [/wevtutil\s+cl/i, /clear-eventlog/i, /event\s*id[:=\s]*1102/i, /로그\s*(삭제|초기화)/, /history\s+-c/i, /del\s+.*\.evtx/i],
    techniqueId: 'T1070.001',
    techniqueName: 'Clear Windows Event Logs',
    tacticId: 'TA0005',
    severity: 'high',
    cveIds: [],
  },

  // --- Lateral Movement ---
  {
    sigId: 'lateral',
    category: '내부 확산 (Lateral Movement)',
    description: 'PsExec/WMIC/원격 SMB 등을 통한 측면 이동.',
    patterns: [/psexec/i, /\bwmic\s+\/node:/i, /\\\\[\w.-]+\\(admin\$|c\$|ipc\$)/i, /\bwinrm\b/i, /enter-pssession/i],
    techniqueId: 'T1021',
    techniqueName: 'Remote Services',
    tacticId: 'TA0008',
    severity: 'high',
    cveIds: [],
  },

  // --- Command and Control ---
  {
    sigId: 'c2-beacon',
    category: 'C2 비콘 / 의심 통신',
    description: '주기적 비콘 또는 알려진 C2 도구의 통신 패턴.',
    patterns: [/cobaltstrike/i, /\/(submit|beacon|gate)\.php/i, /metasploit/i, /meterpreter/i, /\buser-agent:\s*$/i],
    techniqueId: 'T1071.001',
    techniqueName: 'Web Protocols',
    tacticId: 'TA0011',
    severity: 'high',
    cveIds: [],
  },

  // --- Exfiltration ---
  {
    sigId: 'exfil',
    category: '데이터 유출 정황',
    description: '대용량 외부 전송 또는 압축 후 업로드 정황.',
    patterns: [/\b(curl|wget|invoke-webrequest)\b.*(post|--upload|-T)\b/i, /\.(zip|rar|7z|tar\.gz)\b.*(upload|exfil|send)/i, /scp\s+.*@/i],
    techniqueId: 'T1041',
    techniqueName: 'Exfiltration Over C2 Channel',
    tacticId: 'TA0010',
    severity: 'high',
    cveIds: [],
  },

  // --- Impact ---
  {
    sigId: 'ransomware',
    category: '랜섬웨어 / 데이터 파괴',
    description: '대량 파일 암호화 확장자/랜섬노트 정황.',
    patterns: [/\.(locked|encrypted|crypt|wcry|wncry|locky)\b/i, /ransom/i, /readme.*decrypt/i, /vssadmin\s+delete\s+shadows/i, /bcdedit.*recoveryenabled\s+no/i],
    techniqueId: 'T1486',
    techniqueName: 'Data Encrypted for Impact',
    tacticId: 'TA0040',
    severity: 'critical',
    cveIds: [],
  },
];

export function tacticOrder(tacticId: string): number {
  return TACTICS[tacticId]?.order ?? 99;
}

export function tacticName(tacticId: string): string {
  return TACTICS[tacticId]?.name ?? tacticId;
}
