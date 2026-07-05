import type { Severity } from '@/types';

// =====================================================================
// MFT 포렌식 분석 규칙 (REQ-F-001, REQ-F-002)
// NTFS MFT 아티팩트 → 이상 파일 탐지 → ATT&CK 매핑.
//
// 매핑 기법은 모두 MITRE ATT&CK 공식(https://attack.mitre.org)
// 기준 2026-06-21 검증 완료.
// =====================================================================

export interface MftTechnique {
  id: string;
  name: string;
  tactic: string;
  tacticId: string;
}

// 검증된 MFT 관련 ATT&CK 기법
export const MFT_TECH = {
  timestomp: { id: 'T1070.006', name: 'Indicator Removal: Timestomp', tactic: 'Defense Evasion', tacticId: 'TA0005' },
  fileDeletion: { id: 'T1070.004', name: 'Indicator Removal: File Deletion', tactic: 'Defense Evasion', tacticId: 'TA0005' },
  ntfsAttr: { id: 'T1564.004', name: 'Hide Artifacts: NTFS File Attributes', tactic: 'Defense Evasion', tacticId: 'TA0005' },
  doubleExt: { id: 'T1036.007', name: 'Masquerading: Double File Extension', tactic: 'Defense Evasion', tacticId: 'TA0005' },
  masqName: { id: 'T1036.005', name: 'Masquerading: Match Legitimate Name or Location', tactic: 'Defense Evasion', tacticId: 'TA0005' },
  ingressTool: { id: 'T1105', name: 'Ingress Tool Transfer', tactic: 'Command and Control', tacticId: 'TA0011' },
  c2: { id: 'T1071.001', name: 'Application Layer Protocol: Web Protocols', tactic: 'Command and Control', tacticId: 'TA0011' },
  webShell: { id: 'T1505.003', name: 'Server Software Component: Web Shell', tactic: 'Persistence', tacticId: 'TA0003' },
  powershell: { id: 'T1059.001', name: 'Command and Scripting Interpreter: PowerShell', tactic: 'Execution', tacticId: 'TA0002' },
  credDump: { id: 'T1003', name: 'OS Credential Dumping', tactic: 'Credential Access', tacticId: 'TA0006' },
  localStaging: { id: 'T1074.001', name: 'Data Staged: Local Data Staging', tactic: 'Collection', tacticId: 'TA0009' },
} as const satisfies Record<string, MftTechnique>;

// 실행/스크립트 확장자
export const EXECUTABLE_EXT = new Set([
  'exe', 'dll', 'sys', 'scr', 'com', 'pif', 'cpl',
  'ps1', 'psm1', 'bat', 'cmd', 'vbs', 'vbe', 'js', 'jse', 'wsf', 'hta',
  'jar', 'msi', 'lnk',
]);

// 실행파일이 있으면 실제로 의심스러운 "고신호" 사용자 쓰기 경로만 포함.
// (ProgramData·AppData\Roaming 등은 정상 설치파일이 너무 많아 제외 — 오탐 방지)
// sev = 해당 위치 실행파일 기본 위험도. 순서대로 첫 매칭 사용(구체적 경로 우선).
export const SUSPICIOUS_DIRS: { re: RegExp; label: string; sev: Severity }[] = [
  // 실행파일이 있으면 매우 비정상인 위치 (스케줄러 폴더, 디버그, 복구 등)
  { re: /\/windows\/tasks\//, label: 'Windows\\Tasks', sev: 'high' },
  { re: /\/windows\/debug\//, label: 'Windows\\Debug', sev: 'high' },
  { re: /\/windows\/(fonts|help|addins|cursors|media)\//, label: 'Windows 비실행 폴더', sev: 'high' },
  { re: /\/recovery\//, label: 'Recovery', sev: 'medium' },
  { re: /(^|\/)intel\//, label: 'Intel(루트)', sev: 'medium' },
  // 사용자 쓰기 영역
  { re: /\/users\/[^/]+\/appdata\/local\/temp\//, label: '사용자 Temp', sev: 'high' },
  { re: /\/windows\/temp\//, label: 'Windows Temp', sev: 'high' },
  { re: /\/users\/[^/]+\/downloads\//, label: 'Downloads', sev: 'high' },
  { re: /\/\$recycle\.bin\//, label: '휴지통($Recycle.Bin)', sev: 'high' },
  { re: /\/users\/[^/]+\/desktop\//, label: '바탕화면', sev: 'medium' },
  { re: /\/users\/public\//, label: 'Public', sev: 'medium' },
  { re: /\/perflogs\//, label: 'PerfLogs', sev: 'medium' },
  { re: /(^|\/)(temp|tmp)\//, label: 'Temp', sev: 'medium' },
];

// 드라이브 루트 직속 실행/스크립트 (예: C:\evil.exe) — 매우 비정상
export const DRIVE_ROOT_EXE = /^\/[^/]+\.(exe|scr|bat|cmd|com|pif|ps1|vbs|js|hta|jar)$/i;

// MFT 경로 재구성 아티팩트: 중간 경로 요소가 "파일"(확장자 보유)인 경우.
// 예) /.../applicationHost.config/NlsData.dll  — 고아 레코드의 부모 참조 재사용.
export const ARTIFACT_PATH =
  /\.(exe|dll|bin|dat|etl|cab|config|toc|hit|dir|cmf|jpg|jpeg|png|gif|ico|log|tmp|sys|mum|cat|que|jrs|chk|jfm|mdb|blf|xml|txt|json|evtx|customdestinations-ms|automaticdestinations-ms|regtrans-ms|winsat\.etl)\/[^/]+$/i;

// 실행파일이 정상적으로 다수 존재하는 영역 (삭제 실행파일 오탐 제외용)
export const EXPECTED_EXE_AREA: RegExp[] = [
  /\/windows\//,
  /\/program files( \(x86\))?\//,
  /\/programdata\//,
  /\/users\/[^/]+\/appdata\/(local|locallow|roaming)\//,
  /\/\$recycle\.bin\//, // 휴지통은 별도 E 에서 처리
];

// OS/시스템 경로 — 정상 서비싱으로 SI<FN 등이 흔함 → 변조 오탐 제외 대상
export const SYSTEM_DIRS: RegExp[] = [
  /\/windows\/winsxs\//,
  /\/windows\/system32\//,
  /\/windows\/syswow64\//,
  /\/windows\/servicing\//,
  /\/windows\/softwaredistribution\//,
  /\/windows\/installer\//,
  /\/program files( \(x86\))?\//,
  /\/windows\/assembly\//,
];

// 보호 시스템 프로세스명 — 정규 경로 외 위치면 위장 의심
export const PROTECTED_PROC = new Set([
  'svchost.exe', 'lsass.exe', 'services.exe', 'csrss.exe', 'winlogon.exe',
  'smss.exe', 'wininit.exe', 'explorer.exe', 'taskhost.exe', 'spoolsv.exe',
  'rundll32.exe', 'conhost.exe', 'dllhost.exe',
]);

// 정규 시스템 경로 (보호 프로세스가 있어야 할 위치)
export const LEGIT_SYS_PATH = /\/(windows|windows\/system32|windows\/syswow64|windows\/winsxs)\//;

// 알려진 공격/해킹 도구·C2 파일명 시그니처. 파일명 기준 정확 매칭으로
// 정상 Windows 구성요소(예: ServerBeacon.dll, shtransform.dll) 오탐 방지.
// 이 검사는 경로(시스템 폴더 포함)와 무관하게 수행한다 — 도구명 자체가 강한 근거.
// note: 탐지 시 설명에 덧붙는 1줄 해설(있으면). 분석가가 도구 성격을 즉시 이해하도록.
export const TOOL_SIGNATURES: { re: RegExp; label: string; tech: MftTechnique; sev: Severity; note?: string }[] = [
  // --- C2 프레임워크 / 임플란트 ---
  { re: /\bsliver\b|sliver.*\.(exe|dll|bin)$/i, label: 'Sliver C2 임플란트', tech: MFT_TECH.c2, sev: 'critical', note: '오픈소스 C2 임플란트. 비콘 주기·도메인 프론팅 점검.' },
  { re: /cobaltstrike|cobalt_strike|^beacon\.(exe|dll)$|^artifact(32|64)?\.exe$|teamserver/i, label: 'Cobalt Strike', tech: MFT_TECH.c2, sev: 'critical', note: '상용 침투 프레임워크. beacon 설정·malleable C2 프로파일 확인.' },
  { re: /meterpreter|metasploit|^msf(venom|console)?\b/i, label: 'Metasploit / Meterpreter', tech: MFT_TECH.c2, sev: 'critical' },
  { re: /\bhavoc\b|demon\.(exe|dll|bin)$/i, label: 'Havoc C2', tech: MFT_TECH.c2, sev: 'critical' },
  { re: /\bmerlin\b|^covenant|grunt(stager)?\.exe$/i, label: 'Merlin / Covenant C2', tech: MFT_TECH.c2, sev: 'critical' },
  { re: /^chaos_server|^chaos\.db$|^chaos_package|^curlchaos/i, label: 'Chaos RAT (C2/원격제어)', tech: MFT_TECH.c2, sev: 'critical', note: '웹 기반 원격제어(C2) 프레임워크. chaos_server.exe=C2 서버, chaos.db=피해 단말·명령 세션을 기록하는 운영 DB(실제 구동 입증), CURLCHAOS.ps1=PowerShell 로더. 웹콘솔로 명령 실행·파일 탐색·화면 캡처·송수신 가능.' },
  { re: /quasar|asyncrat|njrat|remcos|agenttesla|formbook|nanocore|darkcomet|venomrat/i, label: 'RAT 악성코드', tech: MFT_TECH.c2, sev: 'critical', note: '범용 원격제어 트로이목마. 지속성·키로깅·자격증명 탈취 동반 가능.' },
  // --- 자격증명 탈취 ---
  { re: /^mimikatz|sekurlsa|lsadump|^mimilib\.dll$|^mimidrv/i, label: 'Mimikatz (자격증명 탈취)', tech: MFT_TECH.credDump, sev: 'critical', note: 'LSASS 메모리에서 평문 암호·해시·Kerberos 티켓 추출. 노출 호스트의 계정 전수 초기화 필요.' },
  { re: /^procdump(64)?\.exe$|lsass.*\.dmp$|^nanodump/i, label: 'LSASS 덤프', tech: MFT_TECH.credDump, sev: 'critical', note: 'LSASS 프로세스 메모리 덤프 → 오프라인 자격증명 추출.' },
  // --- 원격실행 / 측면이동 ---
  { re: /^psexec(svc)?\.exe$|^paexec\.exe$|^csexec/i, label: 'PsExec (원격 실행)', tech: MFT_TECH.ingressTool, sev: 'high', note: 'SMB 기반 원격 명령 실행. PSEXESVC 서비스 설치 흔적·대상 호스트 확인.' },
  { re: /^(rubeus|sharphound|bloodhound|lazagne|seatbelt|winpeas|powerup|powerview|certify|kerbrute|impacket)\b/i, label: '공격 도구킷', tech: MFT_TECH.ingressTool, sev: 'high', note: 'AD 정찰·권한상승·Kerberos 공격용 공개 도구.' },
  // --- 터널링 / 프록시 ---
  { re: /^chisel|^frpc?\.exe$|^frps\.exe$|^ngrok|^gost\.exe$|^htran|^plink\.exe$|^stowaway|^revsocks/i, label: '터널링/프록시 도구', tech: MFT_TECH.ingressTool, sev: 'high', note: '내부망→외부 역터널 구성. 방화벽 우회·C2 채널·횡적이동 경로로 활용.' },
  { re: /^(nc|ncat|netcat)(64)?\.exe$/i, label: 'Netcat', tech: MFT_TECH.ingressTool, sev: 'high' },
];

// ADS(대체 데이터 스트림) — 정상 스트림 화이트리스트
export const KNOWN_ADS = /:(zone\.identifier|encryptable|wofcompresseddata|favicon|smartscreen|win32app\w*|afp_(afpinfo|resource))$/i;

// 알려진 정상 시스템/AV 내부 구성요소 파일명 (오탐 빈발 → 경로기반 탐지에서 제외)
// 예: Windows Defender 엔진 VDM 구성요소, 다국어 NLS 데이터 등.
export const BENIGN_FILENAME =
  /^(nlsdata\w*|nlslexicons\w*|nl7data\w*|mswb7\w*|korwbrkr|prm\w+|mls\d+\w*|mpengine|mpasbase|mpasdlta|mpavbase|mpavdlta|mpoav|mssp7en|sortdefault)\.(dll|nls)$/i;

// 위장용 가짜 확장자 (이중 확장자 탐지)
export const DOUBLE_EXT = /\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|zip|rar|mp4|mp3|csv|hwp)\.(exe|scr|bat|cmd|com|pif|vbs|vbe|js|jse|ps1|wsf|hta|jar|lnk)$/i;
