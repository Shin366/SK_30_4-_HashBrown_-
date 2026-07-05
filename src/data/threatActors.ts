// =====================================================================
// 공격자 특정(추정) 참조 DB — 위협 그룹 TTP 프로파일 + 도구 시그니처
//
// ⚠️ 본 데이터는 "유사 TTP 위협 그룹"을 좁히기 위한 큐레이션 스냅샷이며,
//    확정 귀속(attribution)이 아니다. Mimikatz·PsExec·Cobalt Strike 등
//    공개/상용 도구는 다수 그룹이 공유하므로 도구 일치만으로 그룹을 단정할 수 없다.
//    프로파일은 MITRE ATT&CK Groups(https://attack.mitre.org/groups) 기반의
//    대표 연관 정보를 요약한 것으로, 최신 정보는 공식 출처에서 대조 권장.
// =====================================================================

// ---- 도구 시그니처 (분석 결과 텍스트에서 사용 도구 탐지) ----
// commodity=true: 다수 그룹 공유(귀속 변별력 낮음). false: 상대적으로 특정 그룹 연관성 높음.
export interface ToolSignature {
  key: string;
  label: string;
  re: RegExp;
  commodity: boolean;
}

export const TOOL_SIGNATURES: ToolSignature[] = [
  { key: 'mimikatz', label: 'Mimikatz', re: /mimikatz|sekurlsa|lsadump/i, commodity: true },
  { key: 'cobaltstrike', label: 'Cobalt Strike', re: /cobalt\s?strike|\bbeacon\b|teamserver/i, commodity: true },
  { key: 'sliver', label: 'Sliver', re: /\bsliver\b/i, commodity: true },
  { key: 'chaos', label: 'Chaos RAT', re: /chaos.?rat|chaos_server|chaos\.db|chaosrat|chaos-container/i, commodity: true },
  { key: 'metasploit', label: 'Metasploit / Meterpreter', re: /metasploit|meterpreter|msfvenom/i, commodity: true },
  { key: 'empire', label: 'PowerShell Empire', re: /\bempire\b/i, commodity: true },
  { key: 'covenant', label: 'Covenant', re: /covenant|\bgrunt\b/i, commodity: true },
  { key: 'bruteratel', label: 'Brute Ratel', re: /brute\s?ratel|\bbadger\b/i, commodity: true },
  { key: 'havoc', label: 'Havoc', re: /\bhavoc\b/i, commodity: true },
  { key: 'psexec', label: 'PsExec', re: /psexec/i, commodity: true },
  { key: 'impacket', label: 'Impacket', re: /impacket|wmiexec|smbexec|secretsdump|atexec/i, commodity: true },
  { key: 'plink', label: 'Plink / PuTTY', re: /\bplink\b|\bputty\b/i, commodity: true },
  { key: 'frp', label: 'FRP (Fast Reverse Proxy)', re: /\bfrpc?\b|\bfrps\b|fast\s?reverse\s?proxy/i, commodity: true },
  { key: 'chisel', label: 'Chisel', re: /\bchisel\b/i, commodity: true },
  { key: 'ngrok', label: 'ngrok', re: /ngrok/i, commodity: true },
  { key: 'netcat', label: 'Netcat', re: /\b(ncat|netcat)\b/i, commodity: true },
  { key: 'nmap', label: 'Nmap', re: /\bnmap\b/i, commodity: true },
  { key: 'softperfect', label: 'SoftPerfect NetScan', re: /netscan|softperfect/i, commodity: true },
  { key: 'advipscan', label: 'Advanced IP Scanner', re: /advanced.?ip.?scanner|advanced_ip_scanner/i, commodity: true },
  { key: 'rclone', label: 'Rclone', re: /rclone/i, commodity: true },
  { key: 'megasync', label: 'MEGAsync', re: /megasync|mega\.nz/i, commodity: true },
  { key: 'anydesk', label: 'AnyDesk', re: /anydesk/i, commodity: true },
  { key: 'sdelete', label: 'SDelete', re: /sdelete/i, commodity: true },
  { key: 'bloodhound', label: 'BloodHound / SharpHound', re: /bloodhound|sharphound/i, commodity: true },
  { key: 'rubeus', label: 'Rubeus', re: /\brubeus\b/i, commodity: true },
  { key: 'lazagne', label: 'LaZagne', re: /lazagne/i, commodity: true },
  { key: 'winpeas', label: 'WinPEAS', re: /winpeas|linpeas/i, commodity: true },
  { key: 'procdump', label: 'ProcDump / nanodump', re: /procdump|nanodump/i, commodity: true },
  // --- 상대적으로 특정 그룹 연관성이 높은(비상용) 임플란트/도구 ---
  { key: 'plugx', label: 'PlugX', re: /\bplugx\b/i, commodity: false },
  { key: 'chinachopper', label: 'China Chopper', re: /china\s?chopper/i, commodity: false },
  { key: 'quasar', label: 'QuasarRAT', re: /quasar/i, commodity: false },
  { key: 'trickbot', label: 'TrickBot', re: /trickbot/i, commodity: false },
  { key: 'carbanak', label: 'Carbanak', re: /carbanak/i, commodity: false },
  { key: 'xagent', label: 'X-Agent', re: /x-?agent|xtunnel/i, commodity: false },
];

// ---- 위협 그룹 TTP 프로파일 ----
export interface ThreatActor {
  id: string; // ATT&CK Group ID
  name: string;
  aliases: string[];
  origin: string; // 배후/유형
  motive: string; // 동기
  note: string; // 한 줄 해설
  techniques: string[]; // 대표 ATT&CK 기법(베이스 ID 기준 매칭)
  software: string[]; // TOOL_SIGNATURES.key
}

export const THREAT_ACTORS: ThreatActor[] = [
  {
    id: 'G0102', name: 'Wizard Spider (Conti/Ryuk)', aliases: ['Conti', 'Ryuk', 'TrickBot Gang'],
    origin: '동유럽 랜섬웨어 크라임', motive: '금전(랜섬웨어·갈취)',
    note: 'PsExec·Mimikatz·Cobalt Strike·SoftPerfect·Rclone 조합의 전형적 랜섬웨어 침투 체인.',
    techniques: ['T1486', 'T1003', 'T1021', 'T1071', 'T1105', 'T1490', 'T1567'],
    software: ['cobaltstrike', 'mimikatz', 'psexec', 'softperfect', 'rclone', 'anydesk', 'trickbot'],
  },
  {
    id: 'G1032', name: 'ALPHV / BlackCat', aliases: ['BlackCat', 'Noberus'],
    origin: '랜섬웨어 크라임(RaaS)', motive: '금전(이중 갈취)',
    note: 'RaaS 계열. 정찰(SoftPerfect)·자격증명(Mimikatz)·유출(Rclone/MEGA) 도구를 폭넓게 활용.',
    techniques: ['T1486', 'T1003', 'T1021', 'T1567', 'T1490'],
    software: ['mimikatz', 'psexec', 'softperfect', 'rclone', 'megasync', 'impacket'],
  },
  {
    id: 'G0008', name: 'LockBit 관계자', aliases: ['LockBit affiliate'],
    origin: '랜섬웨어 크라임(RaaS)', motive: '금전(랜섬웨어)',
    note: '광범위한 제휴 모델. 상용/오픈소스 침투 도구를 조합 — 변별력 낮음.',
    techniques: ['T1486', 'T1003', 'T1021', 'T1490'],
    software: ['mimikatz', 'psexec', 'softperfect', 'rclone', 'megasync', 'advipscan'],
  },
  {
    id: 'G1017', name: 'Volt Typhoon', aliases: ['Bronze Silhouette', 'Vanguard Panda'],
    origin: '중국 국가배후', motive: '첩보·기반시설 침투',
    note: 'Living-off-the-Land 중심. FRP(fast reverse proxy)·Impacket을 이용한 은밀한 지속·터널링이 특징.',
    techniques: ['T1090', 'T1078', 'T1046', 'T1003', 'T1552'],
    software: ['frp', 'impacket', 'mimikatz'],
  },
  {
    id: 'G0096', name: 'APT41 (Winnti)', aliases: ['Winnti', 'Barium', 'Wicked Panda'],
    origin: '중국 국가배후+금전', motive: '첩보·금전 병행',
    note: '웹쉘(China Chopper)·Cobalt Strike·Mimikatz. 첩보와 금전 목적을 병행하는 이중 동기.',
    techniques: ['T1505', 'T1071', 'T1003', 'T1059', 'T1105'],
    software: ['cobaltstrike', 'mimikatz', 'chinachopper', 'plink'],
  },
  {
    id: 'G0045', name: 'APT10 (Stone Panda)', aliases: ['Stone Panda', 'MenuPass', 'Cicada'],
    origin: '중국 국가배후', motive: '첩보(MSP 공급망)',
    note: 'Plink 터널링 + QuasarRAT + Mimikatz. MSP·공급망 경유 침투로 알려짐.',
    techniques: ['T1071', 'T1003', 'T1090', 'T1078'],
    software: ['plink', 'quasar', 'mimikatz', 'psexec'],
  },
  {
    id: 'G0049', name: 'OilRig (APT34)', aliases: ['APT34', 'Helix Kitten'],
    origin: '이란 국가배후', motive: '첩보(중동)',
    note: 'Plink 기반 SSH 터널링과 웹쉘·PowerShell을 활용.',
    techniques: ['T1059', 'T1505', 'T1090', 'T1071'],
    software: ['plink', 'mimikatz'],
  },
  {
    id: 'G0016', name: 'APT29 (Cozy Bear)', aliases: ['Cozy Bear', 'Nobelium', 'Midnight Blizzard'],
    origin: '러시아 국가배후(SVR)', motive: '첩보',
    note: '은밀성 높은 첩보 작전. Cobalt Strike·Mimikatz·WMI를 활용.',
    techniques: ['T1059', 'T1071', 'T1003', 'T1078', 'T1027'],
    software: ['cobaltstrike', 'mimikatz'],
  },
  {
    id: 'G0007', name: 'APT28 (Fancy Bear)', aliases: ['Fancy Bear', 'Sofacy', 'Forest Blizzard'],
    origin: '러시아 국가배후(GRU)', motive: '첩보·정보작전',
    note: '자체 임플란트(X-Agent)와 자격증명 탈취(Mimikatz)를 병행.',
    techniques: ['T1071', 'T1003', 'T1059', 'T1566'],
    software: ['xagent', 'mimikatz'],
  },
  {
    id: 'G0032', name: 'Lazarus Group', aliases: ['Hidden Cobra', 'APT38'],
    origin: '북한 국가배후', motive: '첩보·금전(외화벌이)',
    note: '첩보와 금융 탈취를 병행. 자체 악성코드 + Mimikatz·도구 반입.',
    techniques: ['T1105', 'T1486', 'T1071', 'T1059', 'T1003'],
    software: ['mimikatz', 'metasploit'],
  },
  {
    id: 'G1015', name: 'Scattered Spider', aliases: ['Octo Tempest', 'UNC3944'],
    origin: '영어권 크라임', motive: '금전(사회공학·갈취)',
    note: '사회공학 초기 접근 후 Mimikatz·Impacket·ngrok/AnyDesk로 지속·이동.',
    techniques: ['T1078', 'T1621', 'T1003', 'T1090'],
    software: ['mimikatz', 'impacket', 'ngrok', 'anydesk', 'psexec'],
  },
  {
    id: 'G0046', name: 'FIN7', aliases: ['Carbon Spider', 'Carbanak Group'],
    origin: '금전 크라임', motive: '금전(POS·랜섬웨어)',
    note: 'Carbanak·Cobalt Strike 기반. 최근 랜섬웨어 제휴로 전환.',
    techniques: ['T1059', 'T1071', 'T1055', 'T1486'],
    software: ['cobaltstrike', 'carbanak', 'mimikatz'],
  },
  {
    id: 'G0129', name: 'Mustang Panda', aliases: ['Bronze President', 'Earth Preta'],
    origin: '중국 국가배후', motive: '첩보',
    note: 'PlugX 임플란트 중심의 첩보 활동.',
    techniques: ['T1071', 'T1105', 'T1547', 'T1027'],
    software: ['plugx', 'cobaltstrike'],
  },
  {
    id: 'G0010', name: 'Turla', aliases: ['Snake', 'Venomous Bear'],
    origin: '러시아 국가배후(FSB)', motive: '첩보',
    note: '고도의 은닉 첩보. 자체 백도어 + 위성 C2 등.',
    techniques: ['T1071', 'T1027', 'T1090', 'T1003'],
    software: ['mimikatz'],
  },
  {
    id: 'G0035', name: 'Dragonfly', aliases: ['Energetic Bear', 'Berserk Bear'],
    origin: '러시아 국가배후', motive: '첩보(에너지·기반시설)',
    note: '공개 도구(Impacket·Mimikatz) 위주의 기반시설 정찰.',
    techniques: ['T1078', 'T1003', 'T1046', 'T1133'],
    software: ['impacket', 'mimikatz', 'nmap'],
  },
];
