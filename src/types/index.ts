// =====================================================================
// 공통 타입 정의 — 전체 분석 파이프라인의 단일 계약(Contract).
// 모든 service / component 는 이 파일의 타입을 import 해서 사용한다.
// =====================================================================

export type LogFormat = 'txt' | 'csv' | 'evtx' | 'weblog' | 'xlsx' | 'mft';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/** REQ-NF-002: 사실(Fact) 과 추정(Assessment) 을 명확히 구분 표기 */
export type ConfidenceKind = 'fact' | 'assessment';

// ---------------------------------------------------------------------
// 로그 (REQ-F-001)
// ---------------------------------------------------------------------
export interface LogEntry {
  id: string;
  lineNumber: number;
  timestamp: string | null; // ISO 8601, 파싱 실패 시 null
  rawTimestamp?: string;
  source: string; // 파일명
  sourceIp?: string;
  destIp?: string;
  method?: string; // HTTP method
  url?: string;
  statusCode?: number;
  bytes?: number;
  userAgent?: string;
  user?: string;
  message: string;
  raw: string;
  format: LogFormat;
}

export interface AnomalyEvent {
  id: string;
  logId: string;
  lineNumber: number;
  timestamp: string | null;
  category: string; // 예: "Brute Force", "SQL Injection"
  description: string;
  severity: Severity;
  confidence: ConfidenceKind;
  evidence: string; // 원본 로그 스니펫 (근거)
  sourceIp?: string;
}

// ---------------------------------------------------------------------
// IOC / 위협 매핑 (REQ-F-002)
// ---------------------------------------------------------------------
export type IOCType =
  | 'ip'
  | 'domain'
  | 'url'
  | 'hash-md5'
  | 'hash-sha1'
  | 'hash-sha256'
  | 'email'
  | 'cve'
  | 'filepath';

export interface IOC {
  id: string;
  type: IOCType;
  value: string;
  count: number;
  firstSeen: string | null;
  lastSeen: string | null;
  severity: Severity;
  relatedLogIds: string[];
  vtReference: string; // VirusTotal 조회 URL (REQ-F-001 "VirusTotal참고")
}

export interface AttackTechnique {
  id: string; // Txxxx[.xxx]
  name: string;
  tactic: string; // 전술명
  tacticId: string; // TAxxxx
  description: string;
  url: string; // MITRE ATT&CK 레퍼런스
  matchedEvidence: string[]; // 근거 로그 스니펫
  confidence: ConfidenceKind;
  relatedCves: string[];
  severity: Severity;
}

export interface CVE {
  id: string; // CVE-YYYY-NNNN
  description: string;
  cvss: number;
  severity: Severity;
  url: string;
  matchedTechniques: string[];
  evidence: string[];
}

// ---------------------------------------------------------------------
// 타임라인 / 공격 흐름도 (REQ-F-003)
// ---------------------------------------------------------------------
export interface TimelineEvent {
  id: string;
  timestamp: string | null;
  order: number;
  title: string;
  phase: string; // ATT&CK 전술 / kill-chain 단계
  description: string;
  severity: Severity;
  confidence: ConfidenceKind;
  sourceIp?: string;
}

export interface AttackFlowNode {
  id: string;
  label: string;
  phase: string;
  techniqueId?: string;
  severity: Severity;
}

export interface AttackFlowEdge {
  from: string;
  to: string;
  label?: string;
}

export interface AttackFlow {
  nodes: AttackFlowNode[];
  edges: AttackFlowEdge[];
}

// ---------------------------------------------------------------------
// 트래픽 분석 (REQ-F-004)
// ---------------------------------------------------------------------
export interface TrafficScore {
  id: string;
  sourceIp: string;
  requests: number;
  anomalyScore: number; // 0..1 비정상 확률
  classification: 'normal' | 'abnormal';
  confidence: ConfidenceKind;
  reasons: string[];
  bytes: number;
  errorRate: number; // 0..1
}

// ---------------------------------------------------------------------
// 가이드 보고서 (REQ-F-005)
// ---------------------------------------------------------------------
export interface GuidelineStep {
  step: number;
  title: string;
  rationale: string;
  actions: string[];
  relatedRequirements: string[];
  priority: Severity;
}

export interface ReportSummary {
  generatedAt: string;
  engine: 'local' | 'ai'; // 로컬 규칙기반 / 외부 AI API
  totalLogs: number;
  totalAnomalies: number;
  totalIOCs: number;
  topTechniques: string[];
  steps: GuidelineStep[];
  narrative: string;
  factsVsAssessments: { facts: string[]; assessments: string[] };
}

// ---------------------------------------------------------------------
// MFT (Master File Table) 분석 (REQ-F-001, REQ-NF-004)
// analyzeMFT / MFTECmd 형식의 NTFS MFT 표를 해석.
// ---------------------------------------------------------------------
export interface MftRecord {
  recordNumber: number;
  active: boolean; // Inactive = 삭제됨
  recordType: string; // File / Folder / ...
  path: string; // 전체 경로 (Filename #1)
  fileName: string; // basename
  ext: string; // 확장자(소문자, 점 제외)
  // $STANDARD_INFORMATION (사용자 변경 가능 — 타임스탬프 변조 대상)
  siCreated: string | null;
  siModified: string | null;
  siAccessed: string | null;
  siEntry: string | null;
  // $FILE_NAME (커널 설정 — 변조 난이도 높음)
  fnCreated: string | null;
  fnModified: string | null;
  fnAccessed: string | null;
  fnEntry: string | null;
}

export interface MftFinding {
  id: string;
  recordNumber: number;
  path: string;
  fileName: string;
  category: string;
  description: string;
  severity: Severity;
  confidence: ConfidenceKind;
  techniqueId?: string;
  siCreated: string | null;
  fnCreated: string | null;
  active: boolean;
}

export interface MftAnalysis {
  totalRecords: number;
  fileCount: number;
  folderCount: number;
  activeCount: number;
  inactiveCount: number; // 삭제 정황
  datedRecords: number; // 유효 타임스탬프 보유
  /** $SI 생성 < $FN 생성 불일치 건수 (대부분 정상 복사/프로비저닝 — 정보성) */
  siFnMismatchCount: number;
  /** $SI 생성 > $SI 수정 논리모순 건수 (복사 시에도 발생 — 정보성) */
  tsLogicAnomalyCount: number;
  findings: MftFinding[];
  findingsByCategory: { category: string; count: number; severity: Severity }[];
}

// ---------------------------------------------------------------------
// 머신러닝 분석 (비지도 이상탐지 + 지도 분류 + 군집화)
// 규칙기반 엔진과 병행하는 하이브리드 계층. 브라우저에서 즉시 학습/추론.
// ---------------------------------------------------------------------
export interface MlAnomaly {
  id: string;
  ref: string; // 로그 라인 / MFT 레코드 식별자
  score: number; // 0..1 Isolation Forest 이상 점수
  reasons: string[]; // 기여 특징(z-score 상위)
  snippet: string;
  dupes?: number; // 동일 기여특징 프로파일의 유사 이상치 개수(대표 1건으로 접음)
}

export interface MlClassDist {
  label: string; // 내부 라벨키
  labelKo: string; // 한글 표기
  count: number;
  ratio: number; // 0..1
}

export interface MlCluster {
  id: number;
  size: number;
  ratio: number;
  keywords: string[]; // 대표 토큰(중심 상위 가중)
  rare: boolean; // 소수 군집 = 드문 행위
}

export interface MlEntropyFlag {
  ref: string;
  value: string; // 고엔트로피 토큰(잘라서)
  entropy: number;
  note: string;
}

export interface MlAnalysis {
  trained: boolean;
  target: 'log' | 'mft';
  sampleCount: number; // 모델에 투입된 표본 수
  models: string[]; // 사용된 알고리즘 이름
  featureNames: string[];
  anomalies: MlAnomaly[]; // IF 상위 이상치
  contamination: number; // 이상치로 표시된 비율(0..1)
  classification: MlClassDist[]; // NB 라벨 분포 (log 대상)
  clusters: MlCluster[]; // K-Means 군집
  entropyFlags: MlEntropyFlag[];
  metrics: {
    nbAccuracy: number; // NB 5겹 교차검증 정확도
    nbVocab: number; // 학습 어휘 수
    silhouette: number; // 군집 실루엣(−1..1)
    iforestTrees: number;
    flaggedCount: number;
  };
  summary: string;
}

export type AnalysisKind = 'log' | 'mft';

// ---------------------------------------------------------------------
// 공격자 특정 (추정) — 탐지된 ATT&CK 기법·도구를 알려진 위협 그룹의
// TTP 프로파일과 대조해 "유사 위협 그룹"을 유사도순으로 제시. 확정 귀속이 아님.
// ---------------------------------------------------------------------
export type ActorConfidence = 'low' | 'medium' | 'high';

export interface ActorCandidate {
  id: string; // ATT&CK Group ID(Gxxxx) 또는 큐레이션 식별자
  name: string;
  aliases: string[];
  origin: string; // 배후/유형 (예: '러시아 국가배후', '랜섬웨어 크라임')
  motive: string; // 동기 (첩보/금전 등)
  score: number; // 0..1 유사도
  confidence: ActorConfidence;
  matchedTools: string[]; // 일치한 도구(라벨)
  matchedTechniques: string[]; // 일치한 ATT&CK 기법 ID
  note: string; // 한 줄 해설
  url: string; // attack.mitre.org 레퍼런스
}

export interface ActorAttribution {
  candidates: ActorCandidate[];
  detectedTools: string[]; // 탐지된 도구(라벨)
  summary: string;
  caveats: string[]; // 추정임을 명시하는 한계
}

// ---------------------------------------------------------------------
// AI 추정 침입 경로 (Assessment) — 탐지 지표를 kill-chain 순으로 재구성해
// "공격자가 어떻게 침입·전개했는지"를 서술하는 추정 가설. 사실이 아닌 추정.
// ---------------------------------------------------------------------
export interface IntrusionStep {
  order: number;
  phase: string; // "정찰 · Reconnaissance" 형태(한글·영문 전술명)
  tacticId: string;
  techniqueIds: string[];
  title: string; // 핵심 행위(기법명 요약)
  narrative: string; // 추정 서술 문장
  severity: Severity;
  evidence?: string; // 대표 근거 스니펫
}

export interface IntrusionHypothesis {
  confidence: ConfidenceKind; // 'assessment' — 항상 추정
  entryVector: string; // 초기 침투 경로 추정(한 줄)
  actorProfile: string; // 공격자 성향 추정
  timeSpan: string | null; // 관측 활동 구간
  topSourceIp: string | null; // 주요 출발지 IP
  steps: IntrusionStep[]; // kill-chain 순 재구성
  narrative: string; // 종합 서사
  caveats: string[]; // 한계·불확실성(추정임을 명시)
}

// ---------------------------------------------------------------------
// 통합 결과 (REQ-F-006)
// ---------------------------------------------------------------------
export interface AnalysisResult {
  kind: AnalysisKind;
  fileName: string;
  fileSize: number;
  format: LogFormat;
  parsedAt: string;
  logs: LogEntry[];
  anomalies: AnomalyEvent[];
  iocs: IOC[];
  techniques: AttackTechnique[];
  cves: CVE[];
  timeline: TimelineEvent[];
  attackFlow: AttackFlow;
  traffic: TrafficScore[];
  report: ReportSummary;
  mft?: MftAnalysis; // kind === 'mft' 일 때
  ml?: MlAnalysis; // 머신러닝 계층 결과 (하이브리드)
  intrusion?: IntrusionHypothesis; // AI 추정 침입 경로 (매핑 기법 존재 시)
  attribution?: ActorAttribution; // 공격자 특정 (추정) — 유사 위협 그룹
}

export type AnalysisStatus = 'idle' | 'parsing' | 'analyzing' | 'done' | 'error';
