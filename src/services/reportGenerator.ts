import type {
  AnomalyEvent,
  AttackTechnique,
  CVE,
  GuidelineStep,
  IOC,
  LogEntry,
  ReportSummary,
  TrafficScore,
} from '@/types';
import { severityRank } from '@/utils/format';

// =====================================================================
// 분석 가이드라인 자동 생성 (REQ-F-005)
// 로컬 규칙 기반으로 "어떤 순서로 무엇을 분석할지" 단계별 가이드 + 내러티브.
// REQ-NF-002: 사실(facts) / 추정(assessments) 분리 표기.
// =====================================================================

interface ReportInput {
  logs: LogEntry[];
  anomalies: AnomalyEvent[];
  iocs: IOC[];
  techniques: AttackTechnique[];
  cves: CVE[];
  traffic: TrafficScore[];
  /** 분석 대상 단위 수 (로그 라인 수 또는 MFT 레코드 수) */
  unitCount?: number;
  /** 단위 라벨 ('로그' | 'MFT 레코드') */
  unitLabel?: string;
}

export function generateReport(input: ReportInput, nowIso: string): ReportSummary {
  const { logs, anomalies, iocs, techniques, cves, traffic } = input;
  const unitCount = input.unitCount ?? logs.length;
  const unitLabel = input.unitLabel ?? '로그';

  const critical = anomalies.filter((a) => a.severity === 'critical');
  const high = anomalies.filter((a) => a.severity === 'high');
  const abnormalIps = traffic.filter((t) => t.classification === 'abnormal');
  const topTechniques = [...techniques]
    .sort((a, b) => severityRank(b.severity) - severityRank(a.severity))
    .slice(0, 5)
    .map((t) => `${t.id} ${t.name}`);

  const steps = buildSteps({ iocs, techniques, cves, critical, high, abnormalIps });

  const facts: string[] = [
    `총 ${unitCount.toLocaleString()}건 ${unitLabel} 분석 완료.`,
    `이상징후 ${anomalies.length}건 탐지 (심각 ${critical.length} / 높음 ${high.length}).`,
    `IOC ${iocs.length}종 추출.`,
    `MITRE ATT&CK 기법 ${techniques.length}종, 관련 CVE ${cves.length}건 매핑.`,
  ];
  if (cves.length > 0) facts.push(`관련 CVE: ${cves.slice(0, 5).map((c) => c.id).join(', ')}.`);

  const assessments: string[] = [];
  if (critical.length > 0) {
    assessments.push('심각 수준 이상징후가 존재하여 실제 침해 가능성이 높음으로 추정.');
  } else if (high.length > 0) {
    assessments.push('다수의 높음 수준 징후로 보아 공격 시도가 진행되었을 것으로 추정.');
  } else {
    assessments.push('치명적 징후는 미발견 — 다만 로그 범위 한계로 단정 불가.');
  }
  if (abnormalIps.length > 0) {
    assessments.push(
      `비정상 트래픽 출발지 ${abnormalIps.length}개 추정 (최고 ${abnormalIps[0].sourceIp}, score ${abnormalIps[0].anomalyScore}).`,
    );
  }
  assessments.push('상기 추정은 AI/규칙 기반 보조 판단이며, 분석가 검증이 필요함.');

  return {
    generatedAt: nowIso,
    engine: 'local',
    totalLogs: unitCount,
    totalAnomalies: anomalies.length,
    totalIOCs: iocs.length,
    topTechniques,
    steps,
    narrative: buildNarrative(input, critical.length, high.length, abnormalIps.length, unitCount, unitLabel),
    factsVsAssessments: { facts, assessments },
  };
}

function buildSteps(ctx: {
  iocs: IOC[];
  techniques: AttackTechnique[];
  cves: CVE[];
  critical: AnomalyEvent[];
  high: AnomalyEvent[];
  abnormalIps: TrafficScore[];
}): GuidelineStep[] {
  const steps: GuidelineStep[] = [];
  let n = 1;

  steps.push({
    step: n++,
    title: '초기 분류(Triage) — 심각/높음 징후 우선 확인',
    rationale: '한정된 시간 내 영향도가 큰 이벤트부터 검증해 분석 효율을 높인다.',
    actions: [
      `심각 ${ctx.critical.length}건 · 높음 ${ctx.high.length}건의 이상징후 원본 로그 라인 확인`,
      '각 징후의 evidence(원본 스니펫)로 오탐 여부 1차 판별',
    ],
    relatedRequirements: ['REQ-F-001', 'REQ-NF-002'],
    priority: ctx.critical.length ? 'critical' : ctx.high.length ? 'high' : 'medium',
  });

  if (ctx.techniques.length > 0) {
    steps.push({
      step: n++,
      title: 'ATT&CK 단계 재구성 — 공격 흐름 파악',
      rationale: '탐지된 전술/기법을 kill-chain 순서로 배열하면 침투 경로와 현재 단계를 가늠할 수 있다.',
      actions: [
        `탐지 기법(${ctx.techniques.slice(0, 4).map((t) => t.id).join(', ')}) 의 전술 순서 검토`,
        '타임라인 패널에서 초기 침투 → 확산 → 영향 순으로 시각 확인',
      ],
      relatedRequirements: ['REQ-F-002', 'REQ-F-003'],
      priority: 'high',
    });
  }

  if (ctx.cves.length > 0) {
    steps.push({
      step: n++,
      title: '취약점(CVE) 검증 및 패치 상태 확인',
      rationale: '악용된 것으로 보이는 CVE 의 실제 적용 자산/패치 여부를 확인해 재발을 막는다.',
      actions: [
        `${ctx.cves.slice(0, 3).map((c) => c.id).join(', ')} 영향 자산 식별`,
        'NVD/벤더 권고와 대조하여 패치 적용 여부 확인',
      ],
      relatedRequirements: ['REQ-F-002'],
      priority: ctx.cves.some((c) => c.severity === 'critical') ? 'critical' : 'high',
    });
  }

  if (ctx.iocs.length > 0) {
    steps.push({
      step: n++,
      title: 'IOC 평판 조회 및 차단',
      rationale: '추출된 지표를 평판 서비스와 대조해 악성 여부를 확인하고 경계 차단에 활용한다.',
      actions: [
        `상위 IOC(${ctx.iocs.slice(0, 3).map((i) => i.value).join(', ')}) VirusTotal 참고링크 확인`,
        '악성 확인 시 방화벽/EDR 차단 및 전체 로그 재검색',
      ],
      relatedRequirements: ['REQ-F-001', 'REQ-F-002'],
      priority: 'medium',
    });
  }

  if (ctx.abnormalIps.length > 0) {
    steps.push({
      step: n++,
      title: '비정상 트래픽 출발지 심층 분석',
      rationale: '확률 점수가 높은 출발지는 공격 근원일 가능성이 커 별도 추적이 필요하다.',
      actions: [
        `score 상위 IP(${ctx.abnormalIps.slice(0, 3).map((t) => t.sourceIp).join(', ')}) 의 전체 요청 패턴 검토`,
        '정상 업무 트래픽과 구분되는지 분석가 검증',
      ],
      relatedRequirements: ['REQ-F-004'],
      priority: 'high',
    });
  }

  steps.push({
    step: n++,
    title: '보고서화 및 분석가 최종 검증',
    rationale: 'AI/규칙 결과는 보조 수단이므로 사실과 추정을 구분해 정리하고 최종 판단은 분석가가 내린다.',
    actions: [
      '사실(Fact)과 추정(Assessment)을 분리해 결과 문서화',
      '미해결 항목·추가 수집 필요 로그 식별',
    ],
    relatedRequirements: ['REQ-NF-002', 'REQ-F-005'],
    priority: 'medium',
  });

  return steps;
}

function buildNarrative(
  input: ReportInput,
  crit: number,
  high: number,
  abnormal: number,
  unitCount: number,
  unitLabel: string,
): string {
  const { techniques, cves } = input;
  const firstTactic = techniques[0]?.tactic;
  const lastTactic = techniques[techniques.length - 1]?.tactic;
  const parts: string[] = [];
  parts.push(
    `업로드된 ${unitCount.toLocaleString()}건의 ${unitLabel}에서 ${input.anomalies.length}건의 이상징후가 관측되었다.`,
  );
  if (techniques.length > 0) {
    parts.push(
      `공격은 ${firstTactic ?? '초기 단계'}에서 시작해 ${lastTactic ?? '후속 단계'}까지 ${techniques.length}개 기법이 식별되는 양상으로 추정된다.`,
    );
  }
  if (crit > 0) {
    parts.push(`심각 수준 징후 ${crit}건이 포함되어 즉시 대응이 권장된다(추정).`);
  } else if (high > 0) {
    parts.push(`높음 수준 징후 ${high}건이 확인되어 우선 검증이 필요하다(추정).`);
  }
  if (cves.length > 0) {
    parts.push(`악용 가능 CVE(${cves.slice(0, 3).map((c) => c.id).join(', ')})와의 연관성이 제시된다.`);
  }
  if (abnormal > 0) {
    parts.push(`트래픽 분석상 비정상 출발지 ${abnormal}개가 추정되었다.`);
  }
  parts.push('본 결과는 분석 보조용이며 최종 판단은 분석가의 교차검증을 병행해야 한다.');
  return parts.join(' ');
}
