// =====================================================================
// AI 추정 침입 경로 재구성 (Assessment) — REQ-F-003 확장
// 탐지된 ATT&CK 기법을 kill-chain(전술 순서)으로 재배열해, "공격자가
// 어떻게 최초 침입해 어떤 순서로 공격을 전개했는지"를 서술하는 추정 가설을
// 생성한다. 규칙기반 탐지 결과에서만 유도(외부 호출 없음) — 데이터 기반이며
// 확정 사실이 아닌 추정(assessment)임을 명시한다.
// =====================================================================

import type {
  AttackTechnique,
  IntrusionHypothesis,
  IntrusionStep,
  IOC,
  TimelineEvent,
} from '@/types';
import { TACTICS, tacticOrder } from '@/data/mitreAttack';
import { maxSeverity, severityRank, truncate, formatTimestamp } from '@/utils/format';

// 전술ID → 한글 단계명
const TACTIC_KO: Record<string, string> = {
  TA0043: '정찰',
  TA0001: '초기 침투',
  TA0002: '실행',
  TA0003: '지속성 확보',
  TA0004: '권한 상승',
  TA0005: '방어 회피',
  TA0006: '자격증명 탈취',
  TA0007: '내부 탐색',
  TA0008: '측면 이동',
  TA0009: '데이터 수집',
  TA0011: 'C2 통신',
  TA0010: '데이터 유출',
  TA0040: '피해 유발',
};

// 전술ID → 추정 서술 동사구("~한 것으로 추정됩니다"에 결합)
const TACTIC_ACTION: Record<string, string> = {
  TA0043: '대상 시스템을 스캔·열거해 노출된 서비스와 취약점을 식별',
  TA0001: '공개된 서비스의 취약점을 악용해 최초 발판을 확보',
  TA0002: '확보한 접근 권한으로 명령·스크립트를 실행',
  TA0003: '재접속을 위한 지속성 수단(웹쉘·자동실행 등)을 설치',
  TA0004: '권한을 상승시켜 시스템 통제 범위를 확대',
  TA0005: '이벤트 로그·흔적을 제거해 탐지를 회피',
  TA0006: '자격증명을 탈취해 추가 계정을 장악',
  TA0007: '내부 네트워크·자원 구성을 탐색',
  TA0008: '탈취한 자격증명으로 내부 시스템에 측면 이동',
  TA0009: '표적 데이터를 한곳에 수집',
  TA0011: '외부 C2 서버와 은닉 통신 채널을 수립',
  TA0010: '수집한 데이터를 외부로 반출',
  TA0040: '데이터 암호화·파괴 등으로 실질적 피해를 유발',
};

// 최초 침투 전술 → 초기 침투 벡터 한 줄 힌트
const ENTRY_HINT: Record<string, string> = {
  TA0001: '공개 웹/서비스 취약점 익스플로잇',
  TA0043: '외부 정찰·스캐닝으로 노출면 식별 후 접근',
  TA0006: '인증 무차별 대입 / 자격증명 탈취',
  TA0002: '원격 명령 실행',
  TA0003: '웹쉘 업로드를 통한 발판 확보',
};

/**
 * 탐지 기법·타임라인·IOC 로부터 추정 침입 경로를 재구성한다.
 * 매핑된 기법이 하나도 없으면 undefined(가설 생성 불가).
 */
export function buildIntrusionHypothesis(
  techniques: AttackTechnique[],
  timeline: TimelineEvent[],
  iocs: IOC[],
): IntrusionHypothesis | undefined {
  if (techniques.length === 0) return undefined;

  // 전술별 그룹핑 → kill-chain 순 정렬
  const byTactic = new Map<string, AttackTechnique[]>();
  for (const t of techniques) {
    const arr = byTactic.get(t.tacticId);
    if (arr) arr.push(t);
    else byTactic.set(t.tacticId, [t]);
  }
  const ordered = Array.from(byTactic.keys()).sort((a, b) => tacticOrder(a) - tacticOrder(b));

  const steps: IntrusionStep[] = ordered.map((tid, i) => {
    const techs = byTactic.get(tid)!;
    const names = Array.from(new Set(techs.map((t) => t.name)));
    const ids = Array.from(new Set(techs.map((t) => t.id)));
    const sev = maxSeverity(techs.map((t) => t.severity));
    const ev = techs.map((t) => t.matchedEvidence?.[0]).find(Boolean);
    const action = TACTIC_ACTION[tid] ?? `${TACTICS[tid]?.name ?? tid} 활동을 수행`;
    const enName = TACTICS[tid]?.name ?? tid;
    return {
      order: i + 1,
      phase: TACTIC_KO[tid] ? `${TACTIC_KO[tid]} · ${enName}` : enName,
      tacticId: tid,
      techniqueIds: ids,
      title: names.join(', '),
      narrative: `공격자는 ${action}한 것으로 추정됩니다 (${names.join(', ')}).`,
      severity: sev,
      evidence: ev ? truncate(ev, 140) : undefined,
    };
  });

  // 초기 침투 벡터 = 실제 "침입"이 일어난 전술. 정찰(TA0043)은 침입 이전 준비
  // 단계이므로 초기접근(TA0001)이 있으면 그것을, 없으면 정찰을 제외한 최초 공격
  // 전술을, 그마저 없으면(정찰만 관측) 정찰을 침투 벡터로 삼는다.
  const entryTactic =
    (ordered.includes('TA0001') ? 'TA0001' : undefined) ??
    ordered.find((t) => t !== 'TA0043') ??
    ordered[0];
  const reconPrecedes = ordered.includes('TA0043') && entryTactic !== 'TA0043';
  const entryTechs = byTactic
    .get(entryTactic)!
    .map((t) => `${t.name}(${t.id})`)
    .filter((v, idx, a) => a.indexOf(v) === idx);
  const entryVector =
    (reconPrecedes ? '사전 정찰·스캐닝 후 ' : '') +
    (ENTRY_HINT[entryTactic]
      ? `${ENTRY_HINT[entryTactic]} — ${entryTechs.join(', ')}`
      : entryTechs.join(', '));

  // 관측 활동 구간(타임스탬프 최소~최대)
  const times = timeline.map((e) => e.timestamp).filter((v): v is string => Boolean(v)).sort();
  const timeSpan = times.length
    ? `${formatTimestamp(times[0])} ~ ${formatTimestamp(times[times.length - 1])}`
    : null;

  // 주요 출발지 IP(타임라인 최다 → 없으면 IOC 의 IP)
  const ipCount = new Map<string, number>();
  for (const e of timeline) if (e.sourceIp) ipCount.set(e.sourceIp, (ipCount.get(e.sourceIp) ?? 0) + 1);
  const topSourceIp =
    Array.from(ipCount.entries()).sort((a, b) => b[1] - a[1])[0]?.[0] ??
    iocs.find((i) => i.type === 'ip')?.value ??
    null;

  // 공격자 성향 추정
  const has = (tid: string) => byTactic.has(tid);
  const profileBits: string[] = [];
  if (has('TA0043')) profileBits.push('자동화 스캐닝 도구 활용');
  if (has('TA0006') || has('TA0008')) profileBits.push('수동 조작(핸즈온-키보드) 정황');
  if (has('TA0005')) profileBits.push('흔적 제거로 탐지 회피 시도');
  if (has('TA0040') || has('TA0010')) profileBits.push('데이터 탈취·파괴 등 뚜렷한 최종 목표');
  const actorProfile = profileBits.length
    ? profileBits.join(' · ')
    : '단편적 활동 — 성향을 단정하기 어려움';

  // 종합 서사
  const chain = steps.map((s) => TACTIC_KO[s.tacticId] ?? s.tacticId).join(' → ');
  const worst = steps.reduce((acc, s) =>
    severityRank(s.severity) > severityRank(acc.severity) ? s : acc,
  );
  const narrative =
    `${timeSpan ? `관측된 활동 구간은 ${timeSpan} 이며, ` : ''}` +
    `${topSourceIp ? `주요 출발지 IP 는 ${topSourceIp} 로 보입니다. ` : ''}` +
    `종합하면 공격자는 「${entryVector}」(으)로 최초 침입한 뒤 ${chain} 순서로 공격을 전개한 것으로 추정됩니다. ` +
    `이 중 「${worst.title}」(${worst.phase}) 단계의 심각도가 가장 높아 우선 대응이 필요합니다.`;

  const caveats = buildCaveats();

  return {
    confidence: 'assessment',
    entryVector,
    actorProfile,
    timeSpan,
    topSourceIp,
    steps,
    narrative,
    caveats,
  };
}

function buildCaveats(): string[] {
  return [
    '본 침입 경로는 탐지된 지표를 kill-chain 순으로 재구성한 추정(assessment)이며, 확정된 사실이 아닙니다.',
    '타임스탬프는 변조(타임스톰프)될 수 있어 실제 발생 순서와 다를 수 있습니다.',
    '로그·MFT에 흔적이 남지 않은 활동은 재구성에서 누락됩니다(증거 부재가 활동 부재를 뜻하지 않음).',
    '개발 기간이 짧아 탐지 규칙·학습 범위에 한계가 있으므로 일부 단계가 과탐 또는 미탐될 수 있습니다.',
  ];
}
