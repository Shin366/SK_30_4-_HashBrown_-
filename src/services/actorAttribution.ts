// =====================================================================
// 공격자 특정(추정) — 탐지된 도구·ATT&CK 기법을 위협 그룹 TTP 프로파일과
// 대조해 "유사 위협 그룹"을 유사도순으로 제시한다. 확정 귀속이 아니라,
// 후속 조사를 좁히기 위한 참고용 추정(assessment)이다.
// =====================================================================

import type {
  ActorAttribution,
  ActorCandidate,
  ActorConfidence,
  AnomalyEvent,
  AttackTechnique,
  IOC,
  MftFinding,
} from '@/types';
import { TOOL_SIGNATURES, THREAT_ACTORS } from '@/data/threatActors';

const ATTACK_GROUP_URL = (id: string) => `https://attack.mitre.org/groups/${id}/`;

/** 분석 결과 텍스트에서 사용 도구를 탐지한다. */
function detectTools(corpus: string): { keys: Set<string>; labels: string[]; hasNonCommodity: (keys: string[]) => boolean } {
  const keys = new Set<string>();
  const labels: string[] = [];
  const commodityByKey: Record<string, boolean> = {};
  for (const sig of TOOL_SIGNATURES) {
    commodityByKey[sig.key] = sig.commodity;
    if (sig.re.test(corpus)) {
      keys.add(sig.key);
      labels.push(sig.label);
    }
  }
  return {
    keys,
    labels,
    hasNonCommodity: (ks: string[]) => ks.some((k) => commodityByKey[k] === false),
  };
}

const labelOf = (key: string): string => TOOL_SIGNATURES.find((s) => s.key === key)?.label ?? key;

export function buildAttribution(
  techniques: AttackTechnique[],
  iocs: IOC[],
  anomalies: AnomalyEvent[],
  mftFindings?: MftFinding[],
): ActorAttribution | undefined {
  // 1) 도구 탐지 코퍼스 구성
  const corpus = [
    ...techniques.map((t) => `${t.id} ${t.name} ${t.matchedEvidence.join(' ')}`),
    ...iocs.map((i) => i.value),
    ...anomalies.map((a) => `${a.category} ${a.evidence}`),
    ...(mftFindings ?? []).map((f) => `${f.category} ${f.description} ${f.path}`),
  ].join('\n');

  const tools = detectTools(corpus);

  // 2) 탐지 기법 집합(서브기법은 베이스 ID 로도 포함 — 프로파일은 베이스 기준)
  const techSet = new Set<string>();
  for (const t of techniques) {
    techSet.add(t.id);
    techSet.add(t.id.split('.')[0]);
  }

  // 도구도 기법도 없으면 특정 근거 자체가 없음
  if (tools.keys.size === 0 && techSet.size === 0) return undefined;

  // 3) 그룹별 유사도 산출
  const candidates: ActorCandidate[] = [];
  for (const actor of THREAT_ACTORS) {
    const matchedToolKeys = actor.software.filter((k) => tools.keys.has(k));
    const matchedTechniques = actor.techniques.filter((id) => techSet.has(id));
    const nIndicators = matchedToolKeys.length + matchedTechniques.length;
    if (nIndicators < 2) continue; // 최소 2개 지표 겹칠 때만 후보

    const distinctive = tools.hasNonCommodity(matchedToolKeys);
    const raw = 3 * matchedToolKeys.length + matchedTechniques.length;
    const score = Math.min(1, raw / 12);

    let confidence: ActorConfidence = 'low';
    if (distinctive && matchedToolKeys.length >= 2) confidence = 'high';
    else if (matchedToolKeys.length >= 3 || distinctive) confidence = 'medium';

    candidates.push({
      id: actor.id,
      name: actor.name,
      aliases: actor.aliases,
      origin: actor.origin,
      motive: actor.motive,
      score: Number(score.toFixed(2)),
      confidence,
      matchedTools: matchedToolKeys.map(labelOf),
      matchedTechniques,
      note: actor.note,
      url: ATTACK_GROUP_URL(actor.id),
    });
  }

  candidates.sort((a, b) => b.score - a.score || b.matchedTools.length - a.matchedTools.length);
  const top = candidates.slice(0, 6);

  const distinctiveTools = tools.labels.filter((l) =>
    TOOL_SIGNATURES.some((s) => s.label === l && !s.commodity),
  );
  const summary = top.length
    ? `탐지된 도구 ${tools.labels.length}종·ATT&CK 기법 ${techniques.length}개를 기준으로, TTP가 유사한 알려진 위협 그룹 ${top.length}곳을 유사도순으로 제시한다. ` +
      (distinctiveTools.length
        ? `상대적으로 변별력 있는 도구(${distinctiveTools.join(', ')})가 포함되어 좁힘에 참고가 된다.`
        : `다만 일치 도구가 대부분 공개·상용 도구여서 특정 그룹으로 단정하기 어렵다.`)
    : `탐지된 도구·기법이 특정 위협 그룹 프로파일과 유의미하게(2개 지표 이상) 겹치지 않아 유사 그룹을 제시하지 않는다.`;

  return {
    candidates: top,
    detectedTools: tools.labels,
    summary,
    caveats: [
      '본 결과는 탐지 TTP·도구가 겹치는 알려진 위협 그룹을 유사도순으로 제시한 추정(assessment)이며, 확정 귀속이 아니다.',
      'Mimikatz·PsExec·Cobalt Strike·Sliver 등 공개·상용 도구는 다수 그룹이 공유하므로, 도구 일치만으로 특정 그룹을 단정할 수 없다.',
      '확정 귀속에는 C2 인프라·악성코드 코드 유사성·피해자학·활동 시점 등 추가 증거의 교차분석이 필요하다.',
      '위협 그룹 프로파일은 큐레이션 스냅샷이므로 최신 정보는 attack.mitre.org/groups 에서 대조 권장.',
    ],
  };
}
