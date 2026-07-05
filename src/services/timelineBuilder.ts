import type {
  AnomalyEvent,
  AttackFlow,
  AttackFlowEdge,
  AttackFlowNode,
  AttackTechnique,
  TimelineEvent,
} from '@/types';
import { TACTICS, tacticName, tacticOrder } from '@/data/mitreAttack';
import { makeId, maxSeverity } from '@/utils/format';

// =====================================================================
// 타임라인 · 공격 흐름도 자동 생성 (REQ-F-003)
// 이상징후를 시간순으로 정렬하고, ATT&CK 전술 순서로 공격 흐름도 구성.
// =====================================================================

export function buildTimeline(anomalies: AnomalyEvent[]): TimelineEvent[] {
  const sorted = [...anomalies].sort((a, b) => {
    if (a.timestamp && b.timestamp) return a.timestamp < b.timestamp ? -1 : 1;
    if (a.timestamp) return -1;
    if (b.timestamp) return 1;
    return a.lineNumber - b.lineNumber;
  });

  return sorted.map((a, i) => ({
    id: makeId('tl'),
    timestamp: a.timestamp,
    order: i + 1,
    title: a.category,
    phase: phaseForCategory(a.category),
    description: a.description,
    severity: a.severity,
    confidence: a.confidence,
    sourceIp: a.sourceIp,
  }));
}

/** 카테고리명 → kill-chain 단계 라벨 (대략적 매핑) */
function phaseForCategory(category: string): string {
  const c = category.toLowerCase();
  if (c.includes('스캐너') || c.includes('열거')) return 'Reconnaissance';
  if (c.includes('인젝션') || c.includes('log4shell') || c.includes('xss')) return 'Initial Access';
  if (c.includes('powershell') || c.includes('명령')) return 'Execution';
  if (c.includes('웹쉘') || c.includes('자동실행')) return 'Persistence';
  if (c.includes('권한')) return 'Privilege Escalation';
  if (c.includes('로그') && c.includes('삭제')) return 'Defense Evasion';
  if (c.includes('대입') || c.includes('인증') || c.includes('자격')) return 'Credential Access';
  if (c.includes('탐색')) return 'Discovery';
  if (c.includes('확산') || c.includes('lateral')) return 'Lateral Movement';
  if (c.includes('c2') || c.includes('비콘')) return 'Command and Control';
  if (c.includes('유출')) return 'Exfiltration';
  if (c.includes('랜섬') || c.includes('파괴')) return 'Impact';
  return 'Discovery';
}

export function buildAttackFlow(techniques: AttackTechnique[]): AttackFlow {
  if (techniques.length === 0) return { nodes: [], edges: [] };

  // 전술별로 그룹핑하여 단계 노드 구성
  const byTactic = new Map<string, AttackTechnique[]>();
  for (const t of techniques) {
    const arr = byTactic.get(t.tacticId) ?? [];
    arr.push(t);
    byTactic.set(t.tacticId, arr);
  }

  const orderedTactics = Array.from(byTactic.keys()).sort((a, b) => tacticOrder(a) - tacticOrder(b));

  const nodes: AttackFlowNode[] = [];
  for (const tacticId of orderedTactics) {
    const techs = byTactic.get(tacticId)!;
    const sev = maxSeverity(techs.map((t) => t.severity));
    nodes.push({
      id: tacticId,
      label: tacticName(tacticId),
      phase: TACTICS[tacticId]?.name ?? tacticId,
      techniqueId: techs.map((t) => t.id).join(', '),
      severity: sev,
    });
  }

  const edges: AttackFlowEdge[] = [];
  for (let i = 0; i < nodes.length - 1; i++) {
    edges.push({ from: nodes[i].id, to: nodes[i + 1].id });
  }

  return { nodes, edges };
}
