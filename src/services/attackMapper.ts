import type { AttackTechnique, CVE, IOC, LogEntry, Severity } from '@/types';
import { SIGNATURES, TACTICS, techniqueUrl, tacticName } from '@/data/mitreAttack';
import { CVE_DB, cvePatternList } from '@/data/cveDatabase';
import { maxSeverity, truncate } from '@/utils/format';

// =====================================================================
// 위협 매핑 (REQ-F-002)
// 로그 → MITRE ATT&CK 기법 + 관련 CVE. 모든 매핑은 근거(evidence) 동반.
// =====================================================================

interface MapResult {
  techniques: AttackTechnique[];
  cves: CVE[];
}

export function mapThreats(logs: LogEntry[], iocs: IOC[]): MapResult {
  const techMap = new Map<string, AttackTechnique>();
  const cveMap = new Map<string, CVE>();

  const ensureTechnique = (sigKey: string, base: Omit<AttackTechnique, 'matchedEvidence' | 'relatedCves' | 'severity'> & { severity: Severity; cves: string[] }) => {
    let t = techMap.get(sigKey);
    if (!t) {
      t = {
        id: base.id,
        name: base.name,
        tactic: base.tactic,
        tacticId: base.tacticId,
        description: base.description,
        url: base.url,
        matchedEvidence: [],
        confidence: base.confidence,
        relatedCves: [...base.cves],
        severity: base.severity,
      };
      techMap.set(sigKey, t);
    }
    return t;
  };

  // --- 시그니처 기반 기법 매핑 ---
  for (const log of logs) {
    const text = log.raw || log.message;
    for (const sig of SIGNATURES) {
      if (sig.patterns.some((p) => p.test(text))) {
        const key = sig.techniqueId;
        const t = ensureTechnique(key, {
          id: sig.techniqueId,
          name: sig.techniqueName,
          tactic: tacticName(sig.tacticId),
          tacticId: sig.tacticId,
          description: sig.description,
          url: techniqueUrl(sig.techniqueId),
          confidence: 'fact',
          severity: sig.severity,
          cves: sig.cveIds,
        });
        if (t.matchedEvidence.length < 12) {
          t.matchedEvidence.push(`L${log.lineNumber}: ${truncate(text.trim(), 160)}`);
        }
        t.severity = maxSeverity([t.severity, sig.severity]);
        for (const c of sig.cveIds) if (!t.relatedCves.includes(c)) t.relatedCves.push(c);
      }
    }
  }

  // --- IOC 중 CVE 타입 → CVE 직접 등록 ---
  for (const ioc of iocs) {
    if (ioc.type === 'cve') {
      const id = ioc.value.toUpperCase();
      registerCve(cveMap, id, ioc.relatedLogIds.map((_, i) => `IOC 관측 ${i + 1}`).slice(0, 1).concat([`값: ${ioc.value} (×${ioc.count})`]));
    }
  }

  // --- 로그 본문 CVE 시그니처 직접 매칭 ---
  for (const log of logs) {
    const text = log.raw || log.message;
    for (const { id, pattern } of cvePatternList()) {
      if (pattern.test(text)) {
        registerCve(cveMap, id, [`L${log.lineNumber}: ${truncate(text.trim(), 160)}`]);
      }
    }
  }

  // --- 기법 ↔ CVE 상호 연결 ---
  for (const t of techMap.values()) {
    for (const cveId of t.relatedCves) {
      const cve = registerCve(cveMap, cveId, []);
      if (cve && !cve.matchedTechniques.includes(t.id)) cve.matchedTechniques.push(t.id);
    }
  }

  const techniques = Array.from(techMap.values()).sort(
    (a, b) => (TACTICS[a.tacticId]?.order ?? 99) - (TACTICS[b.tacticId]?.order ?? 99),
  );
  const cves = Array.from(cveMap.values()).sort((a, b) => b.cvss - a.cvss);

  return { techniques, cves };
}

function registerCve(map: Map<string, CVE>, id: string, evidence: string[]): CVE | undefined {
  const entry = CVE_DB[id];
  let cve = map.get(id);
  if (!cve) {
    cve = {
      id,
      description: entry?.description ?? '비공개/미등록 CVE — NVD 참조 필요.',
      cvss: entry?.cvss ?? 0,
      severity: entry?.severity ?? 'medium',
      url: `https://nvd.nist.gov/vuln/detail/${id}`,
      matchedTechniques: [],
      evidence: [],
    };
    map.set(id, cve);
  }
  for (const e of evidence) if (e && !cve.evidence.includes(e)) cve.evidence.push(e);
  return cve;
}
