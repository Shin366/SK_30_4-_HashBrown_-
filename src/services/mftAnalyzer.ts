import type {
  AnomalyEvent,
  AttackTechnique,
  IOC,
  MftAnalysis,
  MftFinding,
  MftRecord,
  Severity,
  TimelineEvent,
} from '@/types';
import {
  ARTIFACT_PATH,
  BENIGN_FILENAME,
  DOUBLE_EXT,
  DRIVE_ROOT_EXE,
  EXECUTABLE_EXT,
  EXPECTED_EXE_AREA,
  KNOWN_ADS,
  LEGIT_SYS_PATH,
  MFT_TECH,
  PROTECTED_PROC,
  SUSPICIOUS_DIRS,
  SYSTEM_DIRS,
  TOOL_SIGNATURES,
  type MftTechnique,
} from '@/data/mftRules';
import { techniqueUrl } from '@/data/mitreAttack';
import { virusTotalUrl } from '@/data/iocPatterns';
import { makeId, maxSeverity, severityRank, truncate } from '@/utils/format';

// =====================================================================
// MFT 이상 파일 탐지 (REQ-F-001, REQ-F-002, REQ-F-003)
// 컬럼 기반(정규식이 아닌 구조적) 분석으로 대용량(수십만 행) 처리.
// =====================================================================

const FINDING_CAP = 3000; // 화면 표시/저장 상한 (카운트는 별도 집계)

function isSystemPath(p: string): boolean {
  return SYSTEM_DIRS.some((re) => re.test(p));
}

function suspiciousDir(p: string): { label: string; sev: Severity } | null {
  for (const d of SUSPICIOUS_DIRS) if (d.re.test(p)) return { label: d.label, sev: d.sev };
  return null;
}

function bump(s: Severity): Severity {
  if (s === 'low') return 'medium';
  if (s === 'medium') return 'high';
  return s; // high/critical 유지
}

interface RawFinding extends Omit<MftFinding, 'id'> {
  tech: MftTechnique;
}

export interface MftResult {
  mft: MftAnalysis;
  anomalies: AnomalyEvent[];
  techniques: AttackTechnique[];
  iocs: IOC[];
  timeline: TimelineEvent[];
}

export function analyzeMft(records: MftRecord[]): MftResult {
  let fileCount = 0;
  let folderCount = 0;
  let activeCount = 0;
  let inactiveCount = 0;
  let datedRecords = 0;
  let siFnMismatch = 0;
  let tsLogicAnomaly = 0;

  const raw: RawFinding[] = [];
  const catCount = new Map<string, { count: number; severity: Severity }>();

  const push = (f: RawFinding) => {
    // 카테고리별 카운트는 상한과 무관하게 누적
    const c = catCount.get(f.category) ?? { count: 0, severity: 'info' as Severity };
    c.count += 1;
    c.severity = maxSeverity([c.severity, f.severity]);
    catCount.set(f.category, c);
    if (raw.length < FINDING_CAP * 2) raw.push(f);
  };

  for (const rec of records) {
    const isFolder = /folder|directory/i.test(rec.recordType);
    if (isFolder) folderCount += 1;
    else fileCount += 1;
    if (rec.active) activeCount += 1;
    else inactiveCount += 1;
    if (rec.siCreated || rec.fnCreated) datedRecords += 1;

    const lp = rec.path.toLowerCase();
    if (!lp) continue; // 이름 없는 레코드: 총계엔 포함, 개별 분석은 제외

    const isExe = EXECUTABLE_EXT.has(rec.ext) && !BENIGN_FILENAME.test(rec.fileName);
    const inSystem = isSystemPath(lp);
    const artifact = ARTIFACT_PATH.test(rec.path); // MFT 경로 재구성 아티팩트
    const orphan = /^(nofnrecord|nosirecord|\.)/i.test(rec.path) || !rec.path.startsWith('/');
    const sus = suspiciousDir(lp);
    const driveRoot = DRIVE_ROOT_EXE.test(rec.path) && !BENIGN_FILENAME.test(rec.fileName);

    // 타임스탬프 신호 사전 계산 (정보성 — 단독 경보 아님)
    const si = rec.siCreated ? Date.parse(rec.siCreated) : NaN;
    const fn = rec.fnCreated ? Date.parse(rec.fnCreated) : NaN;
    const siMod = rec.siModified ? Date.parse(rec.siModified) : NaN;
    const siBeforeFn = !inSystem && !Number.isNaN(si) && !Number.isNaN(fn) && fn - si > 86400_000;
    if (siBeforeFn) siFnMismatch += 1;
    const siCreatedAfterMod = !Number.isNaN(si) && !Number.isNaN(siMod) && si - siMod > 3600_000;
    if (!inSystem && siCreatedAfterMod) tsLogicAnomaly += 1;
    const tsAnomaly = siBeforeFn || siCreatedAfterMod;

    // --- A. 공격 도구 / C2 파일명 (경로 무관, 파일명 정확 매칭) ---
    let toolHit = false;
    for (const sig of TOOL_SIGNATURES) {
      if (sig.re.test(rec.fileName)) {
        toolHit = true;
        push({
          recordNumber: rec.recordNumber, path: rec.path, fileName: rec.fileName,
          category: sig.label, severity: sig.sev,
          description: `공격도구/C2 파일명 일치: ${rec.fileName}${rec.active ? '' : ' · 삭제됨'}${sig.note ? ` — ${sig.note}` : ''}`,
          confidence: 'fact', techniqueId: sig.tech.id, tech: sig.tech,
          siCreated: rec.siCreated, fnCreated: rec.fnCreated, active: rec.active,
        });
      }
    }

    // --- B/C: 파일명 기반 (시스템 경로·재구성 아티팩트 제외) ---
    if (!inSystem && !artifact) {
      // B. 이중 확장자 위장
      if (DOUBLE_EXT.test(rec.fileName)) {
        push({
          recordNumber: rec.recordNumber, path: rec.path, fileName: rec.fileName,
          category: '이중 확장자 위장', severity: 'high',
          description: `문서/이미지로 위장한 실행파일 이름: ${rec.fileName}`,
          confidence: 'fact', techniqueId: MFT_TECH.doubleExt.id, tech: MFT_TECH.doubleExt,
          siCreated: rec.siCreated, fnCreated: rec.fnCreated, active: rec.active,
        });
      }
      // C. ADS — NTFS 시스템 스트림($)·정상 스트림 제외
      const colonIdx = rec.fileName.indexOf(':');
      const stream = colonIdx > 0 ? rec.fileName.slice(colonIdx + 1) : '';
      const ntfsMeta = lp.startsWith('/$') || rec.fileName.startsWith('$') || stream.startsWith('$');
      if (colonIdx > 0 && !ntfsMeta && !KNOWN_ADS.test(rec.fileName)) {
        push({
          recordNumber: rec.recordNumber, path: rec.path, fileName: rec.fileName,
          category: '대체 데이터 스트림(ADS)', severity: 'medium',
          description: `비표준 NTFS 대체 데이터 스트림: ${rec.fileName}`,
          confidence: 'fact', techniqueId: MFT_TECH.ntfsAttr.id, tech: MFT_TECH.ntfsAttr,
          siCreated: rec.siCreated, fnCreated: rec.fnCreated, active: rec.active,
        });
      }
    }

    // --- D. 보호 시스템 프로세스명 위장 (정규 경로 밖) ---
    if (!artifact && PROTECTED_PROC.has(rec.fileName.toLowerCase()) && !LEGIT_SYS_PATH.test(lp)) {
      push({
        recordNumber: rec.recordNumber, path: rec.path, fileName: rec.fileName,
        category: '시스템 프로세스명 위장', severity: 'high',
        description: `시스템 프로세스명(${rec.fileName})이 비정상 경로에 존재.`,
        confidence: 'assessment', techniqueId: MFT_TECH.masqName.id, tech: MFT_TECH.masqName,
        siCreated: rec.siCreated, fnCreated: rec.fnCreated, active: rec.active,
      });
    }

    // --- E. 의심 위치 / 드라이브 루트의 실행·스크립트 파일 ---
    if (isExe && !artifact && !orphan && !toolHit && (sus || driveRoot)) {
      const isPs = rec.ext.startsWith('ps');
      const tech = isPs ? MFT_TECH.powershell : MFT_TECH.ingressTool;
      const locLabel = sus ? sus.label : '드라이브 루트';
      let sev: Severity = sus ? sus.sev : 'high';
      if (!rec.active) sev = bump(sev);
      const tsNote = tsAnomaly ? ' · 타임스탬프 이상 동반(복사 가능성 포함)' : '';
      push({
        recordNumber: rec.recordNumber, path: rec.path, fileName: rec.fileName,
        category: `의심 위치 실행파일 (${locLabel})`, severity: sev,
        description: `악용 빈번 경로의 ${rec.ext.toUpperCase()} 파일${rec.active ? '' : ' · 삭제됨'}${tsNote}`,
        confidence: 'assessment', techniqueId: tech.id, tech,
        siCreated: rec.siCreated, fnCreated: rec.fnCreated, active: rec.active,
      });
    }

    // --- F. 삭제된(Inactive) 실행파일 (시스템·정상영역·의심위치·아티팩트·고아·도구 외) ---
    const inExpectedArea = EXPECTED_EXE_AREA.some((re) => re.test(lp));
    if (!rec.active && isExe && !inSystem && !artifact && !orphan && !toolHit && !sus && !driveRoot && !inExpectedArea) {
      push({
        recordNumber: rec.recordNumber, path: rec.path, fileName: rec.fileName,
        category: '삭제된 실행파일', severity: 'medium',
        description: `삭제 정황(Inactive)의 ${rec.ext.toUpperCase()} 파일 (비정상 위치)`,
        confidence: 'fact', techniqueId: MFT_TECH.fileDeletion.id, tech: MFT_TECH.fileDeletion,
        siCreated: rec.siCreated, fnCreated: rec.fnCreated, active: rec.active,
      });
    }
  }

  // findings 정렬 + 상한 적용
  const sorted = raw.sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
  const findings: MftFinding[] = sorted.slice(0, FINDING_CAP).map((f) => ({
    id: makeId('mftf'),
    recordNumber: f.recordNumber, path: f.path, fileName: f.fileName,
    category: f.category, description: f.description, severity: f.severity,
    confidence: f.confidence, techniqueId: f.techniqueId,
    siCreated: f.siCreated, fnCreated: f.fnCreated, active: f.active,
  }));

  const findingsByCategory = Array.from(catCount.entries())
    .map(([category, v]) => ({ category, count: v.count, severity: v.severity }))
    .sort((a, b) => b.count - a.count);

  const mft: MftAnalysis = {
    totalRecords: records.length,
    fileCount, folderCount, activeCount, inactiveCount, datedRecords,
    siFnMismatchCount: siFnMismatch,
    tsLogicAnomalyCount: tsLogicAnomaly,
    findings, findingsByCategory,
  };

  // --- 파생: anomalies / techniques / iocs / timeline ---
  const anomalies: AnomalyEvent[] = findings.map((f) => ({
    id: makeId('anom'),
    logId: `mft_${f.recordNumber}`,
    lineNumber: f.recordNumber,
    timestamp: f.siCreated,
    category: f.category,
    description: f.description,
    severity: f.severity,
    confidence: f.confidence,
    evidence: truncate(f.path, 240),
  }));

  const techniques = buildTechniques(sorted);
  const iocs = buildIocs(sorted);
  const timeline = buildTimeline(findings);

  return { mft, anomalies, techniques, iocs, timeline };
}

function buildTechniques(findings: RawFinding[]): AttackTechnique[] {
  const map = new Map<string, AttackTechnique>();
  for (const f of findings) {
    const t = f.tech;
    let entry = map.get(t.id);
    if (!entry) {
      entry = {
        id: t.id, name: t.name, tactic: t.tactic, tacticId: t.tacticId,
        description: `MFT 아티팩트 기반 매핑: ${f.category}`,
        url: techniqueUrl(t.id),
        matchedEvidence: [], confidence: f.confidence, relatedCves: [], severity: f.severity,
      };
      map.set(t.id, entry);
    }
    if (entry.matchedEvidence.length < 12) entry.matchedEvidence.push(`#${f.recordNumber}: ${truncate(f.path, 150)}`);
    entry.severity = maxSeverity([entry.severity, f.severity]);
  }
  return Array.from(map.values()).sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
}

function buildIocs(findings: RawFinding[]): IOC[] {
  const map = new Map<string, IOC>();
  for (const f of findings) {
    if (severityRank(f.severity) < severityRank('high')) continue; // high+ 만 IOC 화
    const key = f.path.toLowerCase();
    const ex = map.get(key);
    if (ex) {
      ex.count += 1;
    } else {
      map.set(key, {
        id: makeId('ioc'), type: 'filepath', value: f.path, count: 1,
        firstSeen: f.siCreated, lastSeen: f.siCreated, severity: f.severity,
        relatedLogIds: [`mft_${f.recordNumber}`],
        vtReference: virusTotalUrl('filepath', f.fileName),
      });
    }
  }
  return Array.from(map.values()).sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
}

function buildTimeline(findings: MftFinding[]): TimelineEvent[] {
  const dated = findings.filter((f) => f.siCreated);
  dated.sort((a, b) => (a.siCreated! < b.siCreated! ? -1 : 1));
  return dated.slice(0, 80).map((f, i) => ({
    id: makeId('tl'),
    timestamp: f.siCreated,
    order: i + 1,
    title: `${f.fileName} — ${f.category}`,
    phase: 'File System Artifact',
    description: truncate(f.path, 160),
    severity: f.severity,
    confidence: f.confidence,
  }));
}
