import type { AnalysisResult, Severity } from '@/types';
import { formatTimestamp, severityLabelKo, truncate } from '@/utils/format';

// =====================================================================
// 분석 가이드 보고서 → Word(.doc) 직렬화 (REQ-F-005 산출물)
// "핵심만" 원칙: 개요 · 핵심발견 · 사실/추정 · 추정 침입경로 · 주요 탐지근거 ·
// 우선 대응 — 딱 필요한 것만. (IOC 상세·ATT&CK표·CVE표·트래픽·MFT상세·ML·
// 스크립트 등 상세 표는 대시보드 화면에서 확인)
// =====================================================================

const esc = (s: unknown): string =>
  String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');

// 긴 경로·URL 이 Word 표 칸에서 줄바꿈되도록 구분자 뒤 zero-width space 삽입.
const wrapValue = (v: string): string =>
  esc(String(v ?? '').replace(/([/\\._:@=&?-])/g, '$1​'));

const SEV_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const sevIdx = (s: Severity): number => SEV_ORDER.indexOf(s);
const uniq = <T,>(a: T[]): T[] => Array.from(new Set(a));

// 심각도 색상 칩 — 한눈에 스캔되도록(Word 인라인 배경).
const SEV_HEX: Record<Severity, string> = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#d97706',
  low: '#16a34a',
  info: '#2563eb',
};
const sevTag = (s: Severity): string =>
  `<span style="display:inline-block;padding:0 6px;border-radius:3px;background:${SEV_HEX[s]};color:#fff;font-size:8.5pt;font-weight:600;white-space:nowrap">${severityLabelKo(s)}</span>`;

/** 핵심 발견 — 최상위 위협을 한눈에(불릿). */
function buildKeyFindings(r: AnalysisResult): string {
  const bullets: string[] = [];
  const bySev = (s: Severity) => r.anomalies.filter((a) => a.severity === s);
  const crit = bySev('critical');
  const high = bySev('high');
  if (r.intrusion) bullets.push(`추정 초기 침투: <b>${esc(r.intrusion.entryVector)}</b>`);
  if (crit.length)
    bullets.push(`심각 이상징후 <b>${crit.length}건</b> — ${esc(uniq(crit.map((a) => a.category)).slice(0, 4).join(', '))}`);
  if (high.length)
    bullets.push(`높음 이상징후 <b>${high.length}건</b> — ${esc(uniq(high.map((a) => a.category)).slice(0, 4).join(', '))}`);
  const critCve = r.cves.filter((c) => c.severity === 'critical');
  if (critCve.length) bullets.push(`치명적 CVE — ${esc(critCve.map((c) => c.id).join(', '))}`);
  const abn = [...r.traffic].filter((t) => t.classification === 'abnormal').sort((a, b) => b.anomalyScore - a.anomalyScore);
  if (abn.length) bullets.push(`비정상 트래픽 출발지 <b>${abn.length}개</b> — 최상위 <b>${esc(abn[0].sourceIp)}</b>`);
  if (r.kind === 'mft' && r.mft)
    bullets.push(`삭제 정황 레코드 <b>${r.mft.inactiveCount.toLocaleString()}건</b> / 전체 ${r.mft.totalRecords.toLocaleString()}건`);
  if (!bullets.length) return '';
  return `
  <h2>핵심 발견</h2>
  <ul>${bullets.map((b) => `<li>${b}</li>`).join('')}</ul>`;
}

/** 추정 침입 경로 — 초기 침투 + 서술 + 간결 단계표. */
function buildIntrusionSection(r: AnalysisResult): string {
  const it = r.intrusion;
  if (!it) return '';
  const stepRows = it.steps
    .map(
      (s) => `<tr>
        <td class="c">${esc(s.order)}</td>
        <td>${esc(s.phase)}</td>
        <td>${esc(s.title)}</td>
        <td class="c">${sevTag(s.severity)}</td>
        <td class="val">${esc(s.techniqueIds.join(', '))}</td>
      </tr>`,
    )
    .join('');
  return `
  <h2>추정 침입 경로 <span class="hint">(Assessment · 추정)</span></h2>
  <p><b>초기 침투 경로:</b> ${esc(it.entryVector)}</p>
  <p>${esc(it.narrative)}</p>
  <table class="ti">
    <colgroup><col style="width:6%"><col style="width:24%"><col style="width:42%"><col style="width:11%"><col style="width:17%"></colgroup>
    <tr><th>#</th><th>단계</th><th>핵심 행위</th><th>심각도</th><th>기법</th></tr>
    ${stepRows || '<tr><td colspan="5">—</td></tr>'}
  </table>`;
}

/** 주요 탐지 이상징후 — 원본 스니펫 포함(핵심 근거). 상위 12건. */
function buildEvidenceSection(r: AnalysisResult): string {
  if (!r.anomalies.length) return '';
  const sorted = [...r.anomalies].sort((a, b) => {
    const d = sevIdx(a.severity) - sevIdx(b.severity);
    if (d !== 0) return d;
    if (a.timestamp && b.timestamp) return a.timestamp < b.timestamp ? -1 : 1;
    return a.lineNumber - b.lineNumber;
  });
  const shown = sorted.slice(0, 12);
  const rows = shown
    .map(
      (a) => `<tr>
        <td class="c">${sevTag(a.severity)}</td>
        <td class="c">${esc(a.timestamp ? formatTimestamp(a.timestamp) : '—')}</td>
        <td>${esc(a.category)}</td>
        <td class="c">${esc(a.sourceIp ?? '—')}</td>
        <td class="val">${wrapValue(truncate(a.evidence, 64))}</td>
      </tr>`,
    )
    .join('');
  return `
  <h2>주요 탐지 이상징후 <span class="hint">(근거)</span></h2>
  <table class="ti">
    <colgroup><col style="width:11%"><col style="width:18%"><col style="width:24%"><col style="width:14%"><col style="width:33%"></colgroup>
    <tr><th>심각도</th><th>시각</th><th>유형</th><th>출발지</th><th>근거(원본)</th></tr>
    ${rows}
  </table>
  ${sorted.length > shown.length ? `<p class="req">※ 상위 ${shown.length}건(전체 ${sorted.length}건은 대시보드).</p>` : ''}`;
}

/** 우선 대응 — 상위 3단계만 간결히. */
function buildRecommendation(r: AnalysisResult): string {
  const steps = r.report.steps.slice(0, 3);
  if (!steps.length) return '';
  const items = steps
    .map(
      (s) => `<li><b>${esc(s.title)}</b> ${sevTag(s.priority)}<br>${esc(s.actions[0] ?? '')}</li>`,
    )
    .join('');
  return `
  <h2>우선 대응 권고</h2>
  <ol>${items}</ol>`;
}

/**
 * 분석 결과를 Word 호환 HTML(.doc)로 직렬화. 별도 라이브러리 없이
 * application/msword 로 저장 — Word·Google Docs·LibreOffice 에서 바로 열린다.
 */
export function buildWordReport(r: AnalysisResult): string {
  const engine = r.report.engine === 'ai' ? '생성형 AI' : '로컬 규칙기반';
  const unitLabel = r.kind === 'mft' ? 'MFT 레코드' : '로그 라인';
  const unitCount = r.kind === 'mft' ? r.mft?.totalRecords ?? 0 : r.logs.length;
  const critCount = r.anomalies.filter((a) => a.severity === 'critical').length;
  const highCount = r.anomalies.filter((a) => a.severity === 'high').length;

  const facts = r.report.factsVsAssessments.facts.map((f) => `<li>${esc(f)}</li>`).join('');
  const assessments = r.report.factsVsAssessments.assessments.map((a) => `<li>${esc(a)}</li>`).join('');

  return `<!DOCTYPE html>
<html xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:w="urn:schemas-microsoft-com:office:word" xmlns="http://www.w3.org/TR/REC-html40">
<head>
<meta charset="utf-8">
<title>AI 포렌식 분석 보고서</title>
<style>
  @page WordSection1 { size: 21.0cm 29.7cm; margin: 2.0cm 2.0cm 2.0cm 2.0cm; }
  div.WordSection1 { page: WordSection1; }
  body { font-family: 'Malgun Gothic', 'Segoe UI', sans-serif; font-size: 11pt; color: #18181b; line-height: 1.6; }
  h1 { font-size: 22pt; color: #5b21b6; border-bottom: 3px solid #6d28d9; padding-bottom: 8px; }
  h2 { font-size: 15pt; color: #18181b; border-bottom: 1px solid #d4d4dc; padding-bottom: 4px; margin-top: 24px; }
  .hint { font-size: 10pt; color: #8a8a94; font-weight: 400; }
  table { border-collapse: collapse; width: 100%; table-layout: fixed; margin: 8px 0; font-size: 10pt; }
  th { background: #f3f0fb; border: 1px solid #d4d4dc; padding: 6px 8px; text-align: left; color: #5b21b6; vertical-align: top; }
  td { border: 1px solid #e4e4ea; padding: 6px 8px; vertical-align: top; word-wrap: break-word; overflow-wrap: break-word; }
  td.c { text-align: center; white-space: nowrap; }
  td.val { font-family: 'Consolas','Courier New',monospace; font-size: 8.5pt; word-break: break-all; overflow-wrap: anywhere; }
  ul, ol { margin: 4px 0; padding-left: 22px; }
  li { margin-bottom: 5px; }
  .meta { table-layout: auto; }
  .meta td { border: none; padding: 2px 10px 2px 0; }
  .meta th { background: none; border: none; color: #6c6c78; font-weight: 600; padding: 2px 10px 2px 0; width: 110px; }
  .req { color: #8a8a94; font-size: 9pt; margin: 2px 0; }
  .disclaimer { margin-top: 26px; padding-top: 10px; border-top: 1px solid #d4d4dc; color: #6c6c78; font-size: 9.5pt; }
</style>
</head>
<body>
<div class="WordSection1">
  <h1>AI 포렌식 분석 보고서</h1>
  <table class="meta">
    <tr><th>대상 파일</th><td>${esc(r.fileName)} (${esc(r.format.toUpperCase())})</td></tr>
    <tr><th>분석 일시</th><td>${esc(formatTimestamp(r.parsedAt))}</td></tr>
    <tr><th>분석 엔진</th><td>${esc(engine)}</td></tr>
    <tr><th>처리량</th><td>${esc(unitCount.toLocaleString())} ${esc(unitLabel)}</td></tr>
    <tr><th>탐지 요약</th><td>이상징후 ${esc(r.anomalies.length)}건(심각 ${esc(critCount)} · 높음 ${esc(highCount)}) · IOC ${esc(r.iocs.length)} · ATT&amp;CK ${esc(r.techniques.length)} · CVE ${esc(r.cves.length)}</td></tr>
  </table>

  <h2>개요</h2>
  <p>${esc(r.report.narrative)}</p>
  ${buildKeyFindings(r)}

  <h2>사실 (Fact) <span class="hint">/ 추정 (Assessment) — REQ-NF-002</span></h2>
  <ul>${facts || '<li>—</li>'}</ul>
  <p class="req"><b>추정(분석가 검증 필요)</b></p>
  <ul>${assessments || '<li>—</li>'}</ul>
  ${buildIntrusionSection(r)}
  ${buildEvidenceSection(r)}
  ${buildRecommendation(r)}

  <p class="disclaimer">본 보고서는 AI/규칙 기반 분석 <b>보조 산출물</b>이며, 최종 판단은 분석가의 교차검증을 병행합니다. 상세(ATT&amp;CK·IOC·트래픽·MFT·ML·대응 스크립트)는 대시보드에서 확인하십시오. (REQ-NF-002 · 제약사항)</p>
</div>
</body>
</html>`;
}

export function downloadReport(r: AnalysisResult): void {
  const html = buildWordReport(r);
  // BOM + application/msword → Word 가 UTF-8 한글을 올바르게 인식
  const blob = new Blob(['﻿' + html], { type: 'application/msword;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `forensic-report_${r.fileName.replace(/\.[^.]+$/, '')}.doc`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
