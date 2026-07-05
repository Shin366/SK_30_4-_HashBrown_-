import type { AnalysisResult } from '@/types';
import { resetIdCounter } from '@/utils/format';
import { parseLogs } from './logParser';
import { detectAnomalies } from './anomalyDetector';
import { extractIocs } from './iocExtractor';
import { mapThreats } from './attackMapper';
import { analyzeTraffic } from './trafficAnalyzer';
import { buildAttackFlow, buildTimeline } from './timelineBuilder';
import { buildIntrusionHypothesis } from './intrusionHypothesis';
import { generateReport } from './reportGenerator';
import { isMftTable, parseMft } from './mftParser';
import { analyzeMft } from './mftAnalyzer';
import { analyzeLogsMl, analyzeMftMl } from './mlAnalyzer';
import type { IngestResult } from './fileIngest';

// =====================================================================
// 분석 오케스트레이터 (REQ-F-006 통합)
// 적재 결과(text/rows) → MFT 또는 로그 파이프라인 → AnalysisResult.
// 전부 로컬(브라우저)에서 동작 (REQ-NF-005).
// =====================================================================

export interface RunOptions {
  ingest: IngestResult;
  nowIso: string;
}

export function runAnalysis(opts: RunOptions): AnalysisResult {
  resetIdCounter();
  const { ingest, nowIso } = opts;

  // 1) MFT 표 우선 감지 (xlsx/csv)
  if (ingest.kind === 'rows' && ingest.rows && ingest.rows.length > 1 && isMftTable(ingest.rows[0])) {
    return analyzeMftResult(ingest, nowIso);
  }

  // 2) 일반 로그 경로 (text, 또는 비-MFT 표 → CSV 텍스트로 변환)
  const content =
    ingest.kind === 'text' ? ingest.text ?? '' : ingest.text ?? rowsToCsv(ingest.rows ?? []);
  return analyzeLogResult(ingest.fileName, ingest.fileSize, content, nowIso);
}

function analyzeMftResult(ingest: IngestResult, nowIso: string): AnalysisResult {
  const records = parseMft(ingest.rows!);
  const { mft, anomalies, techniques, iocs, timeline } = analyzeMft(records);
  const ml = analyzeMftMl(records);
  const attackFlow = buildAttackFlow(techniques);
  const intrusion = buildIntrusionHypothesis(techniques, timeline, iocs);
  const report = generateReport(
    {
      logs: [],
      anomalies,
      iocs,
      techniques,
      cves: [],
      traffic: [],
      unitCount: mft.totalRecords,
      unitLabel: 'MFT 레코드',
    },
    nowIso,
  );
  if (ml) report.factsVsAssessments.facts.push(`[ML] ${ml.summary}`);

  return {
    kind: 'mft',
    fileName: ingest.fileName,
    fileSize: ingest.fileSize,
    format: 'mft',
    parsedAt: nowIso,
    logs: [],
    anomalies,
    iocs,
    techniques,
    cves: [],
    timeline,
    attackFlow,
    traffic: [],
    report,
    mft,
    ml,
    intrusion,
  };
}

function analyzeLogResult(
  fileName: string,
  fileSize: number,
  content: string,
  nowIso: string,
): AnalysisResult {
  const { entries: logs, format } = parseLogs(fileName, content);
  const anomalies = detectAnomalies(logs);
  const iocs = extractIocs(logs);
  const { techniques, cves } = mapThreats(logs, iocs);
  const traffic = analyzeTraffic(logs);
  const ml = analyzeLogsMl(logs);
  const timeline = buildTimeline(anomalies);
  const attackFlow = buildAttackFlow(techniques);
  const intrusion = buildIntrusionHypothesis(techniques, timeline, iocs);
  const report = generateReport({ logs, anomalies, iocs, techniques, cves, traffic }, nowIso);
  if (ml) report.factsVsAssessments.facts.push(`[ML] ${ml.summary}`);

  return {
    kind: 'log',
    fileName,
    fileSize,
    format,
    parsedAt: nowIso,
    logs,
    anomalies,
    iocs,
    techniques,
    cves,
    timeline,
    attackFlow,
    traffic,
    report,
    ml,
    intrusion,
  };
}

function rowsToCsv(rows: string[][]): string {
  return rows
    .map((r) => r.map((c) => (/[",\n]/.test(c) ? `"${c.replace(/"/g, '""')}"` : c)).join(','))
    .join('\n');
}
