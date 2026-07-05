// =====================================================================
// 특징 공학(Feature Engineering) — 로그/MFT 를 수치 벡터로 변환
// Isolation Forest 등 수치 기반 모델의 입력. 시그니처 대신 일반적인
// 통계 특징(길이·엔트로피·문자군 비율·시간·상태코드 등)을 사용해
// "무엇이 튀는지"를 데이터가 스스로 드러내게 한다(비하드코딩).
// =====================================================================

import type { LogEntry, MftRecord } from '@/types';
import { charStats, shannonEntropy } from './text';
import { SUSPICIOUS_DIRS, DOUBLE_EXT } from '@/data/mftRules';

// ---- 로그 특징 ----------------------------------------------------------
export const LOG_FEATURE_NAMES = [
  'hour',            // 발생 시각(0..23) 정규화
  'urlLen',          // URL 길이
  'msgEntropy',      // 메시지 엔트로피
  'digitRatio',      // 숫자 비율
  'specialRatio',    // 특수문자 비율
  'statusClass',     // 상태코드 계열(2/3/4/5)
  'bytesLog',        // 응답 크기(log)
  'paramCount',      // 쿼리 파라미터 수
  'uaEntropy',       // User-Agent 엔트로피
  'nonAscii',        // 비ASCII 비율
];

function hourOf(ts: string | null): number {
  if (!ts) return 12 / 23;
  const h = new Date(ts).getHours();
  return isNaN(h) ? 12 / 23 : h / 23;
}

export function logFeatures(log: LogEntry): number[] {
  const url = log.url ?? '';
  const msg = log.raw || log.message || '';
  const cs = charStats(msg);
  const status = log.statusCode ?? 0;
  const statusClass = status >= 500 ? 1 : status >= 400 ? 0.75 : status >= 300 ? 0.4 : status >= 200 ? 0.15 : 0;
  const bytes = log.bytes ?? 0;
  const paramCount = (url.match(/[?&]/g) || []).length;
  const ua = log.userAgent ?? '';
  let nonAscii = 0;
  for (const ch of msg) if (ch.charCodeAt(0) > 127) nonAscii++;
  return [
    hourOf(log.timestamp),
    Math.min(1, url.length / 200),
    Math.min(1, cs.entropy / 6),
    cs.digitRatio,
    cs.specialRatio,
    statusClass,
    Math.min(1, Math.log10(1 + bytes) / 6),
    Math.min(1, paramCount / 6),
    Math.min(1, shannonEntropy(ua) / 6),
    Math.min(1, nonAscii / Math.max(1, msg.length)),
  ];
}

/** IF 이상 근거를 사람이 읽을 수 있게: 표준화 대비 튀는 상위 특징명 반환. */
export function topLogReasons(vec: number[], mean: number[], std: number[]): string[] {
  const labelMap: Record<string, string> = {
    hour: '비정상 시간대',
    urlLen: '비정상적으로 긴 URL',
    msgEntropy: '높은 문자 엔트로피(난독/인코딩)',
    digitRatio: '숫자 비율 이상',
    specialRatio: '특수문자 과다',
    statusClass: '오류 상태코드',
    bytesLog: '응답 크기 이상',
    paramCount: '쿼리 파라미터 과다',
    uaEntropy: '비정상 User-Agent',
    nonAscii: '비ASCII 문자 포함',
  };
  const z = vec.map((v, i) => ({
    name: LOG_FEATURE_NAMES[i],
    z: std[i] > 1e-6 ? Math.abs(v - mean[i]) / std[i] : 0,
  }));
  return z
    .filter((x) => x.z > 1.5)
    .sort((a, b) => b.z - a.z)
    .slice(0, 3)
    .map((x) => labelMap[x.name] ?? x.name);
}

// ---- MFT 특징 -----------------------------------------------------------
export const MFT_FEATURE_NAMES = [
  'nameEntropy',     // 파일명 엔트로피(랜덤 드롭퍼 탐지)
  'nameLen',         // 파일명 길이
  'pathDepth',       // 경로 깊이
  'extRisk',         // 확장자 위험군
  'inactive',        // 삭제 여부(0/1)
  'siFnDelta',       // $SI/$FN 생성시각 차(로그) — 타임스톰프
  'siCreatedHour',   // 생성 시각대
  'digitRatio',      // 파일명 숫자 비율
  'suspiciousLoc',   // 의심 위치(Temp/휴지통/사용자쓰기) — 희소 강신호
  'doubleExt',       // 이중 확장자 위장 — 희소 강신호
];

const RISKY_EXT = new Set(['exe', 'dll', 'ps1', 'bat', 'vbs', 'js', 'jsp', 'jspx', 'php', 'aspx', 'asp', 'scr', 'hta', 'jar', 'sys', 'db']);

function parseTs(s: string | null): number {
  if (!s) return NaN;
  const t = new Date(s).getTime();
  return isNaN(t) ? NaN : t;
}

export function mftFeatures(rec: MftRecord): number[] {
  const name = rec.fileName || '';
  const cs = charStats(name);
  const depth = (rec.path.match(/[\\/]/g) || []).length;
  const extRisk = RISKY_EXT.has(rec.ext) ? 1 : 0;
  const si = parseTs(rec.siCreated);
  const fn = parseTs(rec.fnCreated);
  let siFnDelta = 0;
  if (!isNaN(si) && !isNaN(fn)) {
    const diffSec = Math.abs(si - fn) / 1000;
    siFnDelta = Math.min(1, Math.log10(1 + diffSec) / 8); // 초 단위 차 → log 스케일
  }
  let hour = 12 / 23;
  if (!isNaN(si)) hour = new Date(si).getHours() / 23;
  // 강신호 특징: 대다수 파일은 0 이고 위협만 1 이라 IF 가 1~2 분할로 빠르게
  // 고립 → 실제 위협(Temp·휴지통 삭제 도구, 이중확장자 위장)의 이상 점수가
  // 정상 대비 확실히 벌어진다(거친 이진 특징만으론 점수가 0.6대에 뭉치던 문제 해소).
  const lp = rec.path.toLowerCase();
  const suspiciousLoc = SUSPICIOUS_DIRS.some((d) => d.re.test(lp)) ? 1 : 0;
  const doubleExt = DOUBLE_EXT.test(name) ? 1 : 0;
  return [
    Math.min(1, cs.entropy / 5),
    Math.min(1, name.length / 40),
    Math.min(1, depth / 12),
    extRisk,
    rec.active ? 0 : 1,
    siFnDelta,
    hour,
    cs.digitRatio,
    suspiciousLoc,
    doubleExt,
  ];
}

export function topMftReasons(vec: number[], mean: number[], std: number[]): string[] {
  const labelMap: Record<string, string> = {
    nameEntropy: '무작위성 높은 파일명',
    nameLen: '비정상 파일명 길이',
    pathDepth: '비정상 경로 깊이',
    extRisk: '실행/스크립트 확장자',
    inactive: '삭제된 레코드',
    siFnDelta: '$SI/$FN 생성시각 불일치(타임스톰프)',
    siCreatedHour: '비정상 생성 시간대',
    digitRatio: '파일명 숫자 비율 이상',
    suspiciousLoc: '의심 위치(Temp/휴지통/사용자쓰기)',
    doubleExt: '이중 확장자 위장',
  };
  const z = vec.map((v, i) => ({
    name: MFT_FEATURE_NAMES[i],
    z: std[i] > 1e-6 ? Math.abs(v - mean[i]) / std[i] : 0,
  }));
  return z
    .filter((x) => x.z > 1.3)
    .sort((a, b) => b.z - a.z)
    .slice(0, 3)
    .map((x) => labelMap[x.name] ?? x.name);
}

/** 열별 평균/표준편차 — 근거 해설(z-score) 용. */
export function columnStats(data: number[][]): { mean: number[]; std: number[] } {
  if (data.length === 0) return { mean: [], std: [] };
  const dims = data[0].length;
  const mean = new Array(dims).fill(0);
  const std = new Array(dims).fill(0);
  for (const row of data) for (let j = 0; j < dims; j++) mean[j] += row[j];
  for (let j = 0; j < dims; j++) mean[j] /= data.length;
  for (const row of data) for (let j = 0; j < dims; j++) std[j] += (row[j] - mean[j]) ** 2;
  for (let j = 0; j < dims; j++) std[j] = Math.sqrt(std[j] / data.length);
  return { mean, std };
}
