// =====================================================================
// 머신러닝 분석 오케스트레이터 (하이브리드 계층)
// 규칙기반 엔진과 별개로, 브라우저에서 즉시 학습/추론하는 ML 파이프라인:
//   1) 다항 나이브 베이즈(지도)     — 로그 라인의 공격 범주 분류
//   2) Isolation Forest(비지도)     — 시그니처 없는 통계적 이상치 탐지
//   3) TF-IDF + K-Means(비지도)     — 행위 군집화 & 희소 군집 부각
//   4) 샤논 엔트로피(통계)          — 난독/인코딩 페이로드 탐지
// 모든 난수는 시드 고정 → 동일 입력에 동일 결과(포렌식 재현성).
// =====================================================================

import type { LogEntry, MftRecord, MlAnalysis, MlAnomaly, MlCluster } from '@/types';
import { makeId, truncate } from '@/utils/format';
import { MultinomialNaiveBayes, type NbPrediction } from '@/ml/naiveBayes';
import { IsolationForest } from '@/ml/isolationForest';
import { tfidf, kmeans, silhouetteApprox } from '@/ml/kmeans';
import { findHighEntropyTokens } from '@/ml/text';
import { seedFrom } from '@/ml/random';
import { TRAINING_CORPUS, NB_LABEL_KO } from '@/ml/trainingData';
import {
  logFeatures,
  mftFeatures,
  columnStats,
  topLogReasons,
  topMftReasons,
  LOG_FEATURE_NAMES,
  MFT_FEATURE_NAMES,
} from '@/ml/features';

const IF_TREES = 100;
const LOG_RISK_FLAG = 0.5; // 로그 하이브리드 위험 점수 임계값(IF통계이상+NB공격분류+엔트로피)
const MFT_RISK_FLAG = 0.5; // MFT 하이브리드 위험 점수 임계값(위협신호 노이즈-OR)
const MAX_SAMPLE = 5000; // 성능 상한(대용량 MFT 대비)
const MAX_CLUSTER_DOCS = 1500;

const clamp01 = (x: number) => (x < 0 ? 0 : x > 1 ? 1 : x);

function seedForLogs(logs: LogEntry[]): number {
  return seedFrom(logs.length, logs[0]?.raw ?? '', logs[logs.length - 1]?.raw ?? '');
}

function pickSample<T>(arr: T[], max: number): T[] {
  if (arr.length <= max) return arr;
  const step = arr.length / max;
  const out: T[] = [];
  for (let i = 0; i < max; i++) out.push(arr[Math.floor(i * step)]);
  return out;
}

// 동일 기여특징(reasons) 프로파일은 사실상 같은 유형의 이상치다. 대표 1건만
// 남기고 나머지는 dupes 로 집계 — 함께 삭제된 .NET 구성요소 수백 건이 같은
// 특징·같은 점수로 상위 목록을 중복 도배하는 것을 막는다(비지도 특성상
// 동일 벡터엔 동일 점수가 나오는 것이 정상이므로, 표시를 정리하는 것이 핵심).
function dedupeAnomalies(list: MlAnomaly[]): MlAnomaly[] {
  const groups = new Map<string, MlAnomaly>();
  for (const a of list) {
    const key = a.reasons.length ? a.reasons.join('|') : `__solo__${a.id}`;
    const rep = groups.get(key);
    if (!rep) {
      groups.set(key, { ...a, dupes: 0 });
    } else {
      rep.dupes = (rep.dupes ?? 0) + 1;
      if (a.score > rep.score) {
        rep.score = a.score;
        rep.ref = a.ref;
        rep.snippet = a.snippet;
      }
    }
  }
  return Array.from(groups.values()).sort((a, b) => b.score - a.score);
}

// --- 로그 대상 ML ------------------------------------------------------
export function analyzeLogsMl(logs: LogEntry[]): MlAnalysis | undefined {
  if (logs.length < 5) return undefined; // 표본 부족 시 ML 생략
  const seed = seedForLogs(logs);
  const sample = pickSample(logs, MAX_SAMPLE);

  // 1) 나이브 베이즈 학습 + 교차검증 + 라인별 예측(분류 분포 & 하이브리드 점수 공용)
  const nb = new MultinomialNaiveBayes(1).fit(TRAINING_CORPUS);
  // 자기평가(학습셋=검증셋) 대신 층화 5-겹 교차검증 — 일반화 성능의 정직한 추정.
  const nbAccuracy = MultinomialNaiveBayes.crossValidate(TRAINING_CORPUS, 5, 1);
  const preds = sample.map((log) => nb.predict(log.raw || log.message));
  const counts: Record<string, number> = {};
  for (const pred of preds) {
    // 저신뢰면 benign 으로 흡수(과분류 억제). 라벨 수가 늘면 소프트맥스 최대확률이
    // 전반적으로 낮아지므로 임계값을 0.30 으로 완화(균일분포 1/라벨수 대비 충분히 높음).
    const label = pred.confidence < 0.3 ? 'benign' : pred.label;
    counts[label] = (counts[label] || 0) + 1;
  }
  const classification = Object.entries(counts)
    .map(([label, count]) => ({
      label,
      labelKo: NB_LABEL_KO[label] ?? label,
      count,
      ratio: count / sample.length,
    }))
    .sort((a, b) => b.count - a.count);

  // 2) 하이브리드 위험 점수 = IF 통계이상 + NB 공격분류 신뢰도 + 메시지 엔트로피를
  //    노이즈-OR 로 결합. "통계적으로도 튀고(IF) 공격 범주로도 분류된(NB)" 라인이
  //    확실히 상위(0.7~0.9대)로 분리된다 — 순수 IF 점수가 0.6대에 뭉치던 문제 해소.
  const feats = sample.map(logFeatures);
  const { mean, std } = columnStats(feats);
  const iforest = new IsolationForest({ nTrees: IF_TREES, sampleSize: 256, seed }).fit(feats);
  const scores = iforest.scoreAll(feats);
  const logRisk = (f: number[], ifScore: number, p: NbPrediction): number => {
    const attackConf = p.label !== 'benign' ? p.confidence : 0; // 공격 범주로 분류된 신뢰도
    const w = [
      0.6 * clamp01((ifScore - 0.5) / 0.25), // IF 통계이상(기준선 초과분)
      0.78 * attackConf,                     // NB 공격 범주 신뢰도(공격 라인의 주 동인)
      0.35 * clamp01((f[2] - 0.58) / 0.42),  // 메시지 엔트로피(난독/인코딩) — f[2]=msgEntropy
    ];
    let inv = 1;
    for (const t of w) inv *= 1 - clamp01(t);
    return clamp01(1 - inv);
  };
  const anomalies: MlAnomaly[] = [];
  let flagged = 0;
  for (let i = 0; i < sample.length; i++) {
    const risk = logRisk(feats[i], scores[i], preds[i]);
    if (risk >= LOG_RISK_FLAG) {
      flagged++;
      const reasons = topLogReasons(feats[i], mean, std);
      // 공격 범주로 분류됐다면 그 자체가 가장 강한 근거 — 맨 앞에 표기.
      if (preds[i].label !== 'benign' && preds[i].confidence >= 0.3) {
        reasons.unshift(`공격 분류: ${NB_LABEL_KO[preds[i].label] ?? preds[i].label}`);
      }
      anomalies.push({
        id: makeId('ml'),
        ref: `line ${sample[i].lineNumber}`,
        score: Number(risk.toFixed(3)),
        reasons: reasons.slice(0, 4),
        snippet: truncate((sample[i].raw || sample[i].message).trim(), 160),
      });
    }
  }
  anomalies.sort((a, b) => b.score - a.score);

  // 3) TF-IDF + K-Means 군집화
  const docSample = pickSample(sample, MAX_CLUSTER_DOCS);
  const texts = docSample.map((l) => l.raw || l.message);
  const { clusters, silhouette } = clusterLogs(texts, seed);

  // 4) 엔트로피 기반 난독/인코딩 플래그
  const entropyFlags = collectEntropyFlags(sample.map((l) => ({ ref: `line ${l.lineNumber}`, text: l.raw || l.message })));

  const attackRatio = classification
    .filter((c) => c.label !== 'benign')
    .reduce((s, c) => s + c.ratio, 0);

  return {
    trained: true,
    target: 'log',
    sampleCount: sample.length,
    models: ['Isolation Forest + NB 하이브리드', 'Multinomial Naive Bayes', 'TF-IDF + K-Means', 'Shannon Entropy'],
    featureNames: LOG_FEATURE_NAMES,
    anomalies: dedupeAnomalies(anomalies).slice(0, 20),
    contamination: Number((flagged / sample.length).toFixed(3)),
    classification,
    clusters,
    entropyFlags,
    metrics: {
      nbAccuracy: Number(nbAccuracy.toFixed(3)),
      nbVocab: nb.vocabSize,
      silhouette,
      iforestTrees: IF_TREES,
      flaggedCount: flagged,
    },
    summary:
      `하이브리드 위험 점수(Isolation Forest 통계이상 + 나이브베이즈 공격분류 신뢰도 + 엔트로피를 노이즈-OR 결합)가 ` +
      `${sample.length.toLocaleString()}개 로그 중 ${flagged}건(${(flagged / sample.length * 100).toFixed(1)}%)을 위험 라인으로 표시했다. ` +
      `통계적으로도 튀고 공격 범주로도 분류된 라인일수록 점수가 1 에 근접한다. ` +
      `나이브 베이즈 분류기(5겹 교차검증 정확도 ${(nbAccuracy * 100).toFixed(0)}%)는 약 ${(attackRatio * 100).toFixed(0)}%를 공격성 범주로 분류했다.`,
  };
}

function clusterLogs(texts: string[], seed: number): { clusters: MlCluster[]; silhouette: number } {
  if (texts.length < 6) return { clusters: [], silhouette: 0 };
  const model = tfidf(texts, 200);
  const k = Math.min(6, Math.max(2, Math.round(Math.sqrt(texts.length / 2))));
  const res = kmeans(model.vectors, k, seed);
  const silhouette = Number(silhouetteApprox(model.vectors, res).toFixed(3));

  const sizes = new Array(res.k).fill(0);
  for (const a of res.assignments) sizes[a]++;
  const clusters: MlCluster[] = [];
  for (let c = 0; c < res.k; c++) {
    if (sizes[c] === 0) continue;
    // 중심 상위 가중 토큰 = 대표 키워드 (§ 심볼 토큰은 사람이 읽는 라벨로 치환)
    // 순수 숫자 토큰(상태코드·바이트 등)은 의미가 낮아 대표 키워드에서 제외
    const top = res.centroids[c]
      .map((w, j) => ({ w, term: model.vocab[j] }))
      .filter((x) => Boolean(x.term) && !/^\d+$/.test(x.term))
      .sort((a, b) => b.w - a.w)
      .slice(0, 5)
      .map((x) => symbolLabel(x.term))
      .filter(Boolean);
    clusters.push({
      id: c,
      size: sizes[c],
      ratio: Number((sizes[c] / texts.length).toFixed(3)),
      keywords: top,
      rare: sizes[c] / texts.length < 0.12,
    });
  }
  clusters.sort((a, b) => b.size - a.size);
  return { clusters, silhouette };
}

function symbolLabel(term: string): string {
  const map: Record<string, string> = {
    '§traversal': '경로순회(../)',
    '§jndi': 'JNDI',
    '§xss': '<script>',
    '§union_select': 'UNION SELECT',
    '§tautology': "OR 1=1",
    '§sqlcomment': 'SQL주석(--)',
    '§urlenc': 'URL인코딩(%xx)',
    '§b64cmd': 'Base64명령',
    '§sensitivefile': '민감파일(/etc/passwd)',
    '§creddump': '자격증명덤프',
    '§cmdsep': '명령구분(;)',
    '§pipe': '파이프(|)',
    '§cmdsubst': '명령치환($())',
    '§andcmd': '연쇄(&&)',
    '§backtick': '백틱(`)',
  };
  return map[term] ?? term;
}

function collectEntropyFlags(items: { ref: string; text: string }[]) {
  const flags: { ref: string; value: string; entropy: number; note: string }[] = [];
  const seen = new Set<string>();
  for (const it of items) {
    for (const hit of findHighEntropyTokens(it.text, 20, 4.3)) {
      const key = hit.token.slice(0, 24);
      if (seen.has(key)) continue;
      seen.add(key);
      const note =
        hit.entropy >= 5 ? '암호화/패킹 가능성' : /^[A-Za-z0-9+/=]+$/.test(hit.token) ? 'Base64 인코딩 추정' : '난독화 문자열 추정';
      flags.push({ ref: it.ref, value: truncate(hit.token, 40), entropy: hit.entropy, note });
      if (flags.length >= 12) return flags;
    }
  }
  return flags;
}

// --- MFT 대상 ML -------------------------------------------------------
export function analyzeMftMl(records: MftRecord[]): MlAnalysis | undefined {
  if (records.length < 8) return undefined;
  const seed = seedFrom(records.length, records[0]?.fileName ?? '');
  const sample = pickSample(records, MAX_SAMPLE);

  // Isolation Forest — 파일명 무작위성/타임스톰프/삭제 등 수치 특징 기반
  const feats = sample.map(mftFeatures);
  const { mean, std } = columnStats(feats);
  const iforest = new IsolationForest({ nTrees: IF_TREES, sampleSize: 256, seed }).fit(feats);
  const scores = iforest.scoreAll(feats);

  // 하이브리드 위험 점수 — 노이즈-OR(Noisy-OR) 게이트로 위협신호를 결합한다.
  //   risk = 1 - ∏ₖ (1 - wₖ·signalₖ)
  // 각 지표(의심위치·이중확장자·삭제·실행확장자·타임스톰프·랜덤파일명·IF통계이상)를
  // "독립적인 경보"로 보고, 지표가 겹칠수록 1 에 포화한다(다중 지표 동시관측 = 강한 확신).
  // 순수 IF 가 0.6대에 뭉치던 문제 해소: IF 는 기준선(≈0.5) 초과분만 신호로 환산해
  // 하나의 지표로만 반영하고, 실제 위협신호가 점수를 주도 → 위험 파일이 0.7~0.9대로
  // 확실히 분리된다(정상 파일은 신호가 0 이라 0 에 수렴). 단일 강신호도 상당 점수를 확보.
  // (특징 인덱스: 0=nameEntropy,3=extRisk,4=inactive,5=siFnDelta,8=suspiciousLoc,9=doubleExt)
  const hybridRisk = (f: number[], ifScore: number): number => {
    const w = [
      0.66 * f[8],                             // suspiciousLoc  의심 위치(Temp/휴지통)
      0.7 * f[9],                              // doubleExt      이중 확장자 위장
      0.45 * f[3],                             // extRisk        실행/스크립트 확장자
      0.44 * f[4],                             // inactive       삭제 레코드
      0.6 * f[5],                              // siFnDelta      타임스톰프
      0.44 * clamp01((f[0] - 0.7) / 0.3),      // nameEntropy    랜덤 파일명(드롭퍼)
      0.48 * clamp01((ifScore - 0.5) / 0.25),  // IF 통계이상(기준선 초과분)
    ];
    let inv = 1;
    for (const t of w) inv *= 1 - clamp01(t);
    return clamp01(1 - inv);
  };
  const risk = scores.map((s, i) => hybridRisk(feats[i], s));

  const anomalies: MlAnomaly[] = [];
  let flagged = 0;
  for (let i = 0; i < sample.length; i++) {
    if (risk[i] >= MFT_RISK_FLAG) {
      flagged++;
      anomalies.push({
        id: makeId('ml'),
        ref: `#${sample[i].recordNumber} ${sample[i].fileName}`,
        score: Number(risk[i].toFixed(3)),
        reasons: topMftReasons(feats[i], mean, std),
        snippet: truncate(sample[i].path, 160),
      });
    }
  }
  anomalies.sort((a, b) => b.score - a.score);

  // K-Means — 수치 특징 군집화(파일 행위 그룹)
  const k = Math.min(6, Math.max(2, Math.round(Math.sqrt(sample.length / 40))));
  const res = kmeans(feats, k, seed);
  const sil = silhouetteApprox(feats, res);
  const sizes = new Array(res.k).fill(0);
  const extByCluster: Record<number, Record<string, number>> = {};
  for (let i = 0; i < sample.length; i++) {
    const c = res.assignments[i];
    sizes[c]++;
    (extByCluster[c] ??= {});
    const e = sample[i].ext || '(무확장자)';
    extByCluster[c][e] = (extByCluster[c][e] || 0) + 1;
  }
  const clusters: MlCluster[] = [];
  for (let c = 0; c < res.k; c++) {
    if (sizes[c] === 0) continue;
    const top = Object.entries(extByCluster[c] || {})
      .sort((a, b) => b[1] - a[1])
      .slice(0, 4)
      .map(([e]) => e);
    clusters.push({
      id: c,
      size: sizes[c],
      ratio: Number((sizes[c] / sample.length).toFixed(3)),
      keywords: top,
      rare: sizes[c] / sample.length < 0.1,
    });
  }
  clusters.sort((a, b) => b.size - a.size);

  const entropyFlags = collectEntropyFlags(
    sample.map((r) => ({ ref: `#${r.recordNumber}`, text: r.fileName })),
  );

  return {
    trained: true,
    target: 'mft',
    sampleCount: sample.length,
    models: ['Isolation Forest + 위협신호 하이브리드', 'K-Means', 'Shannon Entropy'],
    featureNames: MFT_FEATURE_NAMES,
    anomalies: dedupeAnomalies(anomalies).slice(0, 20),
    contamination: Number((flagged / sample.length).toFixed(3)),
    classification: [], // MFT 는 텍스트 분류 대상 아님
    clusters,
    entropyFlags,
    metrics: {
      nbAccuracy: 0,
      nbVocab: 0,
      silhouette: Number(sil.toFixed(3)),
      iforestTrees: IF_TREES,
      flaggedCount: flagged,
    },
    summary:
      `하이브리드 위험 점수(의심위치·이중확장자·삭제·실행확장자·타임스톰프·랜덤파일명·IF통계이상을 노이즈-OR 결합)가 ` +
      `${sample.length.toLocaleString()}개 MFT 레코드 중 ${flagged}건(${(flagged / sample.length * 100).toFixed(1)}%)을 위험 후보로 표시했다. ` +
      `위협 지표가 겹칠수록 점수가 1 에 근접하도록 결합해 실제 위협(Temp·휴지통 삭제 실행파일, 이중확장자 위장)을 0.7~0.9대 상위로 끌어올린다. K-Means 는 ${clusters.length}개 파일 행위 군집으로 분리했다.`,
  };
}
