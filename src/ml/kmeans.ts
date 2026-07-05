// =====================================================================
// TF-IDF 벡터화 + K-Means(K-Means++) 군집화 — 비지도 행위 그룹화
// 로그 라인을 TF-IDF 벡터로 임베딩한 뒤 K개 군집으로 묶어, 소수(희소)
// 군집을 "드문 행위"로 부각한다. 실루엣 계수로 군집 품질을 자기평가.
// =====================================================================

import { mulberry32, randInt } from './random';
import { tokenize } from './text';

export interface TfidfModel {
  vocab: string[];
  idf: number[];
  vectors: number[][]; // 문서 × 어휘 (L2 정규화)
}

/** 상위 빈도 어휘로 어휘집을 제한(maxFeatures)해 TF-IDF 행렬을 만든다. */
export function tfidf(docs: string[], maxFeatures = 240): TfidfModel {
  const tokenized = docs.map(tokenize);
  const df: Record<string, number> = {};
  for (const toks of tokenized) {
    for (const t of new Set(toks)) df[t] = (df[t] || 0) + 1;
  }
  // 문서 1건에만 등장하는 극희소 토큰 제거 후 df 상위 maxFeatures 선택
  const vocab = Object.keys(df)
    .filter((t) => df[t] >= 2 || docs.length < 8)
    .sort((a, b) => df[b] - df[a])
    .slice(0, maxFeatures);
  const vIndex: Record<string, number> = {};
  vocab.forEach((t, i) => (vIndex[t] = i));

  const N = docs.length || 1;
  const idf = vocab.map((t) => Math.log((1 + N) / (1 + df[t])) + 1);

  const vectors = tokenized.map((toks) => {
    const tf = new Array(vocab.length).fill(0);
    for (const t of toks) {
      const j = vIndex[t];
      if (j !== undefined) tf[j] += 1;
    }
    const len = toks.length || 1;
    let norm = 0;
    for (let j = 0; j < tf.length; j++) {
      tf[j] = (tf[j] / len) * idf[j];
      norm += tf[j] * tf[j];
    }
    norm = Math.sqrt(norm) || 1;
    for (let j = 0; j < tf.length; j++) tf[j] /= norm;
    return tf;
  });

  return { vocab, idf, vectors };
}

function dist2(a: number[], b: number[]): number {
  let s = 0;
  for (let i = 0; i < a.length; i++) {
    const d = a[i] - b[i];
    s += d * d;
  }
  return s;
}

export interface KMeansResult {
  assignments: number[];
  centroids: number[][];
  k: number;
  inertia: number;
}

/** K-Means++ 초기화 + Lloyd 반복. 시드로 재현성 확보. */
export function kmeans(data: number[][], k: number, seed = 42, maxIter = 40): KMeansResult {
  const n = data.length;
  if (n === 0) return { assignments: [], centroids: [], k: 0, inertia: 0 };
  const K = Math.min(k, n);
  const rng = mulberry32(seed);

  // K-Means++ 초기 중심 선택
  const centroids: number[][] = [];
  centroids.push(data[randInt(rng, n)].slice());
  while (centroids.length < K) {
    const d2 = data.map((x) => Math.min(...centroids.map((c) => dist2(x, c))));
    const total = d2.reduce((s, v) => s + v, 0) || 1;
    let r = rng() * total;
    let chosen = 0;
    for (let i = 0; i < n; i++) {
      r -= d2[i];
      if (r <= 0) {
        chosen = i;
        break;
      }
    }
    centroids.push(data[chosen].slice());
  }

  const assignments = new Array(n).fill(0);
  let inertia = 0;
  for (let iter = 0; iter < maxIter; iter++) {
    let changed = false;
    inertia = 0;
    // 할당 단계
    for (let i = 0; i < n; i++) {
      let best = 0;
      let bestD = Infinity;
      for (let c = 0; c < K; c++) {
        const d = dist2(data[i], centroids[c]);
        if (d < bestD) {
          bestD = d;
          best = c;
        }
      }
      inertia += bestD;
      if (assignments[i] !== best) {
        assignments[i] = best;
        changed = true;
      }
    }
    // 갱신 단계
    const sums = Array.from({ length: K }, () => new Array(data[0].length).fill(0));
    const counts = new Array(K).fill(0);
    for (let i = 0; i < n; i++) {
      const c = assignments[i];
      counts[c]++;
      const row = data[i];
      const acc = sums[c];
      for (let j = 0; j < row.length; j++) acc[j] += row[j];
    }
    for (let c = 0; c < K; c++) {
      if (counts[c] === 0) continue;
      for (let j = 0; j < centroids[c].length; j++) centroids[c][j] = sums[c][j] / counts[c];
    }
    if (!changed && iter > 0) break;
  }
  return { assignments, centroids, k: K, inertia };
}

/**
 * 실루엣 계수 근사(중심 간 거리 기반, O(nK)) — 군집 응집/분리 품질(−1..1).
 * 정확한 O(n²) 대신 "자기 중심 거리 vs 최근접 타 중심 거리"로 추정.
 */
export function silhouetteApprox(data: number[][], res: KMeansResult): number {
  if (data.length === 0 || res.k < 2) return 0;
  let sum = 0;
  for (let i = 0; i < data.length; i++) {
    const a = Math.sqrt(dist2(data[i], res.centroids[res.assignments[i]]));
    let b = Infinity;
    for (let c = 0; c < res.k; c++) {
      if (c === res.assignments[i]) continue;
      const d = Math.sqrt(dist2(data[i], res.centroids[c]));
      if (d < b) b = d;
    }
    const s = (b - a) / (Math.max(a, b) || 1);
    sum += s;
  }
  return sum / data.length;
}
