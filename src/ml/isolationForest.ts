// =====================================================================
// Isolation Forest — 비지도 이상탐지 (Liu, Ting & Zhou, 2008)
// 라벨 없이, 무작위 분할로 각 표본을 고립시키는 데 필요한 평균 경로 길이로
// 이상치를 채점한다. 이상치는 적은 분할로 고립되어 경로가 짧다 → 점수↑.
// 시그니처가 없어도 "통계적으로 튀는" 로그/파일을 잡아낸다(비하드코딩).
// =====================================================================

import { mulberry32, randInt, sample } from './random';

interface INode {
  // internal
  splitAttr?: number;
  splitVal?: number;
  left?: INode;
  right?: INode;
  // external
  size?: number;
  depth?: number;
}

// 이진탐색트리 평균 실패경로 길이(정규화 상수 c(n)).
function cFactor(n: number): number {
  if (n <= 1) return 0;
  return 2 * (Math.log(n - 1) + 0.5772156649) - (2 * (n - 1)) / n;
}

function buildTree(
  data: number[][],
  idx: number[],
  depth: number,
  maxDepth: number,
  rng: () => number,
): INode {
  if (depth >= maxDepth || idx.length <= 1) {
    return { size: idx.length, depth };
  }
  const dims = data[0].length;
  // 이 부분집합에서 값이 서로 다른(분할 가능한) 속성만 후보로 선정한다.
  // 상수 속성을 무작위로 골라 조기 종료되면 경로 길이가 뭉개져 이상 점수가
  // 좁은 대역으로 압축된다 — extRisk·inactive 같은 0/1 이진 특징이 많은
  // MFT 에서 특히 빈번하므로 반드시 상수 속성을 제외해야 한다.
  const candidates: number[] = [];
  for (let a = 0; a < dims; a++) {
    let lo = Infinity;
    let hi = -Infinity;
    for (const i of idx) {
      const v = data[i][a];
      if (v < lo) lo = v;
      if (v > hi) hi = v;
    }
    if (hi > lo) candidates.push(a);
  }
  if (candidates.length === 0) {
    // 모든 속성이 상수 → 완전히 동일한 벡터 묶음, 더 이상 나눌 수 없음
    return { size: idx.length, depth };
  }
  const attr = candidates[randInt(rng, candidates.length)];
  let min = Infinity;
  let max = -Infinity;
  for (const i of idx) {
    const v = data[i][attr];
    if (v < min) min = v;
    if (v > max) max = v;
  }
  const splitVal = min + rng() * (max - min);
  const left: number[] = [];
  const right: number[] = [];
  for (const i of idx) {
    if (data[i][attr] < splitVal) left.push(i);
    else right.push(i);
  }
  return {
    splitAttr: attr,
    splitVal,
    left: buildTree(data, left, depth + 1, maxDepth, rng),
    right: buildTree(data, right, depth + 1, maxDepth, rng),
  };
}

function pathLength(x: number[], node: INode, depth: number): number {
  if (node.left === undefined || node.right === undefined) {
    // 외부노드: 남은 부분트리의 기대 경로를 보정치로 더한다
    return depth + cFactor(node.size ?? 1);
  }
  if (x[node.splitAttr!] < node.splitVal!) return pathLength(x, node.left, depth + 1);
  return pathLength(x, node.right, depth + 1);
}

export interface IForestOptions {
  nTrees?: number;
  sampleSize?: number;
  seed?: number;
}

export class IsolationForest {
  private trees: INode[] = [];
  private c = 1;
  private opts: Required<IForestOptions>;

  constructor(opts: IForestOptions = {}) {
    this.opts = {
      nTrees: opts.nTrees ?? 100,
      sampleSize: opts.sampleSize ?? 256,
      seed: opts.seed ?? 1337,
    };
  }

  fit(data: number[][]): this {
    if (data.length === 0) return this;
    const rng = mulberry32(this.opts.seed);
    const psi = Math.min(this.opts.sampleSize, data.length);
    this.c = cFactor(psi) || 1;
    const maxDepth = Math.ceil(Math.log2(Math.max(2, psi)));
    const allIdx = data.map((_, i) => i);
    this.trees = [];
    for (let t = 0; t < this.opts.nTrees; t++) {
      const subIdx = sample(rng, allIdx, psi);
      this.trees.push(buildTree(data, subIdx, 0, maxDepth, rng));
    }
    return this;
  }

  /** 이상 점수 s = 2^(-E[h(x)]/c). 0.5≈보통, →1 이상치, →0 정상. */
  score(x: number[]): number {
    if (this.trees.length === 0) return 0;
    let sum = 0;
    for (const tree of this.trees) sum += pathLength(x, tree, 0);
    const avg = sum / this.trees.length;
    return Math.pow(2, -avg / this.c);
  }

  scoreAll(data: number[][]): number[] {
    return data.map((x) => this.score(x));
  }
}
