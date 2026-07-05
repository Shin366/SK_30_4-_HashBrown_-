// =====================================================================
// 재현 가능한 난수 생성기 (mulberry32) — REQ-NF: 포렌식 재현성
// 무작위 초기화(Isolation Forest 분할, K-Means 초기 중심)에 사용하되,
// 동일 입력 → 동일 시드 → 동일 결과를 보장하기 위해 seed 를 데이터에서 유도한다.
// (브라우저 Math.random 은 비결정적이라 보고서 재현성이 깨지므로 사용하지 않는다.)
// =====================================================================

/** 32-bit 시드 기반 선형 합동 계열 PRNG. 0..1 실수를 반환. */
export function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return function () {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** 문자열/길이에서 안정적인 32-bit 시드를 만든다 (FNV-1a 변형). */
export function seedFrom(...parts: (string | number)[]): number {
  let h = 2166136261;
  const s = parts.join('|');
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

/** rng 를 이용한 정수 [0, n) */
export function randInt(rng: () => number, n: number): number {
  return Math.floor(rng() * n);
}

/** 배열에서 크기 k 의 비복원 표본 추출 (Fisher–Yates 부분 셔플). */
export function sample<T>(rng: () => number, arr: T[], k: number): T[] {
  if (k >= arr.length) return arr.slice();
  const idx = arr.map((_, i) => i);
  for (let i = 0; i < k; i++) {
    const j = i + randInt(rng, idx.length - i);
    [idx[i], idx[j]] = [idx[j], idx[i]];
  }
  return idx.slice(0, k).map((i) => arr[i]);
}
