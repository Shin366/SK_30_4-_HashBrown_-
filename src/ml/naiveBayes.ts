// =====================================================================
// 다항 나이브 베이즈(Multinomial Naive Bayes) 분류기 — 지도학습
// 라벨링된 로그 코퍼스로 브라우저에서 즉시 학습(fit)하고, 새 로그 라인을
// 공격 범주(정찰/SQLi/Log4Shell/웹쉘/무차별대입/자격증명덤프/유출/C2/정상)로
// 분류한다. 라플라스 스무딩 + 로그공간 계산으로 언더플로를 방지.
// =====================================================================

import { tokenize } from './text';

export interface LabeledDoc {
  text: string;
  label: string;
}

export interface NbPrediction {
  label: string;
  confidence: number; // 0..1 (소프트맥스 정규화된 사후확률)
  scores: { label: string; prob: number }[];
}

export class MultinomialNaiveBayes {
  private classes: string[] = [];
  private vocab = new Set<string>();
  private logPrior: Record<string, number> = {};
  // label -> token -> count
  private tokenCounts: Record<string, Record<string, number>> = {};
  private classTokenTotal: Record<string, number> = {};
  private alpha: number; // 라플라스 스무딩 계수

  constructor(alpha = 1) {
    this.alpha = alpha;
  }

  /** 라벨링 문서로 학습. 사전확률 P(c) 와 우도 P(w|c) 를 추정한다. */
  fit(docs: LabeledDoc[]): this {
    const classDocCount: Record<string, number> = {};
    for (const d of docs) {
      const c = d.label;
      if (!this.tokenCounts[c]) {
        this.tokenCounts[c] = {};
        this.classTokenTotal[c] = 0;
        classDocCount[c] = 0;
      }
      classDocCount[c]++;
      for (const t of tokenize(d.text)) {
        this.vocab.add(t);
        this.tokenCounts[c][t] = (this.tokenCounts[c][t] || 0) + 1;
        this.classTokenTotal[c]++;
      }
    }
    this.classes = Object.keys(this.tokenCounts);
    const total = docs.length || 1;
    for (const c of this.classes) {
      this.logPrior[c] = Math.log((classDocCount[c] || 1) / total);
    }
    return this;
  }

  private logLikelihood(tokens: string[], c: string): number {
    const V = this.vocab.size;
    const denom = this.classTokenTotal[c] + this.alpha * V;
    let lp = this.logPrior[c];
    for (const t of tokens) {
      if (!this.vocab.has(t)) continue; // 어휘 밖 토큰 무시
      const num = (this.tokenCounts[c][t] || 0) + this.alpha;
      lp += Math.log(num / denom);
    }
    return lp;
  }

  predict(text: string): NbPrediction {
    const tokens = tokenize(text);
    const logps = this.classes.map((c) => ({ label: c, lp: this.logLikelihood(tokens, c) }));
    // 로그공간 → 소프트맥스(수치안정: 최대값 차감)
    const maxLp = Math.max(...logps.map((x) => x.lp));
    const exps = logps.map((x) => ({ label: x.label, e: Math.exp(x.lp - maxLp) }));
    const sum = exps.reduce((s, x) => s + x.e, 0) || 1;
    const scores = exps
      .map((x) => ({ label: x.label, prob: x.e / sum }))
      .sort((a, b) => b.prob - a.prob);
    return { label: scores[0].label, confidence: scores[0].prob, scores };
  }

  get labels(): string[] {
    return this.classes.slice();
  }

  get vocabSize(): number {
    return this.vocab.size;
  }

  /** 홀드아웃/학습셋에 대한 정확도 자기평가(과적합-낙관적). */
  evaluate(docs: LabeledDoc[]): number {
    if (docs.length === 0) return 0;
    let correct = 0;
    for (const d of docs) {
      if (this.predict(d.text).label === d.label) correct++;
    }
    return correct / docs.length;
  }

  /**
   * 층화 k-겹 교차검증 정확도 — 학습셋에서 평가하는 자기평가와 달리
   * 각 겹을 학습에서 제외하고 검증하므로 일반화 성능의 정직한 추정치.
   * 라벨별로 i%k 분할(외부 난수 미사용 → 동일 코퍼스는 항상 동일 결과).
   */
  static crossValidate(docs: LabeledDoc[], k = 5, alpha = 1): number {
    if (docs.length < k) return new MultinomialNaiveBayes(alpha).fit(docs).evaluate(docs);
    const byLabel: Record<string, LabeledDoc[]> = {};
    for (const d of docs) (byLabel[d.label] ??= []).push(d);
    const folds: LabeledDoc[][] = Array.from({ length: k }, () => []);
    for (const label in byLabel) byLabel[label].forEach((d, i) => folds[i % k].push(d));
    let correct = 0;
    let total = 0;
    for (let f = 0; f < k; f++) {
      const test = folds[f];
      const train = folds.filter((_, i) => i !== f).flat();
      if (train.length === 0 || test.length === 0) continue;
      const model = new MultinomialNaiveBayes(alpha).fit(train);
      for (const d of test) {
        total++;
        if (model.predict(d.text).label === d.label) correct++;
      }
    }
    return total ? correct / total : 0;
  }
}
