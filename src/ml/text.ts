// =====================================================================
// 텍스트 특징 유틸 — 토큰화 · 샤논 엔트로피 · 문자군 통계
// NLP 전처리(Naive Bayes/TF-IDF)와 난독화·인코딩 탐지(엔트로피)에 사용.
// =====================================================================

/**
 * 로그/명령 문자열 토큰화.
 * 소문자화 후 영숫자 시퀀스를 기본 토큰으로, 공격 문법에서 의미가 큰
 * 특수 시퀀스(../, jndi:, ', --, <script, %xx, ;)는 별도 토큰으로 보존한다.
 */
export function tokenize(text: string): string[] {
  if (!text) return [];
  const lower = text.toLowerCase();
  const tokens: string[] = [];

  // 의미있는 특수 패턴을 심볼 토큰으로 승격
  const symbols: [RegExp, string][] = [
    [/\.\.\//g, '§traversal'],
    [/jndi:/g, '§jndi'],
    [/<script/g, '§xss'],
    [/union\s+select/g, '§union_select'],
    [/or\s+1\s*=\s*1|'\s*or\s*'1'\s*=\s*'1/g, '§tautology'],
    [/--\s|--$|#\s*$/g, '§sqlcomment'],
    [/%[0-9a-f]{2}/g, '§urlenc'],
    [/-enc\s|frombase64|frombase64string/g, '§b64cmd'],
    [/\/etc\/passwd|\/etc\/shadow/g, '§sensitivefile'],
    [/sekurlsa|logonpasswords|lsass/g, '§creddump'],
    // 명령어 인젝션 신호 — ; | $() && ` 는 [a-z0-9_] 필터에 지워지므로 심볼로 보존.
    // (뒤따르는 명령 단어는 look-ahead 로 남겨 토큰 손실 방지)
    [/;\s*(?=[a-z])/g, '§cmdsep'],
    [/\|\s*(?=[a-z])/g, '§pipe'],
    [/\$\(/g, '§cmdsubst'],
    [/&&\s*(?=[a-z])/g, '§andcmd'],
    [/`(?=[a-z])/g, '§backtick'],
  ];
  let scratch = lower;
  for (const [re, tok] of symbols) {
    if (re.test(scratch)) {
      const n = (scratch.match(re) || []).length;
      for (let i = 0; i < n; i++) tokens.push(tok);
      scratch = scratch.replace(re, ' ');
    }
  }

  // 일반 영숫자 토큰 (길이 2 이상)
  const words = scratch.match(/[a-z0-9_]{2,}/g) || [];
  for (const w of words) {
    // 순수 숫자·너무 긴 랜덤 토큰은 제외(과적합/노이즈 억제), 대신 엔트로피에서 반영
    if (/^\d+$/.test(w) && w.length > 4) continue;
    if (w.length > 24) continue;
    tokens.push(w);
  }
  return tokens;
}

/** 샤논 엔트로피(bit/char). base64·암호화·패킹된 문자열일수록 높다(≈4.5~6). */
export function shannonEntropy(s: string): number {
  if (!s) return 0;
  const freq: Record<string, number> = {};
  for (const ch of s) freq[ch] = (freq[ch] || 0) + 1;
  const len = [...s].length; // 코드포인트 기준(빈도 집계와 일치 — 서로게이트쌍 보정)
  let h = 0;
  for (const k in freq) {
    const p = freq[k] / len;
    h -= p * Math.log2(p);
  }
  return h;
}

export interface CharStats {
  len: number;
  digitRatio: number;
  upperRatio: number;
  specialRatio: number;
  entropy: number;
}

export function charStats(s: string): CharStats {
  const len = s.length || 1;
  let digit = 0;
  let upper = 0;
  let special = 0;
  for (const ch of s) {
    if (ch >= '0' && ch <= '9') digit++;
    else if (ch >= 'A' && ch <= 'Z') upper++;
    else if (!/[a-z\s]/i.test(ch)) special++;
  }
  return {
    len,
    digitRatio: digit / len,
    upperRatio: upper / len,
    specialRatio: special / len,
    entropy: shannonEntropy(s),
  };
}

/**
 * 긴 토큰(≥16) 중 고엔트로피(≥4.0) 구간을 찾아 난독/인코딩 후보를 반환.
 * base64 페이로드, DGA 유사 도메인, 패킹 문자열 탐지에 사용.
 */
export function findHighEntropyTokens(text: string, minLen = 16, minH = 4.0): { token: string; entropy: number }[] {
  const out: { token: string; entropy: number }[] = [];
  const cands = text.match(/[A-Za-z0-9+/=._-]{16,}/g) || [];
  for (const c of cands) {
    if (c.length < minLen) continue;
    const h = shannonEntropy(c);
    if (h >= minH) out.push({ token: c, entropy: Number(h.toFixed(2)) });
  }
  return out.sort((a, b) => b.entropy - a.entropy);
}
