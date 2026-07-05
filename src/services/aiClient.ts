// =====================================================================
// 생성형 AI API 클라이언트 (선택적) — REQ-F-005 보조
// 기본값: 미설정 → 100% 로컬 규칙기반 엔진 사용 (REQ-NF-005 데이터 보안).
// .env 에 VITE_AI_API_KEY/URL 설정 시에만 외부 호출 활성화.
// =====================================================================

interface AiConfig {
  key: string;
  url: string;
  model: string;
}

/**
 * AI 설정 조회. 런타임(localStorage) 우선 → 빌드타임(.env) 폴백.
 * 런타임 우선이므로 빌드 산출물(dist/exe)에 키를 굽지 않아도 로컬에서 키를 넣어 시연 가능.
 * (키가 빌드에 박히면 배포 시 노출되므로, 로컬 데모는 localStorage 사용을 권장)
 */
export function getAiConfig(): AiConfig | null {
  const ls = typeof localStorage !== 'undefined' ? localStorage : null;
  const key = ls?.getItem('hb_ai_key') || (import.meta.env.VITE_AI_API_KEY as string | undefined) || '';
  const url = ls?.getItem('hb_ai_url') || (import.meta.env.VITE_AI_API_URL as string | undefined) || '';
  if (!key || !url) return null;
  const model =
    ls?.getItem('hb_ai_model') || (import.meta.env.VITE_AI_MODEL as string | undefined) || 'claude-fable-5';
  return { key, url, model };
}

export function isAiConfigured(): boolean {
  return getAiConfig() !== null;
}

/** 런타임 AI 키 설정/해제 (localStorage 전용 — 빌드·서버에 저장 안 됨). UI 버튼에서 호출. */
export function toggleAiKey(): void {
  if (getAiConfig()) {
    if (confirm('AI 연동을 해제할까요? (저장된 키 삭제)')) {
      ['hb_ai_key', 'hb_ai_url', 'hb_ai_model'].forEach((k) => localStorage.removeItem(k));
      location.reload();
    }
    return;
  }
  const k = prompt(
    'Anthropic API 키(sk-ant-...)를 입력하세요.\n이 브라우저의 localStorage 에만 저장되며 서버·빌드파일에는 포함되지 않습니다.',
  );
  if (!k || !k.trim()) return;
  localStorage.setItem('hb_ai_key', k.trim());
  localStorage.setItem('hb_ai_url', 'https://api.anthropic.com/v1/messages');
  localStorage.setItem('hb_ai_model', 'claude-fable-5');
  location.reload();
}

export interface AiNarrativeRequest {
  summary: string; // 로컬 분석 요약(민감 원문 대신 집계치 전달 권장)
  question: string;
}

/**
 * AI 내러티브 생성. 미설정 시 null 반환 → 호출측이 로컬 결과 사용.
 * 설정 시 OpenAI/Anthropic 호환 Messages 형태로 호출(엔드포인트에 맞게 조정).
 */
export async function generateAiNarrative(req: AiNarrativeRequest): Promise<string | null> {
  const cfg = getAiConfig();
  if (!cfg) return null;

  const { url, key, model } = cfg;
  const isFable = /fable|mythos/i.test(model); // 항상 thinking on · refusal 폴백 대상

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'x-api-key': key,
    'anthropic-version': '2023-06-01',
    // 브라우저(클라이언트)에서 Anthropic 직접 호출 허용 (CORS 우회 공식 헤더)
    'anthropic-dangerous-direct-browser-access': 'true',
  };
  // Fable/Mythos: 보안·악성코드 문맥은 안전분류기 오탐 거부(refusal)가 날 수 있어 서버측 폴백(→Opus 4.8) 활성화
  if (isFable) headers['anthropic-beta'] = 'server-side-fallback-2026-06-01';

  const body: Record<string, unknown> = {
    model,
    max_tokens: 1024,
    messages: [
      {
        role: 'user',
        content: `당신은 침해사고 포렌식 분석 보조 AI 입니다. 사실과 추정을 구분해 한국어로 간결히 작성하세요.\n\n[분석요약]\n${req.summary}\n\n[요청]\n${req.question}`,
      },
    ],
  };
  if (isFable) body.fallbacks = [{ model: 'claude-opus-4-8' }];

  try {
    const res = await fetch(url, { method: 'POST', headers, body: JSON.stringify(body) });
    if (!res.ok) return null;
    const data = await res.json();
    if (data?.stop_reason === 'refusal') return null; // 분류기 거부 → 로컬 폴백
    // Anthropic: content[] 의 text 블록 결합 / OpenAI 호환: choices[0].message.content
    const anthropicText = Array.isArray(data?.content)
      ? data.content
          .filter((b: { type?: string }) => b?.type === 'text')
          .map((b: { text?: string }) => b.text ?? '')
          .join('')
          .trim()
      : '';
    return anthropicText || data?.choices?.[0]?.message?.content || null;
  } catch {
    return null; // 네트워크/CORS 오류 시 조용히 로컬 폴백
  }
}
