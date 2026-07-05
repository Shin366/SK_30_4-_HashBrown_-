import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react';
import type { AnalysisResult, AnalysisStatus } from '@/types';
import { runAnalysis } from '@/services/analysisEngine';
import { ingestFile, type IngestResult } from '@/services/fileIngest';
import { isAiConfigured, generateAiNarrative } from '@/services/aiClient';
import { SAMPLE_SETS } from '@/data/sampleLogs';

// AI 로 보낼 요약(집계치만 — 민감 원문 미포함, REQ-NF-005 준수)
function buildAiSummary(r: AnalysisResult): string {
  const facts = r.report.factsVsAssessments.facts.join(' ');
  const tech = r.techniques.slice(0, 5).map((t) => `${t.id} ${t.name}`).join(', ');
  return `[집계] ${facts} 주요 ATT&CK 기법: ${tech || '없음'}.`;
}

// =====================================================================
// 분석 상태 전역 컨텍스트. 패널들은 useAnalysis() 로 결과를 구독한다.
// =====================================================================

export type ViewKey =
  | 'overview'
  | 'logs'
  | 'ml'
  | 'threats'
  | 'timeline'
  | 'traffic'
  | 'report';

// 유효한 뷰 키 목록 — 딥링크(?view=) 값 검증용(잘못된 값이 오면 무시).
const VIEW_KEYS: readonly ViewKey[] = ['overview', 'logs', 'ml', 'threats', 'timeline', 'traffic', 'report'];

interface AnalysisContextValue {
  status: AnalysisStatus;
  result: AnalysisResult | null;
  error: string | null;
  activeView: ViewKey;
  setActiveView: (v: ViewKey) => void;
  analyzeFile: (file: File) => Promise<void>;
  analyzeText: (fileName: string, text: string) => Promise<void>;
  reset: () => void;
}

const AnalysisContext = createContext<AnalysisContextValue | null>(null);

const tick = () => new Promise((r) => setTimeout(r, 30));

export function AnalysisProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<AnalysisStatus>('idle');
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [activeView, setActiveView] = useState<ViewKey>('overview');
  // 분석 실행 세대(generation) — 늦게 도착한 이전 분석의 비동기 AI 내러티브가
  // 더 새로운 분석 결과를 덮어쓰지 못하게 하는 가드.
  const runIdRef = useRef(0);

  const runIngest = useCallback(async (produce: () => Promise<IngestResult>) => {
    const myRun = ++runIdRef.current;
    setStatus('parsing');
    setError(null);
    try {
      await tick(); // 스피너 렌더 기회
      const ingest = await produce();
      setStatus('analyzing');
      await tick();
      const res = runAnalysis({ ingest, nowIso: new Date().toISOString() });
      setResult(res);
      setStatus('done');
      setActiveView('overview');
      // [AI] 키 설정 시 생성형 AI 내러티브로 보강 (실패/거부 시 로컬 결과 그대로 유지)
      if (isAiConfigured()) {
        void (async () => {
          const aiText = await generateAiNarrative({
            summary: buildAiSummary(res),
            question: '위 요약을 바탕으로 이 침해사고의 핵심을 한국어 3~4문장으로 정리해줘. 사실과 추정을 구분해서.',
          });
          // 이 AI 응답이 도착하는 사이 사용자가 다른 파일을 분석/리셋했다면 무시.
          if (aiText && runIdRef.current === myRun) {
            setResult((prev) =>
              prev ? { ...prev, report: { ...prev.report, narrative: aiText, engine: 'ai' } } : prev,
            );
          }
        })();
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : '분석 중 오류가 발생했습니다.');
      setStatus('error');
    }
  }, []);

  const analyzeFile = useCallback(
    async (file: File) => {
      await runIngest(() => ingestFile(file));
    },
    [runIngest],
  );

  const analyzeText = useCallback(
    async (fileName: string, text: string) => {
      await runIngest(async () => ({
        fileName,
        fileSize: new Blob([text]).size,
        kind: 'text',
        text,
      }));
    },
    [runIngest],
  );

  const reset = useCallback(() => {
    runIdRef.current++; // 진행 중인 이전 AI 요청 무효화
    setResult(null);
    setStatus('idle');
    setError(null);
    setActiveView('overview');
  }, []);

  // 딥링크 데모: ?sample=<id> 로 진입 시 해당 합성 로그를 자동 분석,
  // &view=<key> 로 진입 시 분석 완료 후 해당 탭으로 이동(공유·시연용).
  const didAuto = useRef(false);
  useEffect(() => {
    if (didAuto.current || typeof window === 'undefined') return;
    didAuto.current = true;
    const sid = new URLSearchParams(window.location.search).get('sample');
    if (sid) {
      const s = SAMPLE_SETS.find((x) => x.id === sid);
      if (s) void analyzeText(s.fileName, s.content);
    }
  }, [analyzeText]);
  // ?view=<key> 딥링크는 "데모 진입(?sample=...) 직후 1회"만 적용한다. 그렇지 않으면
  // URL 에 남은 view 파라미터가 매 분석 완료마다 재적용되어, 사용자가 새 파일을
  // 업로드해도 계속 그 탭으로 튀는 문제가 생긴다(업로드는 항상 메인에서 시작해야 함).
  const didView = useRef(false);
  useEffect(() => {
    if (status !== 'done' || didView.current) return;
    didView.current = true;
    const params = new URLSearchParams(window.location.search);
    if (!params.get('sample')) return; // 직접 업로드로 진입한 경우엔 뷰 강제 이동 없음
    const v = params.get('view');
    // 알 수 없는 값(?view=garbage)이면 무시 — 검증 없이 캐스팅하면 App.tsx 에서
    // PAGE[activeView] 가 undefined 가 되어 화면 전체가 크래시한다.
    if (v && VIEW_KEYS.includes(v as ViewKey)) setActiveView(v as ViewKey);
  }, [status]);

  const value = useMemo<AnalysisContextValue>(
    () => ({ status, result, error, activeView, setActiveView, analyzeFile, analyzeText, reset }),
    [status, result, error, activeView, analyzeFile, analyzeText, reset],
  );

  return <AnalysisContext.Provider value={value}>{children}</AnalysisContext.Provider>;
}

export function useAnalysis(): AnalysisContextValue {
  const ctx = useContext(AnalysisContext);
  if (!ctx) throw new Error('useAnalysis must be used within AnalysisProvider');
  return ctx;
}
