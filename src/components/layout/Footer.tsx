import { useAnalysis } from '@/context/AnalysisContext';
import { getAiConfig, toggleAiKey } from '@/services/aiClient';
import { formatTimestamp } from '@/utils/format';

export function Footer() {
  const { result, reset } = useAnalysis();
  const ai = getAiConfig();

  return (
    <footer className="app-footer">
      <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
        <span style={{ fontWeight: 600, color: 'var(--text-1)' }}>HashBrown</span>
        <span className="sep">·</span>
        <span>AI 포렌식 분석 보조 도구</span>
        <span className="sep">·</span>
        <span className="row" style={{ gap: 6 }}><span className="live-dot" /> 로컬 처리 · 외부 유출 없음</span>
        <span className="sep">·</span>
        <button
          className="btn btn-ghost"
          style={{ padding: '2px 8px', fontSize: 11, color: ai ? 'var(--accent)' : undefined }}
          onClick={() => toggleAiKey()}
          title={ai ? `생성형 AI 연동됨 (${ai.model}) · 클릭하여 해제` : '생성형 AI 연동 (키는 localStorage 에만 저장)'}
        >
          {ai ? `● AI 연동됨 (${ai.model})` : 'AI 연동'}
        </button>
      </div>

      <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
        <span>ATT&amp;CK · NVD 교차검증 2026-06-21</span>
        {result && (
          <>
            <span className="sep">·</span>
            <span className="num">{result.fileName}</span>
            <span className="sep">·</span>
            <span className="num">{formatTimestamp(result.parsedAt)}</span>
            <span className="sep">·</span>
            <button
              className="btn btn-ghost"
              style={{ padding: '2px 8px', fontSize: 11 }}
              onClick={reset}
              title="처음 화면으로 (새 분석)"
            >
              새 분석 ↺
            </button>
          </>
        )}
      </div>
    </footer>
  );
}
