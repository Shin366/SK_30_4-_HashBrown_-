import { useCallback, useRef, useState, type DragEvent } from 'react';
import { useAnalysis } from '@/context/AnalysisContext';
import { getAiConfig, toggleAiKey } from '@/services/aiClient';
import { SAMPLE_SETS } from '@/data/sampleLogs';
import { IconUpload } from '@/components/common/icons';
import { BrandLogo } from '@/components/common/Logo';

export function LogUploader() {
  const { analyzeFile, analyzeText, status, error } = useAnalysis();
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const busy = status === 'parsing' || status === 'analyzing';

  const onDrop = useCallback(
    (e: DragEvent) => {
      e.preventDefault();
      setDragging(false);
      const file = e.dataTransfer.files?.[0];
      if (file) void analyzeFile(file);
    },
    [analyzeFile],
  );

  return (
    <div
      style={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: 24,
        background:
          'radial-gradient(900px 480px at 18% -12%, rgba(109,40,217,0.10), transparent), radial-gradient(820px 460px at 88% 0%, rgba(14,165,233,0.08), transparent), var(--bg-0)',
      }}
    >
      <div style={{ width: '100%', maxWidth: 720 }}>
        <div className="col" style={{ alignItems: 'center', gap: 10, marginBottom: 28, textAlign: 'center' }}>
          <BrandLogo size={56} />
          <h1 style={{ fontSize: 26 }}>HashBrown · AI 포렌식 분석 대시보드</h1>
          <p className="muted" style={{ maxWidth: 540, margin: 0 }}>
            침해사고 로그 또는 NTFS MFT 를 업로드하면 이상징후/의심파일 추출,
            IOC·MITRE ATT&CK·CVE 매핑, 타임라인, 트래픽 이상탐지, 분석 가이드까지 자동 생성합니다.
          </p>
          <span className="badge badge-low" style={{ marginTop: 4 }}>
            ● 모든 분석은 브라우저 내 로컬 처리 (데이터 외부 유출 없음)
          </span>
          <button
            className="btn btn-ghost"
            style={{ marginTop: 6, padding: '3px 10px', fontSize: 12, color: getAiConfig() ? 'var(--accent)' : undefined }}
            onClick={() => toggleAiKey()}
            title={getAiConfig() ? '생성형 AI 연동됨 · 클릭하여 해제' : '생성형 AI 연동 (키는 이 브라우저 localStorage 에만 저장)'}
          >
            {getAiConfig() ? `● 생성형 AI 연동됨 (${getAiConfig()!.model})` : '＋ 생성형 AI 연동 (선택)'}
          </button>
        </div>

        <div
          onDragOver={(e) => {
            e.preventDefault();
            setDragging(true);
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={onDrop}
          onClick={() => inputRef.current?.click()}
          className="card"
          style={{
            padding: '44px 24px',
            textAlign: 'center',
            cursor: 'pointer',
            border: `1.5px dashed ${dragging ? 'var(--accent)' : 'var(--surface-border-strong)'}`,
            background: dragging ? 'var(--accent-soft)' : 'var(--bg-1)',
            transition: 'all 0.15s',
          }}
        >
          <input
            ref={inputRef}
            type="file"
            accept=".txt,.log,.csv,.tsv,.evtx,.xlsx,.xls,text/plain,text/csv"
            style={{ display: 'none' }}
            onChange={(e) => {
              const f = e.target.files?.[0];
              if (f) void analyzeFile(f);
            }}
          />
          {busy ? (
            <div className="col" style={{ alignItems: 'center', gap: 12 }}>
              <div className="spinner" />
              <span className="muted">
                {status === 'parsing' ? '로그 파싱 중…' : '분석·매핑·시각화 중…'}
              </span>
            </div>
          ) : (
            <div className="col" style={{ alignItems: 'center', gap: 10 }}>
              <span style={{ color: 'var(--accent)' }}><IconUpload size={34} /></span>
              <strong style={{ fontSize: 16 }}>로그 / MFT 파일을 드래그하거나 클릭하여 업로드</strong>
              <span className="text-sm muted">지원 포맷: TXT · LOG · CSV · 웹로그 · XLSX(MFT) · MFT(analyzeMFT/MFTECmd)</span>
              <span className="text-xs dim">한글(EUC-KR/CP949) 자동 인식 · 엑셀 MFT 자동 감지</span>
            </div>
          )}
        </div>

        {error && (
          <div className="card card-pad mt-16" style={{ borderColor: 'var(--sev-critical)', color: 'var(--sev-critical)' }}>
            {error}
          </div>
        )}

        <div className="mt-16">
          <div className="spread" style={{ marginBottom: 10 }}>
            <span className="text-sm muted">또는 데모용 합성 로그로 바로 체험</span>
            <span className="text-xs dim">실습·합성 데이터</span>
          </div>
          <div className="grid grid-3">
            {SAMPLE_SETS.map((s) => (
              <button
                key={s.id}
                className="card card-pad"
                disabled={busy}
                onClick={() => void analyzeText(s.fileName, s.content)}
                style={{ textAlign: 'left', cursor: 'pointer', border: '1px solid var(--surface-border)' }}
              >
                <div style={{ fontWeight: 650, marginBottom: 4 }}>{s.name}</div>
                <div className="text-xs muted" style={{ lineHeight: 1.5 }}>{s.description}</div>
                <div className="text-xs dim mono mt-8">{s.fileName}</div>
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
