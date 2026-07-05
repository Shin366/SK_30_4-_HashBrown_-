import { useRef } from 'react';
import { useAnalysis, type ViewKey } from '@/context/AnalysisContext';
import { IconUpload } from '@/components/common/icons';
import { BrandLogo } from '@/components/common/Logo';

interface NavItem { key: ViewKey; label: string }

function navItems(isMft: boolean): NavItem[] {
  // 파일 종류와 무관하게 항상 동일한 7개 탭을 노출 (데모와 일관)
  return [
    { key: 'overview', label: '개요' },
    { key: 'logs', label: isMft ? 'MFT 분석' : '로그 분석' },
    { key: 'ml', label: 'ML 분석' },
    { key: 'threats', label: '위협 매핑' },
    { key: 'timeline', label: '타임라인' },
    { key: 'traffic', label: '트래픽' },
    { key: 'report', label: '가이드' },
  ];
}

export function Header() {
  const { activeView, setActiveView, result, analyzeFile, status } = useAnalysis();
  const inputRef = useRef<HTMLInputElement>(null);
  const busy = status === 'parsing' || status === 'analyzing';
  const hasData = status === 'done' && result;
  const NAV = navItems(result?.kind === 'mft');

  return (
    <header className="app-header">
      <div className="brand">
        <BrandLogo size={30} />
        <span className="brand-name">HashBrown</span>
      </div>

      <nav className="nav-pills">
        {NAV.map((item) => {
          const active = activeView === item.key;
          const locked = !hasData && item.key !== 'overview';
          return (
            <button
              key={item.key}
              className={`nav-pill${active ? ' active' : ''}`}
              disabled={locked}
              onClick={() => setActiveView(item.key)}
            >
              {active && <span className="pill-dot" />}
              {item.label}
            </button>
          );
        })}
      </nav>

      <div className="header-actions">
        <span
          className="row"
          title="모든 분석은 브라우저 내 로컬 처리"
          style={{
            gap: 7,
            padding: '5px 11px',
            borderRadius: 999,
            border: '1px solid color-mix(in srgb, var(--sev-low) 35%, transparent)',
            background: 'color-mix(in srgb, var(--sev-low) 9%, transparent)',
            color: 'var(--sev-low)',
            fontSize: 11,
            fontWeight: 700,
            letterSpacing: '0.04em',
          }}
        >
          <span className="live-dot" /> LOCAL
        </span>

        <input
          ref={inputRef}
          type="file"
          accept=".txt,.log,.csv,.tsv,.evtx,.xlsx,.xls,text/plain,text/csv"
          style={{ display: 'none' }}
          onChange={(e) => {
            const f = e.target.files?.[0];
            if (f) void analyzeFile(f);
            e.target.value = '';
          }}
        />
        <button className="btn btn-primary" disabled={busy} onClick={() => inputRef.current?.click()} title="새 로그/MFT 파일 업로드">
          {busy ? <span className="spinner" style={{ width: 14, height: 14 }} /> : <IconUpload size={15} />}
          {busy ? '분석 중…' : '새 파일'}
        </button>
      </div>
    </header>
  );
}
