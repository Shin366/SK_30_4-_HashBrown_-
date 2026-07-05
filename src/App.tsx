import { useAnalysis, type ViewKey } from '@/context/AnalysisContext';
import { Header } from '@/components/layout/Header';
import { Footer } from '@/components/layout/Footer';
import { LogUploader } from '@/components/upload/LogUploader';
import { OverviewPanel } from '@/components/panels/OverviewPanel';
import { LogAnalysisPanel } from '@/components/panels/LogAnalysisPanel';
import { MftPanel } from '@/components/panels/MftPanel';
import { MlPanel } from '@/components/panels/MlPanel';
import { ThreatMappingPanel } from '@/components/panels/ThreatMappingPanel';
import { TimelinePanel } from '@/components/panels/TimelinePanel';
import { TrafficPanel } from '@/components/panels/TrafficPanel';
import { ReportPanel } from '@/components/panels/ReportPanel';

const PAGE: Record<ViewKey, { title: string; desc: string }> = {
  overview: { title: '통합 대시보드', desc: '분석·매핑·시각화 결과 통합 (REQ-F-006)' },
  logs: { title: '로그 분석', desc: '주요 이벤트·이상징후 추출 (REQ-F-001)' },
  ml: { title: '머신러닝 분석', desc: '비지도 이상탐지 · 지도 분류 · 군집화 (하이브리드)' },
  threats: { title: '위협 매핑', desc: 'IOC · MITRE ATT&CK · CVE 매핑 (REQ-F-002)' },
  timeline: { title: '타임라인 · 공격 흐름도', desc: '시간순 재구성 (REQ-F-003)' },
  traffic: { title: '트래픽 분석', desc: '정상/비정상 확률 스코어 (REQ-F-004)' },
  report: { title: '분석 가이드 보고서', desc: '단계별 분석 가이드라인 (REQ-F-005)' },
};

export default function App() {
  const { status, result, activeView } = useAnalysis();

  // 분석 전: 업로드 화면
  if (status !== 'done' || !result) {
    return <LogUploader />;
  }

  const page =
    activeView === 'logs' && result.kind === 'mft'
      ? { title: 'MFT 분석', desc: 'NTFS Master File Table 아티팩트 분석 (REQ-F-001)' }
      : PAGE[activeView];

  return (
    <div className="app-shell">
      <Header />
      <main className="main-scroll">
        <div className="main-canvas">
          <div className="page-band">
            <div className="col" style={{ minWidth: 0 }}>
              <h1 className="page-title">{page.title}</h1>
              <span className="page-desc">{page.desc}</span>
            </div>
            <div className="row" style={{ gap: 14, flexWrap: 'wrap' }}>
              <Stat label="이상징후" value={result.anomalies.length} />
              <Stat label="IOC" value={result.iocs.length} />
              <Stat label="ATT&CK" value={result.techniques.length} />
              <Stat label="CVE" value={result.cves.length} />
            </div>
          </div>

          {activeView === 'overview' && <OverviewPanel result={result} />}
          {activeView === 'logs' &&
            (result.kind === 'mft' ? <MftPanel result={result} /> : <LogAnalysisPanel result={result} />)}
          {activeView === 'ml' && <MlPanel result={result} />}
          {activeView === 'threats' && <ThreatMappingPanel result={result} />}
          {activeView === 'timeline' && <TimelinePanel result={result} />}
          {activeView === 'traffic' && <TrafficPanel result={result} />}
          {activeView === 'report' && <ReportPanel result={result} />}
        </div>
      </main>
      <Footer />
    </div>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div className="col" style={{ alignItems: 'flex-end', gap: 1 }}>
      <span className="num" style={{ fontFamily: 'var(--font-display)', fontSize: 21, fontWeight: 700, color: 'var(--text-0)', lineHeight: 1 }}>
        {value.toLocaleString()}
      </span>
      <span className="eyebrow" style={{ fontSize: 9.5 }}>{label}</span>
    </div>
  );
}
