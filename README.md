# HashBrown · AI 기반 포렌식 분석 대시보드

침해사고 포렌식 분석을 위한 **AI 기반 분석 대시보드**(HashBrown).
로그 또는 NTFS MFT 를 업로드하면 이상징후 추출 → IOC·MITRE ATT&CK·CVE 매핑 →
머신러닝 이상탐지 → 타임라인·AI 추정 침입 경로 → 분석 가이드 보고서까지 자동 생성·시각화한다.

규칙기반 시그니처 + 머신러닝 + (선택)생성형 AI 를 결합한 **하이브리드 분석 엔진**이며,
모든 분석은 **브라우저 내(로컬)** 에서 수행되어 데이터가 외부로 유출되지 않는다 (REQ-NF-005).
설치가 필요 없는 단독 실행 파일(`release/HashBrown.exe`)로도 배포된다.

## 기능

| 패널 | 요구사항 | 설명 |
|------|----------|------|
| 통합 대시보드 | REQ-F-006 | KPI·심각도 분포·트래픽/의심유형·기법·타임라인·요약 통합 |
| 로그 분석 / MFT 분석 | REQ-F-001 | TXT/CSV/EVTX/웹로그 파싱 + 이상징후, 또는 NTFS MFT 의심파일 탐지 |
| ML 분석 | — | 비지도 이상탐지(Isolation Forest + 위협신호 Noisy-OR) · 지도 분류(NB, 5겹 교차검증) · 군집(K-Means) · 엔트로피 |
| 위협 매핑 | REQ-F-002 | IOC 추출 + ATT&CK 기법 + 관련 CVE + **공격자 특정(추정)**: 탐지 TTP·도구를 위협 그룹 프로파일과 대조해 유사 그룹 추정(확정 귀속 아님) |
| 타임라인·흐름도 | REQ-F-003 | 시간순 타임라인 + kill-chain 흐름도 + **AI 추정 침입 경로**(kill-chain 재구성) |
| 트래픽 분석 | REQ-F-004 | 출발지별 정상/비정상 확률 + 순위 막대그래프 (로그 전용) |
| 분석 가이드 | REQ-F-005 | 단계별 분석 가이드라인 + **Word(.doc) 내보내기** |

사실(Fact)과 추정(Assessment)은 `FACT` / `ASSESS` 태그로 구분 표기한다 (REQ-NF-002).

### 지원 입력 포맷 (REQ-NF-004)

- **로그**: TXT · LOG · CSV/TSV · 웹로그(CLF/Combined) · syslog · EVTX(텍스트 export)
- **MFT(NTFS Master File Table)**: `analyzeMFT` / `MFTECmd` 형식의 **XLSX 또는 CSV**.
  엑셀 바이너리(OOXML)를 직접 파싱하며(fflate), 컬럼/날짜(Excel 시리얼) 자동 인식.
- **한글 인코딩**: UTF-8/UTF-16 BOM 인식 + 깨짐 시 EUC-KR/CP949 자동 폴백.

### MFT 분석 정확성

대용량 MFT(수십만 행)를 컬럼 구조 기반으로 분석한다. 다음을 탐지:
- 의심 위치(Temp·Downloads·$Recycle.Bin 등) 실행/스크립트 파일 (T1105)
- 삭제(Inactive) 실행파일 (T1070.004), 이중 확장자 위장 (T1036.007)
- 비표준 ADS/NTFS 속성 (T1564.004), 시스템 프로세스명 위장 (T1036.005)
- 알려진 공격도구 파일명 (Mimikatz·Cobalt Strike·PsExec 등)

> **타임스탬프(Timestomp, T1070.006) 주의**: `$SI < $FN` 또는 `$SI 생성 > 수정` 은
> 정상 파일 복사·시스템 프로비저닝에서도 대량 발생하므로 **단독 경보로 올리지 않고**
> 정보성 지표로만 표시한다(오탐 방지). 의심 파일과 교차검증될 때만 보강 근거로 사용.

### 위협 인텔리전스 출처

MITRE ATT&CK 기법/전술과 CVE(CVSS) 데이터는 **공식 출처 기준 2026-06-21 교차검증** 완료.
- ATT&CK: https://attack.mitre.org (기법 ID·명칭·전술, 전술 ID)
- CVE/CVSS: https://nvd.nist.gov (CVSS v3.1 base score·severity)

각 항목은 UI 에서 공식 레퍼런스 링크(attack.mitre.org / nvd.nist.gov)로 연결된다.

## 기술 스택

- React 18 + TypeScript + Vite
- Recharts (차트/시각화)
- fflate (XLSX/OOXML 압축 해제 — 경량·무취약점)
- 순수 클라이언트 분석 엔진 (정규식·규칙·MFT 구조 기반)

## 실행

```bash
npm install
npm run dev      # http://localhost:5173
```

빌드 / 타입체크:

```bash
npm run build      # 타입체크 + 프로덕션 빌드
npm run typecheck  # 타입체크만
npm run preview    # 빌드 결과 미리보기
```

사용법: 업로드 화면에서 로그 파일을 드래그하거나, **데모용 합성 로그** 카드를 클릭해 바로 체험.

## (선택) 생성형 AI 연동

기본값은 100% 로컬 규칙 엔진이다. 보고서/내러티브를 외부 AI 로 강화하려면
`.env.example` 을 `.env` 로 복사 후 키를 입력한다. 미설정 시 자동으로 로컬 폴백한다.

```
VITE_AI_API_KEY=...
VITE_AI_API_URL=...
VITE_AI_MODEL=claude-fable-5
```

## 폴더 구조

```
DashBoard/
├─ docs/                        요구사항 문서·산출물(.docx 보고서/명세)
├─ public/                      정적 자원 (favicon)
├─ src/
│  ├─ types/                    공통 타입 (단일 계약)
│  ├─ data/                     규칙 DB (ATT&CK·CVE·IOC 패턴·MFT 규칙·샘플로그)
│  ├─ ml/                       브라우저 내 ML (NB·Isolation Forest·K-Means·엔트로피·특징공학)
│  ├─ services/                 분석 엔진 (파서·탐지·매핑·트래픽·타임라인·침입경로·ML·보고서)
│  ├─ context/                  전역 분석 상태
│  ├─ utils/                    포맷·차트 유틸
│  ├─ components/
│  │  ├─ common/                Card·Badge·StatCard·아이콘 등 공용
│  │  ├─ layout/                Header·Footer
│  │  ├─ upload/                LogUploader
│  │  └─ panels/                7개 기능 패널 (개요·로그/MFT·ML·위협·타임라인·트래픽·가이드)
│  ├─ App.tsx                   라우팅/셸
│  └─ main.tsx                  진입점
├─ _pkg/                        단독 실행 exe 패키징 소스 (HashBrown.cs)
├─ release/                     배포본 (HashBrown.exe)
├─ index.html
├─ package.json
└─ vite.config.ts
```

## 데이터 흐름

```
파일 업로드
  └─ services/analysisEngine.runAnalysis()   (로그 또는 MFT 경로 자동 분기)
       ├─ logParser / mftParser  포맷 감지 + 파싱     → LogEntry[] / MftRecord[]
       ├─ anomalyDetector        시그니처+빈도 탐지    → AnomalyEvent[]
       ├─ iocExtractor           IOC 추출 + VT 링크    → IOC[]
       ├─ attackMapper           ATT&CK 기법 + CVE     → AttackTechnique[] / CVE[]
       ├─ trafficAnalyzer        IP별 이상 확률        → TrafficScore[]
       ├─ mlAnalyzer             ML 하이브리드 계층    → MlAnalysis (이상탐지·분류·군집·엔트로피)
       ├─ timelineBuilder        타임라인 + 흐름도     → TimelineEvent[] / AttackFlow
       ├─ intrusionHypothesis    kill-chain 재구성     → IntrusionHypothesis (추정 침입 경로)
       └─ reportGenerator        가이드라인 + 내러티브 → ReportSummary
  → AnalysisResult → Context → 7개 패널 렌더링 + Word(.doc) 보고서 내보내기
```

## 제약/면책

본 도구는 침해사고 분석 **보조 수단**이다. AI/규칙 기반 결과(추정)는 반드시 분석가의 교차검증을
병행해야 하며, 분석 대상은 실습·합성 데이터를 가정한다 (요구사항정의서 제약사항).
