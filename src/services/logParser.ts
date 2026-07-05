import type { LogEntry, LogFormat } from '@/types';
import { makeId } from '@/utils/format';

// =====================================================================
// 로그 파서 (REQ-F-001, REQ-NF-004)
// TXT / CSV / EVTX(텍스트 export) / 웹로그(CLF·Combined) 지원.
// =====================================================================

const MONTHS: Record<string, number> = {
  jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5,
  jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11,
};

/** 다양한 포맷의 타임스탬프를 ISO 문자열로 정규화 */
export function parseTimestamp(line: string): { iso: string | null; raw?: string } {
  // Apache: [10/Oct/2000:13:55:36 -0700]
  const apache = line.match(/\[(\d{2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})(?:\s*([+-]\d{4}))?/);
  if (apache) {
    const [, d, mon, y, h, mi, s, off] = apache;
    const m = MONTHS[mon.toLowerCase()];
    if (m !== undefined) {
      // 오프셋(±HHMM)이 있으면 정확한 UTC 로 환산한다(변조·미기록이 아닌 한
      // 절대시각 보존). 오프셋이 없으면 기존대로 로컬 시각으로 해석.
      let dt: Date;
      if (off) {
        const offMin = (off[0] === '-' ? -1 : 1) * (Number(off.slice(1, 3)) * 60 + Number(off.slice(3, 5)));
        dt = new Date(Date.UTC(Number(y), m, Number(d), Number(h), Number(mi), Number(s)) - offMin * 60000);
      } else {
        dt = new Date(Number(y), m, Number(d), Number(h), Number(mi), Number(s));
      }
      if (!Number.isNaN(dt.getTime())) return { iso: dt.toISOString(), raw: apache[0] };
    }
  }
  // ISO: 2026-06-12T13:55:36 or 2026-06-12 13:55:36(.mmm)
  const iso = line.match(/(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?/);
  if (iso) {
    const [, y, mo, d, h, mi, s] = iso;
    const dt = new Date(Number(y), Number(mo) - 1, Number(d), Number(h), Number(mi), Number(s));
    if (!Number.isNaN(dt.getTime())) return { iso: dt.toISOString(), raw: iso[0] };
  }
  // Syslog: Oct 10 13:55:36  (연도 미포함 → 현재 연도 가정)
  const sys = line.match(/\b([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\b/);
  if (sys) {
    const m = MONTHS[sys[1].toLowerCase()];
    if (m !== undefined) {
      const dt = new Date(2026, m, Number(sys[2]), Number(sys[3]), Number(sys[4]), Number(sys[5]));
      if (!Number.isNaN(dt.getTime())) return { iso: dt.toISOString(), raw: sys[0] };
    }
  }
  // Epoch (10 or 13 digits)
  const ep = line.match(/\b(1[0-9]{9})(\d{3})?\b/);
  if (ep) {
    const ms = ep[2] ? Number(ep[1]) * 1000 + Number(ep[2]) : Number(ep[1]) * 1000;
    const dt = new Date(ms);
    if (!Number.isNaN(dt.getTime())) return { iso: dt.toISOString(), raw: ep[0] };
  }
  return { iso: null };
}

export function detectFormat(fileName: string, sample: string): LogFormat {
  const ext = fileName.toLowerCase().split('.').pop() ?? '';
  if (ext === 'csv') return 'csv';
  if (ext === 'evtx') return 'evtx';
  // 웹로그 휴리스틱: CLF/Combined 패턴
  if (/"\s*(GET|POST|PUT|DELETE|HEAD)\s+\S+\s+HTTP\/\d/i.test(sample)) return 'weblog';
  if (ext === 'log' && /\d+\.\d+\.\d+\.\d+\s+-\s+/.test(sample)) return 'weblog';
  return 'txt';
}

const IPV4 = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/;

// --- Combined Log Format 파서 ---
const CLF = new RegExp(
  '^(\\S+)\\s+\\S+\\s+(\\S+)\\s+\\[([^\\]]+)\\]\\s+"(\\S+)\\s+([^"]*?)\\s+(HTTP/[\\d.]+)?"\\s+(\\d{3})\\s+(\\S+)(?:\\s+"([^"]*)"\\s+"([^"]*)")?',
);

function parseWebLogLine(line: string, lineNumber: number, source: string): LogEntry | null {
  const m = line.match(CLF);
  const { iso } = parseTimestamp(line);
  if (m) {
    const [, ip, user, , method, url, , status, bytes, , ua] = m;
    return {
      id: makeId('log'),
      lineNumber,
      timestamp: iso,
      source,
      sourceIp: ip,
      user: user && user !== '-' ? user : undefined,
      method,
      url,
      statusCode: Number(status),
      bytes: bytes === '-' ? 0 : Number(bytes),
      userAgent: ua || undefined,
      message: `${method} ${url} → ${status}`,
      raw: line,
      format: 'weblog',
    };
  }
  // CLF 매칭 실패 → 일반 라인 폴백
  return genericLine(line, lineNumber, source, 'weblog');
}

// --- 일반 텍스트 라인 ---
function genericLine(line: string, lineNumber: number, source: string, format: LogFormat): LogEntry {
  const { iso, raw } = parseTimestamp(line);
  const ipMatch = line.match(IPV4);
  const httpMatch = line.match(/\b(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(\/\S*)/i);
  // HTTP/x.x 컨텍스트가 있을 때만 상태코드로 인정한다. (예전엔 접두부가 optional 이라
  // 라인 안의 아무 3자리 숫자 — 포트·PID·무관한 403/500 — 를 statusCode 로 오인해
  // 무차별대입/열거 오탐과 트래픽 이상점수 부풀림을 유발했다.)
  const statusMatch = line.match(/HTTP\/\d\.\d"?\s+(\d{3})\b/i);
  return {
    id: makeId('log'),
    lineNumber,
    timestamp: iso,
    rawTimestamp: raw,
    source,
    sourceIp: ipMatch ? ipMatch[0] : undefined,
    method: httpMatch ? httpMatch[1].toUpperCase() : undefined,
    url: httpMatch ? httpMatch[2] : undefined,
    statusCode: statusMatch ? Number(statusMatch[1]) : undefined,
    message: line.trim().slice(0, 500),
    raw: line,
    format,
  };
}

// --- CSV 파서 (간단한 따옴표 처리 포함) ---
function splitCsv(line: string): string[] {
  const out: string[] = [];
  let cur = '';
  let inQ = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      if (inQ && line[i + 1] === '"') {
        cur += '"';
        i++;
      } else inQ = !inQ;
    } else if (ch === ',' && !inQ) {
      out.push(cur);
      cur = '';
    } else cur += ch;
  }
  out.push(cur);
  return out.map((s) => s.trim());
}

function parseCsv(content: string, source: string): LogEntry[] {
  const lines = content.split(/\r?\n/).filter((l) => l.trim().length > 0);
  if (lines.length === 0) return [];
  const headers = splitCsv(lines[0]).map((h) => h.toLowerCase());
  const find = (...keys: string[]) => headers.findIndex((h) => keys.some((k) => h.includes(k)));
  const tsIdx = find('time', 'date', '시간', '일시');
  const ipIdx = find('ip', 'src', 'source', 'client', '출발지');
  const msgIdx = find('message', 'msg', 'event', 'description', 'detail', '내용', '메시지');
  const userIdx = find('user', 'account', '사용자', '계정');
  const statusIdx = find('status', 'code', 'result', '결과');

  const out: LogEntry[] = [];
  for (let i = 1; i < lines.length; i++) {
    const cols = splitCsv(lines[i]);
    const joined = cols.join(' ');
    const { iso } = tsIdx >= 0 && cols[tsIdx] ? parseTimestamp(cols[tsIdx]) : parseTimestamp(joined);
    const ipFromCol = ipIdx >= 0 ? cols[ipIdx] : undefined;
    const ipMatch = joined.match(IPV4);
    out.push({
      id: makeId('log'),
      lineNumber: i + 1,
      timestamp: iso,
      source,
      sourceIp: ipFromCol && IPV4.test(ipFromCol) ? ipFromCol : ipMatch ? ipMatch[0] : undefined,
      user: userIdx >= 0 ? cols[userIdx] || undefined : undefined,
      statusCode: statusIdx >= 0 && /^\d{3}$/.test(cols[statusIdx]) ? Number(cols[statusIdx]) : undefined,
      message: msgIdx >= 0 ? cols[msgIdx] : joined.slice(0, 500),
      raw: lines[i],
      format: 'csv',
    });
  }
  return out;
}

/** 메인 진입점: 파일명 + 내용 → LogEntry[] */
export function parseLogs(fileName: string, content: string): { entries: LogEntry[]; format: LogFormat } {
  const sample = content.slice(0, 4000);
  const format = detectFormat(fileName, sample);
  if (format === 'csv') {
    return { entries: parseCsv(content, fileName), format };
  }
  const lines = content.split(/\r?\n/);
  const entries: LogEntry[] = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!line.trim()) continue;
    if (format === 'weblog') {
      const e = parseWebLogLine(line, i + 1, fileName);
      if (e) entries.push(e);
    } else {
      entries.push(genericLine(line, i + 1, fileName, format));
    }
  }
  return { entries, format };
}
