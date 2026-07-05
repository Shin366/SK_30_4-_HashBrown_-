import { readXlsx } from './xlsxReader';

// =====================================================================
// 파일 적재 (REQ-NF-004, REQ-NF-005)
// File → 정규화된 결과. xlsx/xls 는 OOXML 파싱, csv/txt 는 인코딩 자동판별.
// 전부 로컬에서 처리.
// =====================================================================

export interface IngestResult {
  fileName: string;
  fileSize: number;
  kind: 'text' | 'rows';
  text?: string;
  rows?: string[][]; // rows[0] = 헤더
}

/** BOM/휴리스틱 기반 디코딩 (UTF-8 우선, 한글 깨짐 시 EUC-KR/CP949 폴백) */
export function decodeBytes(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    return new TextDecoder('utf-8').decode(bytes.subarray(3));
  }
  if (bytes.length >= 2 && bytes[0] === 0xff && bytes[1] === 0xfe) {
    return new TextDecoder('utf-16le').decode(bytes.subarray(2));
  }
  if (bytes.length >= 2 && bytes[0] === 0xfe && bytes[1] === 0xff) {
    return new TextDecoder('utf-16be').decode(bytes.subarray(2));
  }
  const utf8 = new TextDecoder('utf-8').decode(bytes);
  const bad = (utf8.match(/�/g) || []).length;
  if (bad > 0) {
    // 한글 Windows CSV(EUC-KR/CP949) 폴백
    for (const enc of ['euc-kr', 'cp949', 'windows-949']) {
      try {
        const alt = new TextDecoder(enc).decode(bytes);
        const bad2 = (alt.match(/�/g) || []).length;
        if (bad2 < bad) return alt;
      } catch {
        /* 미지원 라벨 무시 */
      }
    }
  }
  return utf8;
}

function splitDelimited(line: string, delim: string): string[] {
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
    } else if (ch === delim && !inQ) {
      out.push(cur);
      cur = '';
    } else cur += ch;
  }
  out.push(cur);
  return out.map((s) => s.trim());
}

export function csvToRows(text: string): string[][] {
  const lines = text.split(/\r?\n/).filter((l) => l.length > 0);
  if (lines.length === 0) return [];
  // 구분자 판별: 헤더에 탭이 콤마보다 많으면 TSV
  const head = lines[0];
  const delim = (head.match(/\t/g)?.length ?? 0) > (head.match(/,/g)?.length ?? 0) ? '\t' : ',';
  return lines.map((l) => splitDelimited(l, delim));
}

function extOf(name: string): string {
  return name.toLowerCase().split('.').pop() ?? '';
}

export function ingestArrayBuffer(fileName: string, fileSize: number, buf: ArrayBuffer): IngestResult {
  const ext = extOf(fileName);
  if (ext === 'xlsx' || ext === 'xlsm' || ext === 'xls') {
    const sheet = readXlsx(buf);
    return { fileName, fileSize, kind: 'rows', rows: sheet.rows };
  }
  const text = decodeBytes(buf);
  if (ext === 'csv' || ext === 'tsv') {
    return { fileName, fileSize, kind: 'rows', rows: csvToRows(text), text };
  }
  return { fileName, fileSize, kind: 'text', text };
}

export async function ingestFile(file: File): Promise<IngestResult> {
  const buf = await file.arrayBuffer();
  return ingestArrayBuffer(file.name, file.size, buf);
}
