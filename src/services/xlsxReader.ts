import { unzipSync, strFromU8 } from 'fflate';

// =====================================================================
// 최소 XLSX 리더 (OOXML). SheetJS 대신 fflate + 자체 파서 사용.
//  - 보안 도구이므로 알려진 취약점 없는 경량 의존성만 사용.
//  - shared strings / inline strings / 숫자·불리언 셀 지원.
//  - 전부 로컬(브라우저)에서 처리 (REQ-NF-005).
// =====================================================================

export interface SheetData {
  name: string;
  rows: string[][]; // rows[0] = 헤더
}

const ENTITY: Record<string, string> = {
  amp: '&', lt: '<', gt: '>', quot: '"', apos: "'",
};

function decodeXml(s: string): string {
  return s.replace(/&(#x?[0-9a-fA-F]+|amp|lt|gt|quot|apos);/g, (_, e: string) => {
    if (e[0] === '#') {
      const code = e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      return Number.isFinite(code) ? String.fromCodePoint(code) : _;
    }
    return ENTITY[e] ?? _;
  });
}

/** 셀 참조(A1, AB12)에서 0-based 컬럼 인덱스 추출 */
function colIndex(ref: string): number {
  let n = 0;
  for (let i = 0; i < ref.length; i++) {
    const c = ref.charCodeAt(i);
    if (c >= 65 && c <= 90) n = n * 26 + (c - 64);
    else if (c >= 97 && c <= 122) n = n * 26 + (c - 96);
    else break;
  }
  return n - 1;
}

/** <si>..</si> 내부의 모든 <t>..</t> 텍스트를 이어붙여 공유문자열 1건 생성 */
function parseSharedStrings(xml: string): string[] {
  const out: string[] = [];
  const siRe = /<si\b[^>]*>([\s\S]*?)<\/si>/g;
  const tRe = /<t\b[^>]*>([\s\S]*?)<\/t>/g;
  let m: RegExpExecArray | null;
  while ((m = siRe.exec(xml)) !== null) {
    const inner = m[1];
    let text = '';
    let t: RegExpExecArray | null;
    tRe.lastIndex = 0;
    while ((t = tRe.exec(inner)) !== null) text += t[1];
    out.push(decodeXml(text));
  }
  return out;
}

function parseSheet(xml: string, shared: string[], maxRows: number): string[][] {
  const rows: string[][] = [];
  const rowRe = /<row\b[^>]*>([\s\S]*?)<\/row>/g;
  // 자체 닫힘 빈 행도 처리
  const cellRe = /<c\b([^>]*)(?:\/>|>([\s\S]*?)<\/c>)/g;
  const refRe = /r="([A-Z]+)\d+"/;
  const typeRe = /t="([^"]+)"/;
  const vRe = /<v\b[^>]*>([\s\S]*?)<\/v>/;
  const isTRe = /<t\b[^>]*>([\s\S]*?)<\/t>/g;

  let rm: RegExpExecArray | null;
  while ((rm = rowRe.exec(xml)) !== null) {
    if (rows.length >= maxRows) break;
    const rowXml = rm[1];
    const cells: string[] = [];
    let cm: RegExpExecArray | null;
    cellRe.lastIndex = 0;
    while ((cm = cellRe.exec(rowXml)) !== null) {
      const attrs = cm[1] ?? '';
      const body = cm[2] ?? '';
      const refM = attrs.match(refRe);
      const idx = refM ? colIndex(refM[1]) : cells.length;
      const tM = attrs.match(typeRe);
      const type = tM ? tM[1] : '';
      let value = '';
      if (type === 's') {
        const v = body.match(vRe);
        const si = v ? Number(v[1]) : -1;
        value = si >= 0 && si < shared.length ? shared[si] : '';
      } else if (type === 'inlineStr') {
        let t: RegExpExecArray | null;
        isTRe.lastIndex = 0;
        while ((t = isTRe.exec(body)) !== null) value += t[1];
        value = decodeXml(value);
      } else {
        const v = body.match(vRe);
        value = v ? decodeXml(v[1]) : '';
      }
      while (cells.length < idx) cells.push('');
      cells[idx] = value;
    }
    rows.push(cells);
  }
  return rows;
}

/** workbook.xml 에서 첫 시트 이름 */
function firstSheetName(wb: string): string {
  const m = wb.match(/<sheet\b[^>]*\bname="([^"]+)"/);
  return m ? decodeXml(m[1]) : 'Sheet1';
}

export function readXlsx(buffer: ArrayBuffer, maxRows = 500_000): SheetData {
  const files = unzipSync(new Uint8Array(buffer));
  const shared = files['xl/sharedStrings.xml'] ? parseSharedStrings(strFromU8(files['xl/sharedStrings.xml'])) : [];

  // 첫 워크시트 파일 선택
  const sheetKey =
    Object.keys(files)
      .filter((k) => /^xl\/worksheets\/sheet\d+\.xml$/.test(k))
      .sort()[0] ?? 'xl/worksheets/sheet1.xml';
  const sheetXml = files[sheetKey] ? strFromU8(files[sheetKey]) : '';
  const rows = parseSheet(sheetXml, shared, maxRows);

  const name = files['xl/workbook.xml'] ? firstSheetName(strFromU8(files['xl/workbook.xml'])) : 'Sheet1';
  return { name, rows };
}
