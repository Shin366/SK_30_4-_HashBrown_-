import type { MftRecord } from '@/types';
import { parseTimestamp } from './logParser';

// =====================================================================
// MFT 표(rows) 파서 (REQ-F-001, REQ-NF-004)
// analyzeMFT / MFTECmd 등 다양한 헤더를 유연하게 매핑.
// 날짜는 Excel 시리얼(숫자) 또는 문자열 모두 처리.
// =====================================================================

function norm(h: string): string {
  return h.trim().toLowerCase();
}

/** Excel 시리얼(1899-12-30 기준) → ISO. 문자열 날짜도 처리. placeholder 는 null. */
export function parseMftDate(raw: string | undefined): string | null {
  if (!raw) return null;
  const v = raw.trim();
  if (!v) return null;
  // placeholder
  if (/^(no(si|fn)record|zero|n\/?a|-|0)$/i.test(v)) return null;
  // Excel 시리얼 숫자
  if (/^\d+(\.\d+)?$/.test(v)) {
    const serial = Number(v);
    if (serial > 1 && serial < 2958466) {
      // 1900-01-01 ~ 9999-12-31 범위
      const ms = Math.round((serial - 25569) * 86400000);
      const d = new Date(ms);
      if (!Number.isNaN(d.getTime())) return d.toISOString();
    }
    return null;
  }
  // 문자열 날짜
  const { iso } = parseTimestamp(v);
  if (iso) return iso;
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

interface ColMap {
  recordNumber: number;
  active: number;
  inUse: number;
  recordType: number;
  isDir: number;
  path: number;
  parentPath: number;
  fileName: number;
  siC: number; siM: number; siA: number; siE: number;
  fnC: number; fnM: number; fnA: number; fnE: number;
}

function buildColMap(headers: string[]): ColMap {
  const h = headers.map(norm);
  const find = (...keys: string[]) => h.findIndex((x) => keys.some((k) => x === k || x.includes(k)));
  return {
    recordNumber: find('record number', 'entry number', 'entrynumber', 'inode', 'recordnumber'),
    active: find('active'),
    inUse: find('in use', 'inuse'),
    recordType: find('record type', 'recordtype'),
    isDir: find('isdirectory', 'is directory'),
    path: find('filename #1', 'full path', 'fullpath', 'filepath', 'full name'),
    parentPath: find('parent path', 'parentpath'),
    fileName: find('filename', 'file name', 'name'),
    siC: find('std info creation', 'created0x10', 'si created', 'standardinfo creation'),
    siM: find('std info modification', 'lastmodified0x10', 'si modified'),
    siA: find('std info access', 'lastaccess0x10', 'si access'),
    siE: find('std info entry', 'lastrecordchange0x10', 'si entry'),
    fnC: find('fn info creation', 'created0x30', 'fn created', 'filename creation'),
    fnM: find('fn info modification', 'lastmodified0x30', 'fn modified'),
    fnA: find('fn info access', 'lastaccess0x30', 'fn access'),
    fnE: find('fn info entry', 'lastrecordchange0x30', 'fn entry'),
  };
}

/** 헤더가 MFT 표인지 판별 */
export function isMftTable(headers: string[]): boolean {
  const h = headers.map(norm);
  const has = (k: string) => h.some((x) => x.includes(k));
  const hasName = has('filename') || has('file name');
  const hasMftDates =
    has('std info creation') || has('created0x10') || has('fn info creation') || has('created0x30');
  const hasRec = has('record number') || has('entry number') || has('entrynumber') || has('inode');
  return hasName && (hasMftDates || (hasRec && (has('record type') || has('parent'))));
}

function basename(path: string): string {
  const clean = path.replace(/[\\/]+$/, '');
  const idx = Math.max(clean.lastIndexOf('/'), clean.lastIndexOf('\\'));
  return idx >= 0 ? clean.slice(idx + 1) : clean;
}

function extOf(name: string): string {
  // ADS(:) 제거 후 확장자
  const base = name.split(':')[0];
  const dot = base.lastIndexOf('.');
  return dot > 0 ? base.slice(dot + 1).toLowerCase() : '';
}

export function parseMft(rows: string[][]): MftRecord[] {
  if (rows.length < 2) return [];
  const cols = buildColMap(rows[0]);
  const out: MftRecord[] = [];

  for (let i = 1; i < rows.length; i++) {
    const r = rows[i];
    if (!r || r.length === 0) continue;
    const cell = (idx: number) => (idx >= 0 && idx < r.length ? r[idx] : '');

    // 경로 결정: 전체경로 컬럼 우선, 없으면 parent + filename 조합
    let path = cell(cols.path).trim();
    if (!path) {
      const p = cell(cols.parentPath).trim();
      const n = cell(cols.fileName).trim();
      path = p ? `${p.replace(/[\\/]+$/, '')}\\${n}` : n;
    }
    // 이름 없는($FILE_NAME 부재) 레코드도 총계에는 포함하되, 분석은 건너뛴다(경로 ''로 표기).
    const placeholder = !path || /^(no(si|fn)record|zero)$/i.test(path);
    const normPath = placeholder ? '' : path.replace(/\\/g, '/');
    const fileName = placeholder ? '' : basename(normPath);

    // active 판정: 'active' 컬럼 또는 'in use'
    let active = true;
    const activeVal = cell(cols.active).trim().toLowerCase();
    if (activeVal) active = !/inactive|deleted|false|no|0/.test(activeVal) && /active|true|yes|1/.test(activeVal);
    else {
      const inUse = cell(cols.inUse).trim().toLowerCase();
      if (inUse) active = /true|yes|1/.test(inUse);
    }

    let recordType = cell(cols.recordType).trim();
    if (!recordType) {
      const isDir = cell(cols.isDir).trim().toLowerCase();
      recordType = /true|yes|1/.test(isDir) ? 'Folder' : 'File';
    }

    out.push({
      recordNumber: Number(cell(cols.recordNumber)) || i,
      active,
      recordType,
      path: normPath,
      fileName,
      ext: placeholder ? '' : extOf(fileName),
      siCreated: parseMftDate(cell(cols.siC)),
      siModified: parseMftDate(cell(cols.siM)),
      siAccessed: parseMftDate(cell(cols.siA)),
      siEntry: parseMftDate(cell(cols.siE)),
      fnCreated: parseMftDate(cell(cols.fnC)),
      fnModified: parseMftDate(cell(cols.fnM)),
      fnAccessed: parseMftDate(cell(cols.fnA)),
      fnEntry: parseMftDate(cell(cols.fnE)),
    });
  }
  return out;
}
