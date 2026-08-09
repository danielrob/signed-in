import process from 'node:process';

let colorEnabled = supportsColor();
let quietEnabled = false;

const fallbackColumns = 100;
const maximumColumns = 88;
const minimumColumns = 32;
const asciiEnabled = prefersAscii();

// Applies invocation-level presentation choices without weakening errors, warnings, or prompts.
export function configureUi(options: { color?: boolean; quiet?: boolean }): void {
  if (options.color === false) {
    colorEnabled = false;
    process.env.NO_COLOR = '1';
  } else if (options.color === true) {
    colorEnabled = supportsColor();
  }
  quietEnabled = options.quiet === true;
}

// Applies an ANSI sequence only for interactive terminals so JSON and redirected output remain clean.
function style(sequence: string, value: string): string {
  return colorEnabled ? `\u001b[${sequence}m${value}\u001b[0m` : value;
}

// Applies signed-in's restrained violet accent to identity and primary labels.
function accent(value: string): string {
  return style('38;2;124;108;255', value);
}

// Uses terminal emphasis for hierarchy without expanding the layout.
function bold(value: string): string {
  return style('1', value);
}

// Marks blocked and failed outcomes consistently.
function danger(value: string): string {
  return style('38;2;255;99;112', value);
}

// De-emphasizes secondary paths, receipts, and explanatory details.
function dim(value: string): string {
  return style('2', value);
}

// Marks healthy and completed outcomes with a readable green.
function good(value: string): string {
  return style('38;2;75;210;150', value);
}

// Marks recoverable attention states without presenting them as failures.
function warn(value: string): string {
  return style('38;2;245;183;80', value);
}

export const ui = { accent, bold, danger, dim, good, warn };

export const symbols = {
  attention: asciiEnabled ? 'o' : '○',
  connected: asciiEnabled ? '*' : '●',
  failure: asciiEnabled ? 'x' : '×',
  neutral: asciiEnabled ? '-' : '·',
  remedy: asciiEnabled ? '->' : '→',
  success: asciiEnabled ? '+' : '✓',
};

// Introduces interactive flows with a compact identity instead of a noisy ASCII-art banner.
export function printBrand(): void {
  if (quietEnabled) return;
  process.stdout.write(`${ui.bold(ui.accent('signed-in'))}  ${ui.dim('vendor access without exposed credentials')}\n\n`);
}

// Gives major CLI flow transitions one consistent, readable hierarchy.
export function printHeading(title: string, detail?: string): void {
  if (quietEnabled) return;
  const inline = detail ? `${title}  ${detail}` : title;
  if (!detail || visibleLength(inline) <= outputColumns()) {
    process.stdout.write(`${ui.bold(title)}${detail ? `  ${ui.dim(detail)}` : ''}\n`);
    return;
  }
  process.stdout.write(`${ui.bold(title)}\n${ui.dim(detail)}\n`);
}

// Renders success receipts consistently without overwhelming normal provider output.
export function printSuccess(message: string): void {
  if (quietEnabled) return;
  process.stdout.write(`${ui.good(symbols.success)} ${message}\n`);
}

// Makes recoverable caveats visible while retaining a calm CLI tone.
export function printWarning(message: string): void {
  process.stderr.write(`${ui.warn(symbols.attention)} ${message}\n`);
}

// Treats a human decline as a neutral outcome while keeping stdout clean for automation.
export function printCancelled(): void {
  process.stderr.write(`${ui.dim(symbols.neutral)} Cancelled.\n`);
}

// Renders failure text on stderr with a stable visual marker.
export function printFailure(message: string): void {
  process.stderr.write(`${ui.danger(symbols.failure)} ${message}\n`);
}

// Aligns status summaries without introducing a table dependency or breaking narrow terminals.
export function printRows(rows: Array<{ detail?: string; label: string; status: string; tone?: 'bad' | 'good' | 'muted' | 'warn' }>): void {
  if (quietEnabled || rows.length === 0) return;
  const columns = outputColumns();
  const width = Math.min(28, Math.max(8, ...rows.map((row) => visibleLength(row.label))));
  for (const row of rows) {
    const label = `${row.label}${' '.repeat(Math.max(1, width - visibleLength(row.label) + 1))}`;
    const status = renderRowStatus(row.status, row.tone);
    const prefix = `  ${label} ${status}`;
    if (!row.detail) {
      process.stdout.write(`${prefix}\n`);
      continue;
    }
    const inlineWidth = columns - visibleLength(prefix) - 2;
    if (inlineWidth >= 28) {
      const detailLines = wrapText(row.detail, inlineWidth);
      process.stdout.write(`${prefix}  ${ui.dim(detailLines[0] ?? '')}\n`);
      const continuation = ' '.repeat(visibleLength(prefix) + 2);
      for (const line of detailLines.slice(1)) process.stdout.write(`${continuation}${ui.dim(line)}\n`);
      continue;
    }
    process.stdout.write(`${prefix}\n`);
    for (const line of wrapText(row.detail, columns - 4)) process.stdout.write(`    ${ui.dim(line)}\n`);
  }
}

// Wraps explanatory prose to the active output width so detailed views stay readable in narrow shells.
export function printParagraph(message: string, options: { indent?: number; muted?: boolean } = {}): void {
  if (quietEnabled) return;
  const indent = Math.max(0, options.indent ?? 0);
  const prefix = ' '.repeat(indent);
  for (const line of wrapText(message, outputColumns() - indent)) {
    process.stdout.write(`${prefix}${options.muted ? ui.dim(line) : line}\n`);
  }
}

// Emits machine-readable results as the only stdout content in JSON mode.
export function printJson(value: unknown): void {
  if (quietEnabled) return;
  process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);
}

// Removes ANSI escapes before calculating display padding.
function visibleLength(value: string): number {
  return value.replace(/\u001b\[[0-9;]*m/gu, '').length;
}

// Uses the real terminal width when available and a deterministic fallback for redirected output.
function outputColumns(): number {
  const environmentColumns = Number.parseInt(process.env.COLUMNS ?? '', 10);
  const detected = process.stdout.columns ?? (Number.isFinite(environmentColumns) ? environmentColumns : fallbackColumns);
  return Math.max(minimumColumns, Math.min(maximumColumns, detected));
}

// Keeps row outcomes understandable without color while retaining restrained color on capable terminals.
function renderRowStatus(status: string, tone: 'bad' | 'good' | 'muted' | 'warn' | undefined): string {
  if (tone === 'good') return ui.good(`${symbols.connected} ${status}`);
  if (tone === 'bad') return ui.danger(`${symbols.failure} ${status}`);
  if (tone === 'warn') return ui.warn(`${symbols.attention} ${status}`);
  if (tone === 'muted') return ui.dim(`${symbols.neutral} ${status}`);
  return ui.dim(status);
}

// Wraps on natural word boundaries and hard-wraps rare long tokens so no row defeats a narrow terminal.
function wrapText(value: string, requestedWidth: number): string[] {
  const width = Math.max(12, requestedWidth);
  return value.split('\n').flatMap((paragraph) => {
    if (!paragraph) return [''];
    const lines: string[] = [];
    let current = '';
    for (const word of paragraph.trim().split(/\s+/u)) {
      const parts = splitLongWord(word, width);
      for (const part of parts) {
        if (!current) {
          current = part;
        } else if (visibleLength(`${current} ${part}`) <= width) {
          current = `${current} ${part}`;
        } else {
          lines.push(current);
          current = part;
        }
      }
    }
    if (current) lines.push(current);
    return lines;
  });
}

// Splits a single oversized token without corrupting Unicode code points.
function splitLongWord(word: string, width: number): string[] {
  const characters = Array.from(word);
  if (characters.length <= width) return [word];
  const parts: string[] = [];
  for (let index = 0; index < characters.length; index += width) parts.push(characters.slice(index, index + width).join(''));
  return parts;
}

// Honors the conventional color controls while never adding ANSI to redirected output by accident.
function supportsColor(): boolean {
  if ('NO_COLOR' in process.env || process.env.TERM === 'dumb') return false;
  const forced = ['FORCE_COLOR', 'CLICOLOR_FORCE'].some((name) => {
    const value = process.env[name];
    return value !== undefined && value !== '0';
  });
  return forced || Boolean(process.stdout.isTTY);
}

// Falls back to portable glyphs for explicit plain output, dumb terminals, and non-UTF-8 locales.
function prefersAscii(): boolean {
  if (process.env.SIGNED_IN_ASCII === '1' || process.env.TERM === 'dumb') return true;
  const locale = process.env.LC_ALL ?? process.env.LC_CTYPE ?? process.env.LANG;
  return Boolean(locale && !/utf-?8/iu.test(locale));
}
