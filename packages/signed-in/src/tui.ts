import {
  cancel,
  confirm,
  intro,
  isCancel,
  log,
  multiselect,
  note,
  outro,
  password,
  select,
  spinner,
  text,
} from '@clack/prompts';
import process from 'node:process';

import { symbols } from './ui.js';

export interface TuiChoice<Value extends string> {
  disabled?: boolean;
  hint?: string;
  label: string;
  value: Value;
}

// Gives callers one stable cancellation type without coupling the CLI to Clack's symbol contract.
export class TuiCancelledError extends Error {
  constructor() {
    super('Aborted with Ctrl+C');
    this.name = 'TuiCancelledError';
  }
}

const terminal = { input: process.stdin, output: process.stderr };

interface TerminalKey {
  name?: string;
  sequence?: string;
}

// Finishes Clack's guide before handing cancellation back to the CLI exit contract.
function cancelTui(): never {
  cancel('Cancelled.', terminal);
  throw new TuiCancelledError();
}

// Keeps the guided experience on stderr so stdout remains safe for JSON and command output.
export function tuiIntro(title: string): void {
  intro(title, terminal);
}

// Closes the guide cleanly without adding a second, unrelated status surface.
export function tuiOutro(message: string): void {
  outro(message, terminal);
}

// Adds a quiet explanatory card only when a prompt benefits from a little context.
export function tuiNote(message: string, title?: string): void {
  note(message, title, terminal);
}

// Marks progress between selected services while retaining Clack's continuous guide rail.
export function tuiStep(message: string): void {
  log.step(message, terminal);
}

// Places compact keyboard help directly beside the control it explains.
export function tuiHint(message: string): void {
  log.info(message, terminal);
}

// Records a completed service inline so the human never has to infer whether sign-in worked.
export function tuiSuccess(message: string): void {
  log.success(message, terminal);
}

// Keeps a recoverable provider problem inside the guided flow instead of collapsing the whole run.
export function tuiWarning(message: string): void {
  log.warn(message, terminal);
}

// Treats a deliberate skip as neutral progress rather than success or a warning.
export function tuiSkipped(message: string): void {
  log.message(message, { symbol: symbols.neutral, ...terminal });
}

// Shows elapsed time for quiet subprocess work so a slow package install or provider probe never looks frozen.
export async function tuiTask<Value>(
  pending: string,
  success: string,
  failure: string,
  task: () => Promise<Value>,
): Promise<Value> {
  const progress = spinner({ indicator: 'timer', ...terminal });
  progress.start(pending);
  try {
    const result = await task();
    progress.stop(success);
    return result;
  } catch (error) {
    progress.error(failure);
    throw error;
  }
}

// Lets each workflow choose whether Enter advances a safe happy path or declines a protected mutation.
export async function tuiConfirm(message: string, active: string, inactive: string, initialValue = true): Promise<boolean> {
  const answer = await confirm({ active, inactive, initialValue, message, ...terminal });
  if (isCancel(answer)) return cancelTui();
  return answer;
}

// Presents every service as one checkbox list without exposing credential mechanics as taxonomy.
export async function tuiMultiselect<Value extends string>(
  message: string,
  options: TuiChoice<Value>[],
  initialValues: Value[] = [],
): Promise<Value[]> {
  let cursor = Math.max(options.findIndex((option) => !option.disabled), 0);
  const selected = new Set(initialValues);
  // Mirrors Clack's checkbox state just far enough to turn an empty Enter into selecting the focused row before submission.
  const trackCheckboxKey = (character: string | undefined, key: TerminalKey): void => {
    const input = character?.toLowerCase();
    const direction = checkboxCursorDirection(character, key);
    if (direction !== 0) cursor = moveCheckboxCursor(cursor, direction, options);
    const focused = options[cursor];
    if ((key.name === 'space' || character === ' ') && focused && !focused.disabled) {
      if (selected.has(focused.value)) selected.delete(focused.value);
      else selected.add(focused.value);
    } else if (input === 'a') {
      const enabled = options.filter((option) => !option.disabled).map((option) => option.value);
      if (enabled.every((value) => selected.has(value))) selected.clear();
      else for (const value of enabled) selected.add(value);
    } else if (input === 'i') {
      for (const option of options) {
        if (option.disabled) continue;
        if (selected.has(option.value)) selected.delete(option.value);
        else selected.add(option.value);
      }
    } else if (key.name === 'return' && selected.size === 0 && focused && !focused.disabled) {
      terminal.input.emit('keypress', ' ', { name: 'space', sequence: ' ' } satisfies TerminalKey);
    }
  };
  terminal.input.prependListener('keypress', trackCheckboxKey);
  let answer: Awaited<ReturnType<typeof multiselect<string>>>;
  try {
    answer = await multiselect<string>({ initialValues, maxItems: 12, message, options, required: false, ...terminal });
  } finally {
    terminal.input.removeListener('keypress', trackCheckboxKey);
  }
  if (isCancel(answer)) return cancelTui();
  return answer as Value[];
}

// Tracks every navigation spelling accepted by Clack so the fallback selection follows the visible cursor exactly.
function checkboxCursorDirection(character: string | undefined, key: TerminalKey): -1 | 0 | 1 {
  const input = character?.toLowerCase();
  if (key.name === 'up' || key.name === 'left' || input === 'k' || input === 'h') return -1;
  if (key.name === 'down' || key.name === 'right' || input === 'j' || input === 'l') return 1;
  return 0;
}

// Wraps across disabled rows with the same behavior as the underlying checkbox prompt.
function moveCheckboxCursor<Value extends string>(current: number, direction: -1 | 1, options: TuiChoice<Value>[]): number {
  if (options.length === 0 || options.every((option) => option.disabled)) return current;
  let next = current;
  do next = (next + direction + options.length) % options.length;
  while (options[next]?.disabled);
  return next;
}

// Reduces each service step to a small set of explicit actions with a sensible default.
export async function tuiSelect<Value extends string>(message: string, options: TuiChoice<Value>[], initialValue: Value): Promise<Value> {
  const answer = await select<string>({ initialValue, message, options, ...terminal });
  if (isCancel(answer)) return cancelTui();
  return answer as Value;
}

// Treats cancellation as a safe selected outcome after work has already been saved, such as Done on a batch summary.
export async function tuiSelectOrDefault<Value extends string>(
  message: string,
  options: TuiChoice<Value>[],
  initialValue: Value,
  cancelledValue: Value,
): Promise<Value> {
  const answer = await select<string>({ initialValue, message, options, ...terminal });
  return isCancel(answer) ? cancelledValue : answer as Value;
}

// Captures ordinary credential metadata within the same guided visual language.
export async function tuiText(message: string, defaultValue?: string): Promise<string> {
  const answer = await text({
    ...(defaultValue ? { initialValue: defaultValue, placeholder: defaultValue } : {}),
    message,
    validate: (value) => value?.trim() ? undefined : 'This field is required.',
    ...terminal,
  });
  if (isCancel(answer)) return cancelTui();
  return answer.trim();
}

// Keeps secret validation inside the active TUI step without echoing or leaking entered material.
export async function tuiPassword(
  message: string,
  validate: (value: string | undefined) => string | undefined = (value) => value ? undefined : 'This field is required.',
): Promise<string> {
  const answer = await password({
    message,
    validate,
    ...terminal,
  });
  if (isCancel(answer)) return cancelTui();
  return answer;
}
