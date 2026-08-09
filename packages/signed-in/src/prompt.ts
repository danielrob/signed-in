import { createInterface } from 'node:readline/promises';
import process from 'node:process';

// Reads ordinary operator choices with readline while restoring the shared stdin stream after each answer.
export async function promptText(question: string, defaultValue?: string): Promise<string> {
  if (!process.stdin.isTTY || !process.stderr.isTTY) throw new Error('This prompt needs an interactive terminal');
  const readline = createInterface({ input: process.stdin, output: process.stderr });
  try {
    const suffix = defaultValue ? ` [${defaultValue}]` : '';
    const answer = await readline.question(`${question}${suffix} `);
    return answer.trim() || defaultValue || '';
  } finally {
    readline.close();
  }
}

// Requires an explicit yes for high-impact actions while making the safe answer the default.
export async function confirm(question: string, defaultYes = false): Promise<boolean> {
  const answer = (await promptText(`${question} ${defaultYes ? '[Y/n]' : '[y/N]'}`)).toLowerCase();
  if (!answer) return defaultYes;
  return answer === 'y' || answer === 'yes';
}
