import { exec } from 'node:child_process'
export function run(command: string): void { exec(command) }
