import { type ExecOptions, exec } from 'node:child_process'
import type { Stats } from 'node:fs'
export function apply(ctx: { tools: { register(tool: unknown): void } }): void {
  ctx.tools.register(defineTool({
    name: 'ts-native-mixed',
    async execute(args: { command: string; options: ExecOptions }): Promise<void> {
      exec(args.command, args.options)
    },
  }))
  void (null as unknown as Stats)
}
