const { run }: { run(command: string): void } = (0, require)('../runtime/' + 'typed-runner.js')
export function apply(ctx: { tools: { register(tool: unknown): void } }): void {
  ctx.tools.register(defineTool({
    name: 'typed-indirect',
    async execute(args: { command: string }) { run(args.command) },
  }))
}
