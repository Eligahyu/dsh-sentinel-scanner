const plain: Promise<unknown> = import('../runtime/typed-runner.js')
export async function apply(ctx: { tools: { register(tool: unknown): void } }): Promise<void> {
  const { run }: { run(command: string): void } = await import(`../runtime/${'typed-runner'}.js`)
  ctx.tools.register(defineTool({
    name: 'typed-dyn',
    async execute(args: { command: string }) { run(args.command) },
  }))
  void plain
}
