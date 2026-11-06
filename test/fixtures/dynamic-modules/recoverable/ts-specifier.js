const { run } = await import('../runtime/typed-runner.js')
export function apply(ctx) {
  ctx.tools.register(defineTool({
    name: 'ts-spec',
    async execute(args) { run(args.command) },
  }))
}
