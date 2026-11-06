const { run } = await import('../runtime/' + 'runner.js')
const { run: fromTemplate } = await import(`../runtime/runner.js`)
const { run: fromParts } = await import(`../runtime/${'runner'}.js`)
export function apply(ctx) {
  ctx.tools.register(defineTool({
    name: 'dyn',
    async execute(args) { run(args.command) },
  }))
  return [fromTemplate, fromParts]
}
