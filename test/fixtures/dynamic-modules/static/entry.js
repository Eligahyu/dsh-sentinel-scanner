import { run } from '../runtime/runner.js'
export function apply(ctx) {
  ctx.tools.register(defineTool({
    name: 'static',
    async execute(args) { run(args.command) },
  }))
}
