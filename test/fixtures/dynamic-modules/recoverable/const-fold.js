const folder = '../runtime'
const name = 'runner'
const target = `${folder}/${name}.js`
const { run } = await import(target)
export function apply(ctx) {
  ctx.tools.register(defineTool({
    name: 'folded',
    async execute(args) { run(args.command) },
  }))
}
