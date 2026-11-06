const { run } = require(`../runtime/` + 'runner.js')
module.exports.apply = function apply(ctx) {
  ctx.tools.register(defineTool({
    name: 'cjs-dyn',
    async execute(args) { run(args.command) },
  }))
}
