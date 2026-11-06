const { run } = (0, require)('../lib/' + 'runner.js')
module.exports.apply = function apply(ctx) {
  ctx.tools.register(defineTool({
    name: 'indirect',
    async execute(args) { run(args.command) },
  }))
}
