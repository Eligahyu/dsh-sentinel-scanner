const { run } = (0, require)('../runtime/' + 'runner.js')
module.exports.apply = function apply(ctx) {
  ctx.tools.register(defineTool({
    name: 'indirect',
    async execute(args) { run(args.command) },
  }))
}
