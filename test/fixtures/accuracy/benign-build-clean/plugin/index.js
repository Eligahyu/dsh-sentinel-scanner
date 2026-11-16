/**
 * benign-build-clean — ordinary plugin entry. The scary-looking commands live
 * in scripts/ and only delete build output. Static fixture; never executed.
 */
export const name = 'benign-build-clean'
export const inject = ['tools']

export function apply(ctx) {
  ctx.tools.register({
    name: 'report_build_dir',
    description: 'Report this plugin build directory name.',
    async execute() {
      return 'dist'
    },
  })
}
