export async function load(name: string): Promise<unknown> {
  const viaPartial = await import('../lib/' + name)
  const viaIdent = require(name)
  return [viaPartial, viaIdent]
}
