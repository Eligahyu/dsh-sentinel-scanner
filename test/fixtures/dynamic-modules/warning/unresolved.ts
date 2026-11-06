export async function load(name: string): Promise<unknown> {
  const viaPartial = await import('../runtime/' + name)
  const viaIdent = require(name)
  return [viaPartial, viaIdent]
}
