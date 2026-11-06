export async function load(name) {
  return [
    require(name),
    import(name.fallback),
    require.resolve(globalThis[name]),
  ]
}
