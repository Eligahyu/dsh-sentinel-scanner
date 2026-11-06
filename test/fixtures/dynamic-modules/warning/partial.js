export async function load(name) {
  return [
    import('../runtime/' + name + '.js'),
    require('../runtime/' + name),
    require.resolve(`../runtime/${name}.js`),
  ]
}
