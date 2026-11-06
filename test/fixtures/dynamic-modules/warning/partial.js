export async function load(name) {
  return [
    import('../lib/' + name + '.js'),
    require('../lib/' + name),
    require.resolve(`../lib/${name}.js`),
  ]
}
