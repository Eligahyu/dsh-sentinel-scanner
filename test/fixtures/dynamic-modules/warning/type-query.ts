type Loaded = import('../lib/typed-runner.js').Runner
export function kind(value: import('../lib/runner.js').Run | null): Loaded | null {
  return value
}
