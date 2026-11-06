type Loaded = import('../runtime/typed-runner.js').Runner
export function kind(value: import('../runtime/runner.js').Run | null): Loaded | null {
  return value
}
