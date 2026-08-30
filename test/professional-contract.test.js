import assert from 'node:assert/strict'
import { test } from 'node:test'
import { buildReport } from '../engine/report.js'

function minimalParts(overrides = {}) {
  return {
    kind: 'path',
    path: '/tmp/plugin',
    name: 'plugin',
    findings: [],
    findingsTotal: 0,
    filesAnalyzed: 1,
    filesDiscovered: 1,
    scanComplete: true,
    scanCoverage: {},
    manifest: {},
    scanMs: 1,
    ...overrides,
  }
}

test('professional report exposes stable analysis-layer defaults', () => {
  const report = buildReport(minimalParts())

  assert.equal(report.schemaVersion, 2)
  assert.ok(report.analysisLayers)
  assert.deepEqual(Object.keys(report.analysisLayers).sort(), [
    'capabilityGraph',
    'dependencyGraph',
    'dynamic',
    'moduleGraph',
    'provenance',
    'sbom',
  ])
  assert.equal(report.analysisLayers.moduleGraph.complete, true)
  assert.equal(report.analysisLayers.dependencyGraph.complete, true)
  assert.deepEqual(report.analysisLayers.dependencyGraph.buildRequirements, [])
  assert.equal(report.analysisLayers.capabilityGraph.complete, true)
  assert.equal(report.analysisLayers.sbom.status, 'not-requested')
  assert.equal(report.analysisLayers.provenance.status, 'not-requested')
  assert.equal(typeof report.analysisLayers.moduleGraph.complete, 'boolean')
})

test('dynamic report contract exposes independent defaults', () => {
  const report = buildReport(minimalParts())

  assert.deepEqual(report.analysisLayers.dynamic, {
    status: 'not-requested',
    requested: false,
    complete: false,
    backend: null,
    profile: null,
    stages: [],
    networkAttempts: [],
    dnsQueries: [],
    processes: [],
    fileEvents: [],
    canaryEvents: [],
    policyViolations: [],
    limitations: [],
    failures: [],
    evidenceDigest: null,
  })
  assert.equal(report.summary.dynamicRequested, false)
  assert.equal(report.summary.dynamicComplete, false)
  assert.equal(report.summary.dynamicStatus, 'not-requested')
  assert.equal(report.summary.scanComplete, true)
})

test('dynamic report contract normalizes malformed values to safe defaults', () => {
  const report = buildReport(minimalParts({
    analysisLayers: {
      dynamic: {
        status: { arbitrary: true },
        requested: 'yes',
        complete: { arbitrary: true },
        backend: { arbitrary: true },
        profile: ['arbitrary'],
        stages: { arbitrary: true },
        networkAttempts: 'arbitrary',
        dnsQueries: null,
        processes: { arbitrary: true },
        fileEvents: 'arbitrary',
        canaryEvents: null,
        policyViolations: { arbitrary: true },
        limitations: 'arbitrary',
        failures: { arbitrary: true },
        evidenceDigest: ['arbitrary'],
        unknown: 'discard me',
      },
    },
  }))

  assert.deepEqual(report.analysisLayers.dynamic, {
    status: 'not-requested',
    requested: false,
    complete: false,
    backend: null,
    profile: null,
    stages: [],
    networkAttempts: [],
    dnsQueries: [],
    processes: [],
    fileEvents: [],
    canaryEvents: [],
    policyViolations: [],
    limitations: [],
    failures: [],
    evidenceDigest: null,
  })
  assert.equal(report.summary.scanComplete, true)
})

test('failed analysis layer makes the report incomplete and preserves reasons', () => {
  const report = buildReport(minimalParts({
    scanComplete: true,
    analysisLayers: {
      moduleGraph: {
        complete: false,
        failures: [{ path: 'plugin/index.js', reason: 'parse-error' }],
      },
    },
  }))

  assert.ok(report.analysisLayers)
  assert.equal(report.analysisLayers.moduleGraph.complete, false)
  assert.equal(report.summary.scanComplete, false)
  assert.match(report.summary.incompleteReasons.join(','), /module-graph/)
  assert.equal(typeof report.summary.incompleteReasons, 'object')
})

test('failed dependency graph is preserved as an auxiliary warning without marking the scan incomplete', () => {
  const report = buildReport(minimalParts({
    analysisLayers: {
      dependencyGraph: {
        complete: false,
        failures: [{ reason: 'unsupported-lockfile' }],
      },
    },
  }))

  assert.equal(report.summary.scanComplete, true)
  assert.deepEqual(report.summary.incompleteReasons, [])
  assert.equal(report.analysisLayers.dependencyGraph.complete, false)
  assert.deepEqual(report.analysisLayers.dependencyGraph.failures, [{ reason: 'unsupported-lockfile' }])
})

test('analysis evidence is retained on findings and validated', () => {
  const report = buildReport(minimalParts({
    findings: [{
      ruleId: 'SEN-AGENT-001',
      severity: 'critical',
      category: 'agent',
      confidence: 'high',
      message: 'cross-file flow',
      file: 'plugin/index.js',
      line: 5,
      snippet: 'run(args.command)',
      recommendation: 'review',
      crossFile: true,
      modulePath: ['plugin/index.js', 'lib/runner.js'],
      attackChainId: 'chain-1',
    }],
    findingsTotal: 1,
    analysisLayers: {
      moduleGraph: {
        complete: true,
        nodes: 2,
        edges: 1,
        failures: [],
      },
    },
  }))

  assert.equal(report.findings[0].crossFile, true)
  assert.deepEqual(report.findings[0].modulePath, ['plugin/index.js', 'lib/runner.js'])
  assert.equal(report.findings[0].attackChainId, 'chain-1')
  assert.equal(typeof report.analysisLayers.moduleGraph.edges, 'number')
})
