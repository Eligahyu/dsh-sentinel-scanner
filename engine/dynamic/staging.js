import fs from 'node:fs'
import { isAbsolute, join, normalize, relative, resolve, sep } from 'node:path'
import { CASE_INSENSITIVE, isInsideRoot, resolveLexicallyInside } from '../path-safety.js'
import { createStagingCapability, disposeStagingCapability } from './container-policy.js'

export const STAGING_SNAPSHOT_LIMITS = Object.freeze({
  maxFiles: 1024,
  maxTotalBytes: 32 * 1024 * 1024,
  maxFileBytes: 8 * 1024 * 1024,
  maxPathLength: 240,
})

const COPY_BUFFER_BYTES = 64 * 1024
const MAX_ENTRY_MULTIPLIER = 4
const OPEN_NOFOLLOW = fs.constants.O_NOFOLLOW ?? 0

class StagingSnapshotError extends Error {
  constructor(code) {
    super(code)
    this.code = code
    this.name = 'StagingSnapshotError'
  }
}

function stagingError(code) {
  return new StagingSnapshotError(code)
}

function samePath(left, right) {
  const a = normalize(resolve(left))
  const b = normalize(resolve(right))
  return CASE_INSENSITIVE ? a.toLowerCase() === b.toLowerCase() : a === b
}

function sameObject(left, right) {
  return left.dev === right.dev && left.ino === right.ino
}

function closeQuietly(fd) {
  if (fd === undefined) return
  try {
    fs.closeSync(fd)
  } catch {
    // A failed close cannot safely override the fixed public error contract.
  }
}

function lstat(path) {
  try {
    return fs.lstatSync(path)
  } catch {
    throw stagingError('staging-copy-failed')
  }
}

function lstatIfPresent(path) {
  try {
    return fs.lstatSync(path)
  } catch (error) {
    if (error?.code === 'ENOENT') return null
    throw stagingError('staging-copy-failed')
  }
}

function assertSafeName(name) {
  if (typeof name !== 'string' || name.length === 0 || name === '.' || name === '..'
    || name.includes('/') || name.includes('\\') || name.includes('\0')) {
    throw stagingError('staging-containment-failed')
  }
}

function toManifestPath(root, path) {
  const value = relative(root, path)
  if (value === '' || value === '..' || value.startsWith(`..${sep}`) || isAbsolute(value)) {
    throw stagingError('staging-containment-failed')
  }
  return value.split(sep).join('/')
}

function checkedChild(root, parent, name) {
  assertSafeName(name)
  try {
    return resolveLexicallyInside(root, join(parent, name))
  } catch {
    throw stagingError('staging-containment-failed')
  }
}

function openVerifiedDirectory(path) {
  const before = lstat(path)
  if (before.isSymbolicLink()) throw stagingError('staging-symlink')
  if (!before.isDirectory()) throw stagingError('staging-special-file')

  let fd
  try {
    fd = fs.openSync(path, fs.constants.O_RDONLY | OPEN_NOFOLLOW)
    const opened = fs.fstatSync(fd)
    const after = lstat(path)
    if (after.isSymbolicLink() || !after.isDirectory() || !opened.isDirectory()
      || !sameObject(before, opened) || !sameObject(before, after)) {
      throw stagingError('staging-containment-failed')
    }
    return { path, fd, stat: opened }
  } catch (error) {
    closeQuietly(fd)
    if (error instanceof StagingSnapshotError) throw error
    throw stagingError('staging-copy-failed')
  }
}

function openVerifiedFile(path) {
  const before = lstat(path)
  if (before.isSymbolicLink()) throw stagingError('staging-symlink')
  if (!before.isFile()) throw stagingError('staging-special-file')
  if (before.nlink !== 1) throw stagingError('staging-hardlink')

  let fd
  try {
    fd = fs.openSync(path, fs.constants.O_RDONLY | OPEN_NOFOLLOW)
    const opened = fs.fstatSync(fd)
    const after = lstat(path)
    if (after.isSymbolicLink() || !after.isFile() || !opened.isFile()
      || before.nlink !== 1 || after.nlink !== 1 || opened.nlink !== 1
      || !sameObject(before, opened) || !sameObject(before, after)) {
      throw stagingError('staging-containment-failed')
    }
    return { path, fd, stat: opened }
  } catch (error) {
    closeQuietly(fd)
    if (error instanceof StagingSnapshotError) throw error
    throw stagingError('staging-copy-failed')
  }
}

function assertDirectoryCurrent(directory) {
  const current = lstat(directory.path)
  let opened
  try {
    opened = fs.fstatSync(directory.fd)
  } catch {
    throw stagingError('staging-containment-failed')
  }
  if (current.isSymbolicLink() || !current.isDirectory() || !opened.isDirectory()
    || !sameObject(directory.stat, current) || !sameObject(directory.stat, opened)) {
    throw stagingError('staging-containment-failed')
  }
}

function boundedOption(options, key, maximum) {
  if (!Object.hasOwn(options, key)) return maximum
  const value = options[key]
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1) {
    throw stagingError('invalid-staging-options')
  }
  return Math.min(value, maximum)
}

function normalizeOptions(input) {
  if (input === undefined) input = {}
  if (input === null || typeof input !== 'object' || Array.isArray(input)) {
    throw stagingError('invalid-staging-options')
  }
  try {
    const limits = {
      maxFiles: boundedOption(input, 'maxFiles', STAGING_SNAPSHOT_LIMITS.maxFiles),
      maxTotalBytes: boundedOption(input, 'maxTotalBytes', STAGING_SNAPSHOT_LIMITS.maxTotalBytes),
      maxFileBytes: boundedOption(input, 'maxFileBytes', STAGING_SNAPSHOT_LIMITS.maxFileBytes),
      maxPathLength: boundedOption(input, 'maxPathLength', STAGING_SNAPSHOT_LIMITS.maxPathLength),
    }
    return Object.freeze({ ...limits, maxEntries: limits.maxFiles * MAX_ENTRY_MULTIPLIER })
  } catch (error) {
    if (error instanceof StagingSnapshotError) throw error
    throw stagingError('invalid-staging-options')
  }
}

function prepareSource(sourceRoot) {
  if (typeof sourceRoot !== 'string' || sourceRoot.length === 0 || sourceRoot.includes('\0')) {
    throw stagingError('invalid-staging-source')
  }
  const path = resolve(sourceRoot)
  const directory = openVerifiedDirectory(path)
  try {
    const real = fs.realpathSync(path)
    if (!samePath(path, real)) throw stagingError('staging-source-symlink')
    return { path, real, directory }
  } catch (error) {
    closeQuietly(directory.fd)
    if (error instanceof StagingSnapshotError) throw error
    throw stagingError('invalid-staging-source')
  }
}

function prepareDestination(capability) {
  let root
  let snapshot
  try {
    root = openVerifiedDirectory(capability.root)
    snapshot = openVerifiedDirectory(capability.snapshot)
    const rootReal = fs.realpathSync(capability.root)
    const snapshotReal = fs.realpathSync(capability.snapshot)
    if (samePath(rootReal, snapshotReal) || !isInsideRoot(rootReal, snapshotReal)) {
      throw stagingError('staging-containment-failed')
    }
    if (!samePath(capability.root, rootReal) || !samePath(capability.snapshot, snapshotReal)) {
      throw stagingError('staging-containment-failed')
    }
    closeQuietly(root.fd)
    return { path: capability.snapshot, real: snapshotReal, directory: snapshot }
  } catch (error) {
    if (root) closeQuietly(root.fd)
    if (snapshot) closeQuietly(snapshot.fd)
    if (error instanceof StagingSnapshotError) throw error
    throw stagingError('staging-containment-failed')
  }
}

function createDestinationDirectory(snapshot, relativePath) {
  let path
  try {
    path = resolveLexicallyInside(snapshot.path, relativePath)
  } catch {
    throw stagingError('staging-containment-failed')
  }
  assertDirectoryCurrent(snapshot.directory)
  try {
    fs.mkdirSync(path, { mode: 0o700 })
  } catch (error) {
    if (error?.code !== 'EEXIST') throw stagingError('staging-copy-failed')
  }
  return openVerifiedDirectory(path)
}

function isNestedWorktree(source, directory) {
  const marker = checkedChild(source.path, directory.path, '.git')
  const stat = lstatIfPresent(marker)
  assertDirectoryCurrent(directory)
  return stat !== null && !stat.isDirectory()
}

function copyDescriptor(source, destinationPath, expectedSize) {
  let destinationFd
  try {
    destinationFd = fs.openSync(
      destinationPath,
      fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL,
      0o600,
    )
    const buffer = Buffer.allocUnsafe(COPY_BUFFER_BYTES)
    let remaining = expectedSize
    while (remaining > 0) {
      const read = fs.readSync(source.fd, buffer, 0, Math.min(buffer.length, remaining), null)
      if (read === 0) throw stagingError('staging-source-changed')
      let offset = 0
      while (offset < read) {
        const written = fs.writeSync(destinationFd, buffer, offset, read - offset, null)
        if (written === 0) throw stagingError('staging-copy-failed')
        offset += written
      }
      remaining -= read
    }
    const finalStat = fs.fstatSync(source.fd)
    if (!finalStat.isFile() || finalStat.nlink !== 1 || finalStat.size !== expectedSize
      || !sameObject(source.stat, finalStat)) {
      throw stagingError('staging-source-changed')
    }
    fs.fchmodSync(destinationFd, source.stat.mode & 0o777)
  } catch (error) {
    if (error instanceof StagingSnapshotError) throw error
    throw stagingError('staging-copy-failed')
  } finally {
    closeQuietly(destinationFd)
  }
}

function copyFile(sourceRoot, snapshot, sourceFile, destinationDirectory, manifestPath, state) {
  const size = sourceFile.stat.size
  if (!Number.isSafeInteger(size) || size < 0) throw stagingError('staging-special-file')
  if (size > state.limits.maxFileBytes) throw stagingError('staging-file-bytes-limit')
  if (state.fileCount >= state.limits.maxFiles) throw stagingError('staging-file-count-limit')
  if (state.totalBytes + size > state.limits.maxTotalBytes) throw stagingError('staging-total-bytes-limit')
  assertDirectoryCurrent(sourceRoot.directory)
  assertDirectoryCurrent(destinationDirectory)

  let destinationPath
  try {
    destinationPath = resolveLexicallyInside(snapshot.path, manifestPath.split('/').join(sep))
  } catch {
    throw stagingError('staging-containment-failed')
  }
  copyDescriptor(sourceFile, destinationPath, size)
  state.fileCount += 1
  state.totalBytes += size
  state.files.push(Object.freeze({
    path: manifestPath,
    bytes: size,
    mode: sourceFile.stat.mode & 0o777,
  }))
}

function walkDirectory(source, snapshot, sourceDirectory, destinationDirectory, relativePath, state) {
  assertDirectoryCurrent(source.directory)
  assertDirectoryCurrent(sourceDirectory)
  assertDirectoryCurrent(destinationDirectory)
  let entries
  try {
    entries = fs.readdirSync(sourceDirectory.path, { withFileTypes: true })
  } catch {
    throw stagingError('staging-copy-failed')
  }
  assertDirectoryCurrent(source.directory)
  assertDirectoryCurrent(sourceDirectory)
  entries.sort((left, right) => String(left.name).localeCompare(String(right.name)))

  for (const entry of entries) {
    const name = entry.name
    assertSafeName(name)
    assertDirectoryCurrent(source.directory)
    assertDirectoryCurrent(sourceDirectory)
    if (name === '.git') {
      state.excluded.git += 1
      continue
    }
    state.entryCount += 1
    if (state.entryCount > state.limits.maxEntries) throw stagingError('staging-file-count-limit')

    const sourcePath = checkedChild(source.path, sourceDirectory.path, name)
    const manifestPath = toManifestPath(source.path, sourcePath)
    if (manifestPath.length > state.limits.maxPathLength) throw stagingError('staging-path-length-limit')
    const stat = lstat(sourcePath)
    if (stat.isSymbolicLink()) throw stagingError('staging-symlink')

    if (stat.isDirectory()) {
      const childSource = openVerifiedDirectory(sourcePath)
      let childDestination
      try {
        if (isNestedWorktree(source, childSource)) {
          state.excluded.worktrees += 1
          continue
        }
        childDestination = createDestinationDirectory(snapshot, manifestPath.split('/').join(sep))
        walkDirectory(source, snapshot, childSource, childDestination, manifestPath, state)
      } finally {
        if (childDestination) closeQuietly(childDestination.fd)
        closeQuietly(childSource.fd)
      }
      continue
    }

    const sourceFile = openVerifiedFile(sourcePath)
    try {
      copyFile(source, snapshot, sourceFile, destinationDirectory, manifestPath, state)
    } finally {
      closeQuietly(sourceFile.fd)
    }
  }
}

function publicError(error) {
  if (error instanceof StagingSnapshotError) return error
  return stagingError('staging-copy-failed')
}

/**
 * Copy an untrusted scan root into a factory-owned, container-mountable snapshot.
 * The only mount authority returned is Task 1's opaque staging capability.
 */
export function createStagingSnapshot(sourceRoot, options) {
  let capability
  try {
    capability = createStagingCapability()
  } catch {
    throw stagingError('staging-capability-factory-failed')
  }

  let cleaned = false
  const cleanup = () => {
    if (cleaned) return
    try {
      disposeStagingCapability(capability)
      cleaned = true
    } catch {
      throw stagingError('staging-cleanup-failed')
    }
  }

  let source
  let snapshot
  try {
    const limits = normalizeOptions(options)
    source = prepareSource(sourceRoot)
    snapshot = prepareDestination(capability)
    if (isInsideRoot(source.real, snapshot.real) || isInsideRoot(snapshot.real, source.real)) {
      throw stagingError('staging-source-overlaps-snapshot')
    }
    const state = {
      limits,
      entryCount: 0,
      fileCount: 0,
      totalBytes: 0,
      files: [],
      excluded: { git: 0, worktrees: 0 },
    }
    walkDirectory(source, snapshot, source.directory, snapshot.directory, '', state)
    const manifest = Object.freeze({
      files: Object.freeze(state.files),
      fileCount: state.fileCount,
      totalBytes: state.totalBytes,
      excluded: Object.freeze({ ...state.excluded }),
    })
    return Object.freeze({
      capability,
      root: capability.root,
      snapshot: capability.snapshot,
      manifest,
      cleanup,
    })
  } catch (error) {
    try {
      cleanup()
    } catch {
      // The operation's error remains safe and deterministic even if rollback is unavailable.
    }
    throw publicError(error)
  } finally {
    if (source) closeQuietly(source.directory.fd)
    if (snapshot) closeQuietly(snapshot.directory.fd)
  }
}
