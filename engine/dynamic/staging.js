import fs from 'node:fs'
import { isAbsolute, resolve, sep } from 'node:path'
import { isInsideRoot } from '../path-safety.js'
import { createStagingCapability, disposeStagingCapability } from './container-policy.js'

export const STAGING_SNAPSHOT_LIMITS = Object.freeze({
  maxFiles: 1024,
  maxEntries: 4096,
  maxTotalBytes: 32 * 1024 * 1024,
  maxFileBytes: 8 * 1024 * 1024,
  maxPathLength: 240,
})

const COPY_BUFFER_BYTES = 64 * 1024
const O_DIRECTORY = fs.constants.O_DIRECTORY
const O_NOFOLLOW = fs.constants.O_NOFOLLOW

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

function sameObject(left, right) {
  return left.dev === right.dev && left.ino === right.ino
}

function closeQuietly(fd) {
  if (fd === undefined) return
  try {
    fs.closeSync(fd)
  } catch {
    // Public errors must stay bounded even if an operating-system close fails.
  }
}

function closeDirectoryQuietly(directory) {
  if (directory) closeQuietly(directory.fd)
}

function assertDescriptorTraversalAvailable() {
  if (process.platform !== 'linux' || !Number.isInteger(O_DIRECTORY) || !Number.isInteger(O_NOFOLLOW)) {
    throw stagingError('staging-descriptor-unavailable')
  }
  let procFd
  try {
    procFd = fs.openSync('/proc/self/fd', fs.constants.O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
    if (!fs.fstatSync(procFd).isDirectory()) throw stagingError('staging-descriptor-unavailable')
  } catch (error) {
    if (error instanceof StagingSnapshotError) throw error
    throw stagingError('staging-descriptor-unavailable')
  } finally {
    closeQuietly(procFd)
  }
}

function assertSafeName(name) {
  if (typeof name !== 'string' || name.length === 0 || name === '.' || name === '..'
    || name.includes('/') || name.includes('\\') || name.includes('\0')) {
    throw stagingError('staging-containment-failed')
  }
}

function descriptorDirectoryPath(fd) {
  return `/proc/self/fd/${fd}`
}

function descriptorChildPath(directory, name) {
  assertSafeName(name)
  return `${descriptorDirectoryPath(directory.fd)}/${name}`
}

function lstatPath(path, optional = false) {
  try {
    return fs.lstatSync(path)
  } catch (error) {
    if (optional && error?.code === 'ENOENT') return null
    throw stagingError('staging-copy-failed')
  }
}

function lstatAt(directory, name, optional = false) {
  return lstatPath(descriptorChildPath(directory, name), optional)
}

function openVerifiedDirectoryPath(path) {
  const before = lstatPath(path)
  if (before.isSymbolicLink()) throw stagingError('staging-symlink')
  if (!before.isDirectory()) throw stagingError('staging-special-file')
  let fd
  try {
    fd = fs.openSync(path, fs.constants.O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
    const opened = fs.fstatSync(fd)
    const after = lstatPath(path)
    if (after.isSymbolicLink() || !after.isDirectory() || !opened.isDirectory()
      || !sameObject(before, opened) || !sameObject(before, after)) {
      throw stagingError('staging-containment-failed')
    }
    return { fd, stat: opened }
  } catch (error) {
    closeQuietly(fd)
    if (error instanceof StagingSnapshotError) throw error
    throw stagingError('staging-copy-failed')
  }
}

function openVerifiedDirectoryAt(parent, name) {
  const path = descriptorChildPath(parent, name)
  const before = lstatPath(path)
  if (before.isSymbolicLink()) throw stagingError('staging-symlink')
  if (!before.isDirectory()) throw stagingError('staging-special-file')
  let fd
  try {
    fd = fs.openSync(path, fs.constants.O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
    const opened = fs.fstatSync(fd)
    const after = lstatPath(path)
    if (after.isSymbolicLink() || !after.isDirectory() || !opened.isDirectory()
      || !sameObject(before, opened) || !sameObject(before, after)) {
      throw stagingError('staging-containment-failed')
    }
    return { fd, stat: opened }
  } catch (error) {
    closeQuietly(fd)
    if (error instanceof StagingSnapshotError) throw error
    throw stagingError('staging-copy-failed')
  }
}

function openVerifiedFileAt(parent, name) {
  const path = descriptorChildPath(parent, name)
  const before = lstatPath(path)
  if (before.isSymbolicLink()) throw stagingError('staging-symlink')
  if (!before.isFile()) throw stagingError('staging-special-file')
  if (before.nlink !== 1) throw stagingError('staging-hardlink')
  let fd
  try {
    fd = fs.openSync(path, fs.constants.O_RDONLY | O_NOFOLLOW)
    const opened = fs.fstatSync(fd)
    const after = lstatPath(path)
    if (after.isSymbolicLink() || !after.isFile() || !opened.isFile()
      || after.nlink !== 1 || opened.nlink !== 1
      || !sameObject(before, opened) || !sameObject(before, after)) {
      throw stagingError('staging-containment-failed')
    }
    return { fd, stat: opened }
  } catch (error) {
    closeQuietly(fd)
    if (error instanceof StagingSnapshotError) throw error
    throw stagingError('staging-copy-failed')
  }
}

function openDirectoryChain(input) {
  const absolute = resolve(input)
  if (!isAbsolute(absolute)) throw stagingError('invalid-staging-source')
  const names = absolute.split(sep).filter(Boolean)
  let current
  try {
    current = openVerifiedDirectoryPath(sep)
    for (const name of names) {
      const next = openVerifiedDirectoryAt(current, name)
      closeDirectoryQuietly(current)
      current = next
    }
    return current
  } catch (error) {
    closeDirectoryQuietly(current)
    throw error
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
      maxEntries: boundedOption(input, 'maxEntries', STAGING_SNAPSHOT_LIMITS.maxEntries),
      maxTotalBytes: boundedOption(input, 'maxTotalBytes', STAGING_SNAPSHOT_LIMITS.maxTotalBytes),
      maxFileBytes: boundedOption(input, 'maxFileBytes', STAGING_SNAPSHOT_LIMITS.maxFileBytes),
      maxPathLength: boundedOption(input, 'maxPathLength', STAGING_SNAPSHOT_LIMITS.maxPathLength),
    }
    return Object.freeze(limits)
  } catch (error) {
    if (error instanceof StagingSnapshotError) throw error
    throw stagingError('invalid-staging-options')
  }
}

function prepareSource(sourceRoot) {
  if (typeof sourceRoot !== 'string' || sourceRoot.length === 0 || sourceRoot.includes('\0')) {
    throw stagingError('invalid-staging-source')
  }
  const directory = openDirectoryChain(sourceRoot)
  try {
    return { directory, real: fs.realpathSync(descriptorDirectoryPath(directory.fd)) }
  } catch {
    closeDirectoryQuietly(directory)
    throw stagingError('invalid-staging-source')
  }
}

function prepareDestination(capability) {
  let root
  let snapshot
  try {
    root = openDirectoryChain(capability.root)
    snapshot = openDirectoryChain(capability.snapshot)
    const rootReal = fs.realpathSync(descriptorDirectoryPath(root.fd))
    const snapshotReal = fs.realpathSync(descriptorDirectoryPath(snapshot.fd))
    if (rootReal === snapshotReal || !isInsideRoot(rootReal, snapshotReal)) {
      throw stagingError('staging-containment-failed')
    }
    closeDirectoryQuietly(root)
    return { directory: snapshot, real: snapshotReal }
  } catch (error) {
    closeDirectoryQuietly(root)
    closeDirectoryQuietly(snapshot)
    if (error instanceof StagingSnapshotError) throw error
    throw stagingError('staging-containment-failed')
  }
}

function codePointCompare(left, right) {
  if (left < right) return -1
  if (left > right) return 1
  return 0
}

function readDirectoryEntries(directory, state) {
  let reader
  const entries = []
  try {
    reader = fs.opendirSync(descriptorDirectoryPath(directory.fd), { bufferSize: 32 })
    while (true) {
      const entry = reader.readSync()
      if (entry === null) break
      assertSafeName(entry.name)
      state.entryCount += 1
      if (state.entryCount > state.limits.maxEntries) throw stagingError('staging-entry-budget-limit')
      entries.push(entry.name)
    }
    return entries
  } catch (error) {
    if (error instanceof StagingSnapshotError) throw error
    throw stagingError('staging-copy-failed')
  } finally {
    if (reader) {
      try {
        reader.closeSync()
      } catch {
        // The directory fd remains owned by the traversal and is closed by its caller.
      }
    }
  }
}

/** VCS metadata has a platform-independent, ASCII case-insensitive policy. */
export function isVcsMetadataName(name) {
  return typeof name === 'string' && name.toLowerCase() === '.git'
}

function isNestedWorktree(directory, entries) {
  for (const name of entries) {
    if (!isVcsMetadataName(name)) continue
    const stat = lstatAt(directory, name)
    if (!stat.isDirectory()) return true
  }
  return false
}

function createDestinationDirectoryAt(parent, name) {
  const path = descriptorChildPath(parent, name)
  try {
    fs.mkdirSync(path, { mode: 0o700 })
  } catch (error) {
    if (error?.code === 'EEXIST') throw stagingError('staging-containment-failed')
    throw stagingError('staging-copy-failed')
  }
  return openVerifiedDirectoryAt(parent, name)
}

function openDestinationFileAt(parent, name) {
  try {
    return fs.openSync(
      descriptorChildPath(parent, name),
      fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | O_NOFOLLOW,
      0o600,
    )
  } catch {
    throw stagingError('staging-copy-failed')
  }
}

function copyFile(sourceFile, destinationDirectory, name, manifestPath, state) {
  const size = sourceFile.stat.size
  if (!Number.isSafeInteger(size) || size < 0) throw stagingError('staging-special-file')
  if (size > state.limits.maxFileBytes) throw stagingError('staging-file-bytes-limit')
  if (state.fileCount >= state.limits.maxFiles) throw stagingError('staging-file-count-limit')
  if (state.totalBytes + size > state.limits.maxTotalBytes) throw stagingError('staging-total-bytes-limit')

  let destinationFd
  try {
    destinationFd = openDestinationFileAt(destinationDirectory, name)
    const buffer = Buffer.allocUnsafe(COPY_BUFFER_BYTES)
    let remaining = size
    while (remaining > 0) {
      const read = fs.readSync(sourceFile.fd, buffer, 0, Math.min(buffer.length, remaining), null)
      if (read === 0) throw stagingError('staging-source-changed')
      let offset = 0
      while (offset < read) {
        const written = fs.writeSync(destinationFd, buffer, offset, read - offset, null)
        if (written === 0) throw stagingError('staging-copy-failed')
        offset += written
      }
      remaining -= read
    }
    const finalStat = fs.fstatSync(sourceFile.fd)
    if (!finalStat.isFile() || finalStat.nlink !== 1 || finalStat.size !== size
      || !sameObject(sourceFile.stat, finalStat)) {
      throw stagingError('staging-source-changed')
    }
    fs.fchmodSync(destinationFd, sourceFile.stat.mode & 0o777)
  } catch (error) {
    if (error instanceof StagingSnapshotError) throw error
    throw stagingError('staging-copy-failed')
  } finally {
    closeQuietly(destinationFd)
  }

  state.fileCount += 1
  state.totalBytes += size
  state.files.push(Object.freeze({
    path: manifestPath,
    bytes: size,
    mode: sourceFile.stat.mode & 0o777,
  }))
}

function walkDirectory(sourceDirectory, destinationDirectory, segments, entries, state) {
  for (const name of [...entries].sort(codePointCompare)) {
    if (isVcsMetadataName(name)) {
      state.excluded.git += 1
      continue
    }
    const childSegments = [...segments, name]
    const manifestPath = childSegments.join('/')
    if (manifestPath.length > state.limits.maxPathLength) throw stagingError('staging-path-length-limit')
    const stat = lstatAt(sourceDirectory, name)
    if (stat.isSymbolicLink()) throw stagingError('staging-symlink')

    if (stat.isDirectory()) {
      const childSource = openVerifiedDirectoryAt(sourceDirectory, name)
      let childDestination
      try {
        const childEntries = readDirectoryEntries(childSource, state)
        if (isNestedWorktree(childSource, childEntries)) {
          state.excluded.worktrees += 1
          continue
        }
        childDestination = createDestinationDirectoryAt(destinationDirectory, name)
        walkDirectory(childSource, childDestination, childSegments, childEntries, state)
      } finally {
        closeDirectoryQuietly(childDestination)
        closeDirectoryQuietly(childSource)
      }
      continue
    }

    const sourceFile = openVerifiedFileAt(sourceDirectory, name)
    try {
      copyFile(sourceFile, destinationDirectory, name, manifestPath, state)
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
 * Source traversal is available only when descriptor-relative Linux access is present.
 */
export function createStagingSnapshot(sourceRoot, options) {
  assertDescriptorTraversalAvailable()
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
    const rootEntries = readDirectoryEntries(source.directory, state)
    walkDirectory(source.directory, snapshot.directory, [], rootEntries, state)
    state.files.sort((left, right) => codePointCompare(left.path, right.path))
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
    closeDirectoryQuietly(source?.directory)
    closeDirectoryQuietly(snapshot?.directory)
    source = undefined
    snapshot = undefined
    try {
      cleanup()
    } catch {
      // Rollback failures are intentionally not allowed to disclose host details.
    }
    throw publicError(error)
  } finally {
    closeDirectoryQuietly(source?.directory)
    closeDirectoryQuietly(snapshot?.directory)
  }
}
