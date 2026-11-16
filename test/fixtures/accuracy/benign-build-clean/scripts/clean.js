/**
 * Benign build cleanup. These commands must not be scored as SEN-FS-001.
 * Static fixture; the scanner must not execute it.
 */
import { execSync } from 'node:child_process'

execSync('rm -rf ./dist')
execSync('rm -rf ./node_modules/.cache')
execSync('rm -rf dist/')
execSync('rm -rf /tmp/build-cache')
execSync('rm -rf "$PWD/coverage"')
execSync('rm -rf ./homepage')
execSync('rm -rf $HOME_CACHE')
