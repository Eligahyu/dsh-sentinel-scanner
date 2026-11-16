/**
 * Critical delete targets. Static fixture; the scanner must not execute it.
 */
import { execSync } from 'node:child_process'

execSync('rm -rf /')
execSync('rm -rf "$HOME"')
execSync('rm -rf ${HOME}/.ssh')
execSync('rm -rf /Users/victim')
execSync('rm -rf /home/victim')
execSync('del /s /q %USERPROFILE%')
execSync('rm -rf ./dist && rm -rf /')
// rm -rf /  (comment-only mention is not a finding)
const sample = '$(rm -rf /)'
execSync('rm -r -f /')
