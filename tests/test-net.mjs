import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createAssert, finish, PKG } from './commons.mjs';

function pinExe() {
  const fromEnv = process.env.PM_COMMONS_PIN_CLI;
  if (fromEnv && existsSync(fromEnv)) return resolve(fromEnv);
  const name = process.platform === 'win32' ? 'pm-commons-pin.exe' : 'pm-commons-pin';
  for (const dir of ['dev', 'release']) {
    const candidate = join(PKG, 'build', dir, name);
    if (existsSync(candidate)) return candidate;
  }
  return join(PKG, 'build', 'dev', name);
}

function runPin(hex) {
  const exe = pinExe();
  const r = spawnSync(exe, [hex], {
    cwd: PKG,
    encoding: 'utf8',
    timeout: 10_000,
  });
  const stdout = String(r.stdout || '').trim();
  let json = null;
  try { json = JSON.parse(stdout); } catch { json = null; }
  return { status: r.status ?? -1, json, stdout, stderr: String(r.stderr || '') };
}

const checks = createAssert();
const { assert } = checks;
const exe = pinExe();
if (!existsSync(exe)) {
  console.error(`pm-commons-pin not built (${exe}). From packages/commons.cpp: npm run configure; npm run build:pin`);
  process.exit(1);
}
console.log(`pm-commons-pin  ${exe}`);

{
  const hex = 'a'.repeat(64);
  const r = runPin(hex);
  assert(r.status === 0 && r.json?.ok === true, 'valid pin formats');
  assert(typeof r.json?.pin === 'string' && r.json.pin.startsWith('sha256//'),
    `pin prefix (got ${r.json?.pin})`);
}

{
  const r = runPin('deadbeef');
  assert(r.status === 1 && r.json?.ok === false && r.json?.code === 'EPIN',
    `short pin rejected (got ${JSON.stringify(r.json)})`);
}

{
  const r = runPin('g'.repeat(64));
  assert(r.status === 1 && r.json?.code === 'EPIN', 'non-hex pin rejected');
}

{
  const r = runPin('http://example');
  assert(r.status === 1 && r.json?.code === 'EPIN', 'garbage pin rejected');
}

finish(checks);
