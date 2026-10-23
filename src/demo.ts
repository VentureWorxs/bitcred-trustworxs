// CLI runner: `npm run demo`. Prints the scenario and exits non-zero if any check fails.
import { runScenario } from './scenario.js';

const ISSUER = 'https://issuer.trustworxs.example';

const report = await runScenario(ISSUER);
for (const step of report.steps) {
  console.log(`\n${step.title}`);
  for (const line of step.lines) console.log(`  ${line}`);
  for (const c of step.checks) {
    console.log(`  ${c.ok ? 'PASS' : 'FAIL'}  ${c.label}${c.detail ? ` (${c.detail})` : ''}`);
  }
}
const failed = report.steps.flatMap((s) => s.checks).filter((c) => !c.ok).length;
console.log(failed === 0 ? '\nAll checks passed.' : `\n${failed} check(s) failed.`);
process.exit(failed === 0 ? 0 : 1);
