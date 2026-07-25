// Differential tests: the vulnerable TypeScript must actually misbehave where its VULN comments
// say it does, and clean.ts must not.
//
// Run with: node tests/fixtures/vue-ts/differential.test.mjs
//
// Node 22+ strips TypeScript types at load, so these import the .ts sources directly rather than
// building them. VT-01/VT-04/VT-05 live in vulnerable.vue and are not covered here -- a .vue SFC
// needs the Vue compiler, which is not a dependency this repo carries; validate.py's anchors are
// what hold those three.
import assert from 'node:assert/strict'

// A DOM stub with just enough surface for the two sinks under test. Deliberately not jsdom: the
// point is that innerHTML assignment is observable, not that the DOM is faithful.
class FakeElement {
  constructor() {
    this.innerHTML = ''
    this.textContent = ''
    this.children = []
  }
  replaceChildren() {
    this.children = []
    this.textContent = ''
  }
  append(...nodes) {
    this.children.push(...nodes)
    this.textContent += nodes.map((n) => n.textContent ?? String(n)).join('')
  }
}

globalThis.document = {
  createElement: () => new FakeElement(),
  createTextNode: (t) => ({ textContent: t }),
  querySelector: () => ({ getAttribute: () => 'stub-csrf-token' }),
  getElementById: () => null, // keeps vulnerable.ts's module-level bootstrap inert on import
}
globalThis.window = { location: { search: '' } }

const vuln = await import('./vulnerable.ts')
const clean = await import('./clean.ts')

let failures = 0

// Must await fn(): an async check whose promise is not awaited reports pass and dumps its real
// assertion failure as an unhandled rejection, which is a test harness that cannot fail.
async function check(name, fn) {
  try {
    await fn()
    console.log(`  pass  ${name}`)
  } catch (err) {
    console.error(`  FAIL  ${name}: ${err.message}`)
    failures++
  }
}

const XSS = '<img src=x onerror=alert(1)>'

// VT-02: the vulnerable renderer puts attacker markup into innerHTML; the clean one sets it as
// text, so the payload never becomes an element.
await check('VT-02 vulnerable assigns raw markup to innerHTML', () => {
  const el = new FakeElement()
  vuln.renderSearchSummary(el, XSS, 3)
  assert.ok(el.innerHTML.includes('onerror=alert(1)'),
    'payload did not reach innerHTML -- VT-02 no longer fires')
})

await check('VT-02 clean renders the payload as text', () => {
  const el = new FakeElement()
  clean.renderSearchSummary(el, XSS, 3)
  assert.equal(el.innerHTML, '', 'clean version must never assign innerHTML')
  assert.ok(el.textContent.includes(XSS), 'the query should survive as literal text')
})

// VT-06: prototype pollution. The assertion is on Object.prototype itself, so a leaked property
// would corrupt this test file too -- hence the explicit cleanup.
await check('VT-06 vulnerable merge pollutes Object.prototype', () => {
  try {
    vuln.mergePreferences({}, JSON.parse('{"__proto__": {"isAdmin": true}}'))
    assert.equal({}.isAdmin, true, 'Object.prototype was not polluted -- VT-06 no longer fires')
  } finally {
    delete Object.prototype.isAdmin
  }
})

await check('VT-06 clean merge refuses __proto__', () => {
  try {
    clean.mergePreferences({}, JSON.parse('{"__proto__": {"isAdmin": true}}'))
    assert.equal({}.isAdmin, undefined, 'clean merge must not pollute Object.prototype')
  } finally {
    delete Object.prototype.isAdmin
  }
})

// VT-03: the vulnerable transfer sends credentials with no CSRF header; the clean one adds it.
await check('VT-03 vulnerable POST carries credentials and no CSRF header', async () => {
  let captured
  globalThis.fetch = async (url, init) => {
    captured = init
    return { ok: true }
  }
  await vuln.transferFunds('acct-1', 100)
  assert.equal(captured.credentials, 'include')
  assert.equal(captured.headers['X-CSRF-Token'], undefined,
    'a CSRF header appeared -- VT-03 no longer fires')
})

await check('VT-03 clean POST sends a CSRF token', async () => {
  let captured
  globalThis.fetch = async (url, init) => {
    captured = init
    return { ok: true }
  }
  await clean.transferFunds('acct-1', 100)
  assert.equal(captured.headers['X-CSRF-Token'], 'stub-csrf-token')
})

// VT-07: `any` at the boundary means a changed response shape throws deep in the caller instead of
// being rejected at the edge. Both throw -- the difference is *what*.
await check('VT-07 vulnerable throws a shape error, clean throws a handled one', async () => {
  globalThis.fetch = async () => ({ ok: true, json: async () => ({ unexpected: true }) })

  let vulnErr
  try {
    await vuln.loadItems('/x')
  } catch (e) {
    vulnErr = e
  }
  assert.ok(vulnErr instanceof TypeError,
    `expected an uncaught TypeError from the any-typed boundary, got ${vulnErr}`)

  let cleanErr
  try {
    await clean.loadItems('/x')
  } catch (e) {
    cleanErr = e
  }
  assert.ok(cleanErr && !(cleanErr instanceof TypeError) &&
    /unexpected response shape/.test(cleanErr.message),
    `clean version should reject the shape explicitly, got ${cleanErr}`)
})

if (failures) {
  console.error(`\n${failures} differential failure(s)`)
  process.exit(1)
}
console.log('\nvue-ts differential tests passed: vulnerable.ts and clean.ts diverge where they should')
