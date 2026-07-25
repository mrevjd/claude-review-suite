// CLEAN-FIXTURE -- the vulnerable.ts situations written correctly (VT-02, VT-03, VT-06, VT-07).
// A review of this file must produce no Critical and no High findings.

// VT-02: structure is built as nodes and the untrusted part is set as text, so markup in the query
// cannot execute.
export function renderSearchSummary(el: HTMLElement, query: string, hits: number): void {
  el.replaceChildren()

  const count = document.createElement('strong')
  count.textContent = String(hits)

  const term = document.createElement('em')
  term.textContent = query

  el.append(count, document.createTextNode(' results for '), term)
}

// VT-03: one wrapper adds the token the backend expects to every state-changing request, so no
// call site can forget it.
function csrfToken(): string {
  const meta = document.querySelector('meta[name="csrf-token"]')
  const token = meta?.getAttribute('content')
  if (!token) throw new Error('csrf token missing from document')
  return token
}

export async function postJson(path: string, payload: unknown): Promise<Response> {
  return fetch(path, {
    method: 'POST',
    credentials: 'same-origin',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRF-Token': csrfToken(),
    },
    body: JSON.stringify(payload),
  })
}

export async function transferFunds(toAccount: string, amountCents: number): Promise<Response> {
  return postJson('/api/transfer', { toAccount, amountCents })
}

// VT-06: prototype-polluting keys are refused, and ownership is checked with Object.hasOwn rather
// than `in`, which would walk the prototype chain.
const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype'])

type Preferences = Record<string, unknown>

export function mergePreferences(target: Preferences, source: Preferences): Preferences {
  for (const key of Object.keys(source)) {
    if (FORBIDDEN_KEYS.has(key)) continue
    if (!Object.hasOwn(source, key)) continue

    const incoming = source[key]
    const existing = target[key]

    if (isPlainObject(incoming)) {
      target[key] = mergePreferences(isPlainObject(existing) ? existing : {}, incoming)
    } else {
      target[key] = incoming
    }
  }
  return target
}

function isPlainObject(value: unknown): value is Preferences {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

// VT-07: the network boundary is typed as unknown and narrowed by a guard, so a changed response
// shape produces a handled error instead of a runtime crash deep in the caller.
interface Item {
  label: string
}

function isItemArray(value: unknown): value is Item[] {
  return (
    Array.isArray(value) &&
    value.every((i) => typeof i === 'object' && i !== null && typeof (i as Item).label === 'string')
  )
}

export async function loadItems(url: string): Promise<string[]> {
  const res = await fetch(url)
  if (!res.ok) throw new Error(`loadItems: ${res.status} ${res.statusText}`)

  const body: unknown = await res.json()
  const items = isPlainObject(body) ? (body as { data?: { items?: unknown } }).data?.items : undefined

  if (!isItemArray(items)) throw new Error('loadItems: unexpected response shape')
  return items.map((i) => i.label)
}
