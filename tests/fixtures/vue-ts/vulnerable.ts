// Deliberately defective TypeScript used to test the review-vue-ts skill.
// Planted defects: VT-02, VT-03, VT-06, VT-07. The rest live in vulnerable.vue.

export function renderSearchSummary(el: HTMLElement, query: string, hits: number): void {
  // VULN: VT-02 -- the query comes from the address bar and is assigned as HTML, so this is
  // reflected XSS reached without touching a template.
  el.innerHTML = `<strong>${hits}</strong> results for <em>${query}</em>`
}

// Reachable from the page's own query string -- this is what actually calls
// renderSearchSummary with attacker-influenced input, matching the VULN comment's premise.
if (typeof document !== 'undefined') {
  const summaryEl = document.getElementById('search-summary')
  const query = new URLSearchParams(window.location.search).get('q') ?? ''
  if (summaryEl) renderSearchSummary(summaryEl, query, 0)
}

export async function transferFunds(toAccount: string, amountCents: number): Promise<Response> {
  // VULN: VT-03 -- a state-changing POST that sends the session cookie with no CSRF token. The
  // JSON content type forces a CORS preflight, so a bare cross-origin form cannot trigger this
  // alone -- but any origin the backend's CORS policy allows with credentials can, and nothing
  // here stops that policy from being permissive.
  return fetch('/api/transfer', {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ toAccount, amountCents }),
  })
}

// VULN: VT-06 -- keys are copied without rejecting __proto__, so a payload of
// {"__proto__": {"isAdmin": true}} mutates Object.prototype and every object in the runtime
// appears to have isAdmin.
export function mergePreferences(target: any, source: any): any {
  for (const key in source) {
    if (typeof source[key] === 'object' && source[key] !== null) {
      target[key] = mergePreferences(target[key] || {}, source[key])
    } else {
      target[key] = source[key]
    }
  }
  return target
}

// VULN: VT-07 -- any at the network boundary switches off checking exactly where the shape is least
// known, so a changed or error-shaped response throws "undefined is not iterable" in the browser
// instead of failing the build.
export async function loadItems(url: string): Promise<string[]> {
  const res = await fetch(url)
  const body: any = await res.json()
  return body.data.items.map((i: any) => i.label)
}
