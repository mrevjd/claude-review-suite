// Deliberately defective TypeScript used to test the review-vue-ts skill.
// Planted defects: VT-02, VT-03, VT-06, VT-07. The rest live in vulnerable.vue.

export function renderSearchSummary(el: HTMLElement, query: string, hits: number): void {
  // VULN: VT-02 -- the query comes from the address bar and is assigned as HTML, so this is
  // reflected XSS reached without touching a template.
  el.innerHTML = `<strong>${hits}</strong> results for <em>${query}</em>`
}

export async function transferFunds(toAccount: string, amountCents: number): Promise<Response> {
  // VULN: VT-03 -- a state-changing POST that sends the session cookie with no CSRF token, so any
  // origin can make the browser perform this transfer on the user's behalf.
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
