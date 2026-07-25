---
name: review-vue-ts
description: Use when reviewing or auditing Vue or TypeScript front-end code - .vue, .ts or .tsx files, "review this component", "audit this front end", "look over this store before I merge" - covering v-html and innerHTML XSS sinks, missing CSRF handling on fetch, secrets shipped in the client bundle, unvalidated props crossing trust boundaries, prototype pollution, and any masking type errors.
---

# Review Vue / TypeScript

Correctness and security review for front-end code. Two things make this different from reviewing a
backend: everything in the bundle is public, and the type system creates a false sense of safety
that `any` quietly punctures. The checklist runs whether or not the toolchain is installed.

## Procedure

Follow `../../references/procedure.md`. Probe, scope, run what exists, walk the checklist by hand,
score per `../../references/rubric.md`, emit both artifacts.

## Capability probe

```bash
command -v tsc
command -v eslint
command -v bun
command -v knip
```

| Tool | Invocation | If absent |
|---|---|---|
| `tsc --noEmit` | `bunx tsc --noEmit` (or `tsc --noEmit` when installed globally) | `bun add -d typescript` |
| `eslint` | `bunx eslint <files>` | `bun add -d eslint` plus a config the project actually uses |
| `bun audit` | `bun audit` — needs a `bun.lock` in scope | `bun install` first, or note that the project does not use bun |
| `knip` | `bunx knip` | `bun add -d knip` |

Several missing at once? The suite ships `review-tools.sh`, which probes and installs the whole
toolchain in one pass. **Name it in `## Checks skipped` and leave running it to the user** — a review
reports, it does not install.

Prefer `bun`/`bunx` over `npm`/`npx` throughout. `tsc` on a Vue project only sees `<script>` blocks
if the project is set up with `vue-tsc`; if `tsc` cannot resolve `.vue` imports, that is a crash for
the `.vue` files and a result for the `.ts` files — say so in `## Checks skipped` rather than
implying the components were typechecked.

A missing `bun.lock` means `bun audit` did not run. That is a skipped check with the reason "no
lockfile in scope", not a clean dependency report.

## Checklist

| ID | Look for | Why it matters | Fix direction |
|---|---|---|---|
| **VT-01** | `v-html` bound to anything that is not a compile-time literal — user bios, post bodies, CMS fields, markdown output, an API string. | Vue escapes interpolation but `v-html` deliberately does not. Author-controlled HTML here is stored XSS running in every viewer's session with their cookies. | Render as text (`{{ }}`) if formatting is not required. Where HTML is genuinely needed, sanitise server-side or with an allow-list sanitiser that strips `script`, `style`, `on*` attributes and `javascript:` URLs. |
| **VT-02** | `el.innerHTML =`, `outerHTML =`, `insertAdjacentHTML`, `document.write`, `new Function`, or a `ref` whose `.innerHTML` is assigned in `onMounted`. | Same sink as `v-html`, reached by bypassing the template compiler entirely, so template-level review misses it. | `textContent` for text. Build nodes with `createElement`/`append` when structure is needed. Sanitise if HTML from elsewhere must be injected. |
| **VT-03** | A state-changing `fetch`/`axios` call — POST, PUT, PATCH, DELETE — with `credentials: 'include'` or cookie auth, and no CSRF token header; or `SameSite` relied on without being set. | Any origin can make the browser send that request with the user's cookies. The response is unreadable to the attacker but the *side effect* already happened. | Send the token the backend expects (`X-CSRF-Token` from a meta tag or cookie) on every state-changing call, and centralise it in one client wrapper rather than per call site. |
| **VT-04** | A literal API key, token, private key, database URL, or webhook secret in any file that reaches the bundle; `import.meta.env.VITE_*` or `process.env.NEXT_PUBLIC_*` holding a secret. | Everything in the bundle is readable by anyone who opens devtools. A `VITE_` prefix is an instruction to inline the value into the shipped JavaScript. Rotation is the only remedy after the fact. | Move the credential server-side and call it through an endpoint of your own. Client-side env vars are for public configuration only. Flag the value for rotation in the finding — it is already leaked. |
| **VT-05** | `defineProps` with no type or a `string`/`any` prop that flows into a sink (`v-html`, a URL, a redirect target, an `href`, a dynamic component name); props typed but never validated when they arrive from a route param, query string, or API response. | A prop's type annotation is erased at runtime. Types constrain callers you compiled with, not values that arrive over the network, so a "trusted" prop can carry anything. | Type props *and* validate at the trust boundary where the value enters the app. Reject `javascript:`/`data:` URLs, resolve dynamic component names through a fixed map, never interpolate a prop into HTML. |
| **VT-06** | A recursive merge, `Object.assign` in a loop, or `JSON.parse` result copied key by key into an existing object without rejecting `__proto__`, `constructor`, `prototype`; a query-string parser building nested objects. | Writing `__proto__` on any object mutates `Object.prototype` for the whole runtime, letting an attacker inject properties every object suddenly appears to have — a classic route to auth bypass and RCE in SSR. | Reject those three keys explicitly, use `Object.hasOwn` rather than `in`, build with `Object.create(null)` or a `Map`, or use a merge implementation that guards them. |
| **VT-07** | `any`, `as unknown as T`, `@ts-ignore`/`@ts-expect-error`, a non-null `!` on a value that can be null, or an untyped `await res.json()` flowing into typed code. | Each of these switches the checker off exactly where data crosses a boundary and shape assumptions are least justified. The error moves from compile time to a runtime `undefined is not a function` in a user's browser. | Type the boundary — a response interface plus a runtime check (a validator, a discriminated union, or a hand-written guard). Where `any` must stay, narrow it immediately and comment why. |

Beyond the checklist, also weigh: reactivity mistakes (`ref` unwrapped in a template but not in
script, mutating a prop), watchers with no cleanup, `v-for` without a stable `key`,
`target="_blank"` without `rel="noopener"`, and open redirects built from route params.

## Output

Both artifacts, always:

1. **Human report** per the skeleton in `../../references/procedure.md`, ending in a
   `## Checks skipped` table with reason and install hint for every tool that did not run.
2. **Agent prompt block** per `../../references/agent-prompt.md`, all severities, omitted entirely
   when there are no findings.

Derive the block's validation line from the probe. With the toolchain present:
`bunx tsc --noEmit && bunx eslint <files>`. Drop what is absent rather than substituting.

## Common mistakes

- **Treating a typecheck pass as a security result.** `tsc` is happy with `v-html`, a hardcoded API
  key, and a POST with no CSRF token. It checks shapes, not trust.
- **Scoring a leaked client-side secret as Low because "it is only the front end".** If it
  authenticates to something, exposure is Critical and the value needs rotating.
- **Missing sinks in `.ts` because the review only read the templates.** `innerHTML` in a composable
  is the same vulnerability as `v-html` in a template.
- **Reporting every `any` as a finding.** `any` in a test helper or a local type shim is noise.
  Report the ones on a data boundary, where the shape is actually unknown.
