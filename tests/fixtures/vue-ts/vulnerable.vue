<script setup lang="ts">
// Deliberately defective Vue used to test the review-vue-ts skill.
// Planted defects: VT-01, VT-04, VT-05. The rest live in vulnerable.ts.
import { ref, onMounted } from 'vue'

// VULN: VT-05 -- bio and avatarUrl arrive from the profile API and a route query respectively.
// The annotations are erased at runtime, so neither value is actually constrained, and both flow
// straight into sinks below.
// ANCHOR: :href="props.avatarUrl"
const props = defineProps<{ bio: string; avatarUrl: string; theme: string }>()

// VULN: VT-04 -- a live API key inlined into a component, so it ships in the client bundle and is
// readable by anyone who opens devtools. Already leaked; needs rotating, not hiding.
//
// The literal below is deliberately inert so this repository does not trip secret scanners. Flag it
// anyway: a reviewer's job is to report a hardcoded credential literal, not to adjudicate whether
// the value is currently live. Treat it exactly as you would a real key.
// ANCHOR: sk_live_EXAMPLE_0000000000000000000000
const ANALYTICS_KEY = 'sk_live_EXAMPLE_0000000000000000000000'

const views = ref(0)

onMounted(async () => {
  const res = await fetch('https://analytics.example.com/v1/views', {
    headers: { Authorization: `Bearer ${ANALYTICS_KEY}` },
  })
  if (!res.ok) return
  const body: unknown = await res.json()
  if (typeof body === 'object' && body !== null && 'count' in body) {
    const count = (body as { count: unknown }).count
    if (typeof count === 'number') views.value = count
  }
})
</script>

<template>
  <section :class="theme">
    <!-- VULN: VT-01 -- bio is author-controlled and reaches v-html unsanitised, which is stored
         XSS in the session of every visitor who loads this profile. -->
     ANCHOR: v-html="props.bio"
    <div class="bio" v-html="props.bio" />

    <!-- avatarUrl is unvalidated, so a javascript: or data: URL is accepted here too. -->
    <a :href="props.avatarUrl"><img :src="props.avatarUrl" alt="avatar" /></a>

    <p>{{ views }} views</p>
  </section>
</template>
