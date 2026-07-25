<script setup lang="ts">
// CLEAN-FIXTURE -- the vulnerable.vue situations written correctly (VT-01, VT-04, VT-05).
// A review of this file must produce no Critical and no High findings.
import { computed, onMounted, ref } from 'vue'

const props = defineProps<{ bio: string; avatarUrl: string; theme: string }>()

// VT-05: the props are typed *and* validated at the boundary, because a type annotation does not
// exist at runtime and these values arrive over the network.
const ALLOWED_THEMES = ['light', 'dark', 'contrast'] as const
type Theme = (typeof ALLOWED_THEMES)[number]

const safeTheme = computed<Theme>(() =>
  (ALLOWED_THEMES as readonly string[]).includes(props.theme) ? (props.theme as Theme) : 'light',
)

// Only http(s) URLs are accepted, so javascript: and data: cannot reach href or src.
const safeAvatarUrl = computed(() => {
  try {
    const parsed = new URL(props.avatarUrl, window.location.origin)
    return parsed.protocol === 'https:' || parsed.protocol === 'http:' ? parsed.href : '/avatar.png'
  } catch {
    return '/avatar.png'
  }
})

// VT-04: no credential in the bundle. The count comes from our own endpoint, which holds the
// analytics key server-side and authenticates the session itself.
const views = ref(0)

onMounted(async () => {
  const res = await fetch('/api/profile/views', { credentials: 'same-origin' })
  if (!res.ok) return
  const body: unknown = await res.json()
  if (typeof body === 'object' && body !== null && 'count' in body) {
    const count = (body as { count: unknown }).count
    if (typeof count === 'number') views.value = count
  }
})
</script>

<template>
  <section :class="safeTheme">
    <!-- VT-01: interpolation escapes, so an author-controlled bio cannot introduce markup. -->
    <div class="bio">{{ props.bio }}</div>

    <a :href="safeAvatarUrl" rel="noopener">
      <img :src="safeAvatarUrl" alt="avatar" />
    </a>

    <p>{{ views }} views</p>
  </section>
</template>
