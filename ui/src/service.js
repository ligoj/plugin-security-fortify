/*
 * Service layer for plugin "security-fortify".
 *
 * Tool-level plugin (lives at `service:security:fortify`). The parent
 * `plugin-security` delegates the subscription-row hooks to us via its
 * `subPluginIdFor` delegation. Mirrors the legacy `fortify.js`:
 *
 *   - renderFeatures   → a link to the Fortify SSC flex UI, scoped to the
 *     project version when set
 *     (`url + '/flex/index.jsp' [+ '#projectVersionId=' + version]`).
 *   - renderDetailsKey → the project-version chip
 *     (`service:security:fortify:version`).
 *
 * The legacy live audit pie / rating chips read `subscription.data` and
 * are omitted here, like the other live-data carousels.
 *
 * Kept free of Vue SFC imports so it can be unit-tested without a DOM.
 */
import { h } from 'vue'
import { VBtn, VChip, VIcon, useI18nStore } from '@ligoj/host'

const PARAM_URL = 'service:security:fortify:url'
const PARAM_VERSION = 'service:security:fortify:version'

/** Fortify SSC flex link. Mirrors the legacy renderFeatures(). */
function renderFeatures(subscription) {
  const params = subscription?.parameters
  const url = params?.[PARAM_URL]
  if (!url) return []
  const { t } = useI18nStore()
  const version = params?.[PARAM_VERSION]
  const href = `${url.replace(/\/$/, '')}/flex/index.jsp${version ? `#projectVersionId=${encodeURIComponent(version)}` : ''}`
  return [
    h(
      VBtn,
      {
        icon: true,
        size: 'small',
        variant: 'text',
        title: t('service:security'),
        href,
        target: '_blank',
        rel: 'noopener noreferrer',
      },
      () => h(VIcon, { size: 'small' }, () => 'mdi-shield-search'),
    ),
  ]
}

/** Project-version chip. Mirrors the legacy renderKey('service:security:fortify:version'). */
function renderDetailsKey(subscription) {
  const version = subscription?.parameters?.[PARAM_VERSION]
  if (!version) return null
  const { t } = useI18nStore()
  return h(
    VChip,
    { size: 'small', variant: 'tonal', class: 'mr-1', title: t('service:security:fortify:version') },
    () => [h(VIcon, { start: true, size: 'small' }, () => 'mdi-shield-check'), ' ', String(version)],
  )
}

export default { renderFeatures, renderDetailsKey }
