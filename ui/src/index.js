/*
 * Plugin "security-fortify" — Fortify implementation of plugin-security.
 *
 * Tool-level plugin (`service:security:fortify`). Augments the parent
 * `plugin-security` via i18n parameter labels + row features (home link +
 * resource chip) merged in through plugin-security's `subPluginIdFor`
 * delegation hook.
 *
 * Authored as source — compiled to `/main/security-fortify/vue/index.js` by Vite.
 */
import { useI18nStore } from '@ligoj/host'
import enMessages from './i18n/en.js'
import frMessages from './i18n/fr.js'
import service from './service.js'

const features = {
  renderFeatures: service.renderFeatures,
  renderDetailsKey: service.renderDetailsKey,
}

export default {
  id: 'security-fortify',
  label: 'Fortify',
  requires: ['security'],
  install() {
    const i18n = useI18nStore()
    i18n.merge(enMessages, 'en')
    i18n.merge(frMessages, 'fr')
  },
  feature(action, ...args) {
    const fn = features[action]
    if (!fn) throw new Error(`Plugin "security-fortify" has no feature "${action}"`)
    return fn(...args)
  },
  service,
  meta: { icon: 'mdi-shield-search', color: 'red-darken-2' },
}

export { service }
