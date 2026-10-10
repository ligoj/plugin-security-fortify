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
 *   - parameterField   → the subscribe-wizard inputs: the project, searched
 *     among the projects of the instance, then its version
 *     (legacy `configureSubscriptionParameters`).
 *
 * The legacy live audit pie / rating chips read `subscription.data` and
 * are omitted here, like the other live-data carousels.
 */
import { renderServiceLink, renderDetailsChip, useI18nStore, remoteSearchField } from '@ligoj/host'
import FortifyVersionField from './fields/FortifyVersionField.vue'

const PARAM_URL = 'service:security:fortify:url'
const PARAM_PROJECT = 'service:security:fortify:pkey'
const PARAM_VERSION = 'service:security:fortify:version'

/** Fortify SSC flex link. Mirrors the legacy renderFeatures(). */
function renderFeatures(subscription) {
  const params = subscription?.parameters
  const url = params?.[PARAM_URL]
  if (!url) return []
  const { t } = useI18nStore()
  const version = params?.[PARAM_VERSION]
  const href = `${url.replace(/\/$/, '')}/flex/index.jsp${version ? `#projectVersionId=${encodeURIComponent(version)}` : ''}`
  return [renderServiceLink({ icon: 'mdi-shield-search', href, title: t('service:security') })]
}

/** Project-version chip. Mirrors the legacy renderKey('service:security:fortify:version'). */
function renderDetailsKey(subscription) {
  const version = subscription?.parameters?.[PARAM_VERSION]
  if (!version) return null
  const { t } = useI18nStore()
  return renderDetailsChip({ icon: 'mdi-shield-check', text: version, title: t('service:security:fortify:version') })
}

// Subscribe-wizard inputs: the project is searched among the projects of the
// selected instance, then its version is picked among the versions of the project.
const PARAMETER_FIELDS = {
  [PARAM_PROJECT]: remoteSearchField({ path: 'rest/service/security/fortify' }),
  [PARAM_VERSION]: FortifyVersionField,
}

/**
 * Subscribe-wizard hook: the project and version inputs. Null for every other
 * parameter and when editing a node: the default type-based input is rendered.
 */
function parameterField({ parameter, isNode } = {}) {
  return isNode ? null : PARAMETER_FIELDS[parameter?.id] || null
}

export default { renderFeatures, renderDetailsKey, parameterField }
