/*
 * The subscribe wizard's input of `service:security:fortify:pkey`: the projects of the
 * selected instance, searched as the user types (the host LjRemoteSearchField).
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'
import { mount, flushPromises } from '@vue/test-utils'
import { reactive } from 'vue'
import def from '../index.js'

const PARAMETER = { id: 'service:security:fortify:pkey', type: 'INTEGER', mandatory: true }

function jsonResponse(body) {
  return { ok: true, status: 200, headers: { get: () => 'application/json' }, json: async () => body }
}
// Expose the bindings of the field; the test types through `update:search`
const inputStub = (name) => ({ name, props: ['items'], emits: ['update:search', 'update:modelValue'], template: '<input />' })
const stubs = { LigojAutocomplete: inputStub('LigojAutocomplete'), LigojCombobox: inputStub('LigojCombobox') }

beforeEach(() => {
  // The search waits for a pause in the typing
  vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
  setActivePinia(createPinia())
  def.install()
  globalThis.fetch = vi.fn(async () => jsonResponse([{ id: 12, name: 'Ligoj' }]))
})
afterEach(() => { vi.useRealTimers() })

describe('service:security:fortify:pkey parameter field', () => {
  it('is a remote search to subscribe, the default input to edit a node or for another parameter', () => {
    const field = def.feature('parameterField', { parameter: PARAMETER, isNode: false })
    expect(field).toBeTruthy()
    // The same component on each render, else the wizard would remount the input
    expect(def.feature('parameterField', { parameter: PARAMETER, isNode: false })).toBe(field)
    expect(def.feature('parameterField', { parameter: PARAMETER, isNode: true })).toBeNull()
    expect(def.feature('parameterField', { parameter: { id: 'service:security:fortify:url' }, isNode: false })).toBeNull()
  })

  it('searches the projects and stores the project identifier', async () => {
    const Field = def.feature('parameterField', { parameter: PARAMETER, isNode: false })
    const w = mount(Field, { props: { modelValue: '', parameter: PARAMETER, formValues: {}, mode: 'link', isNode: false, instanceNodeId: 'service:security:fortify:local' }, global: { stubs } })
    const input = w.findComponent({ name: 'LigojAutocomplete' })
    input.vm.$emit('update:search', 'ligoj')
    vi.advanceTimersByTime(300)
    await flushPromises()
    expect(fetch.mock.calls[0][0]).toBe('rest/service/security/fortify/service%3Asecurity%3Afortify%3Alocal/ligoj')
    expect(input.props('items')).toEqual([{ title: 'Ligoj', subtitle: '12', value: 12 }])
  })
})

describe('service:security:fortify:version parameter field', () => {
  const VERSION = { id: 'service:security:fortify:version', type: 'INTEGER', mandatory: true }
  const NODE = 'service:security:fortify:local'
  const VERSIONS = 'rest/service/security/fortify/versions/service%3Asecurity%3Afortify%3Alocal/'
  const selectStub = { LigojSelect: { name: 'LigojSelect', props: ['items', 'readonly', 'modelValue', 'label'], template: '<select />' } }
  function mountVersion(formValues, modelValue = '') {
    const Field = def.feature('parameterField', { parameter: VERSION, isNode: false })
    const update = vi.fn()
    const w = mount(Field, { props: { modelValue, parameter: VERSION, formValues, mode: 'link', isNode: false, instanceNodeId: NODE, 'onUpdate:modelValue': update }, global: { stubs: selectStub } })
    return { w, update, select: () => w.findComponent({ name: 'LigojSelect' }) }
  }

  it('is the version select to subscribe, the default input to edit a node', () => {
    expect(def.feature('parameterField', { parameter: VERSION, isNode: false })).toBeTruthy()
    expect(def.feature('parameterField', { parameter: VERSION, isNode: true })).toBeNull()
  })

  it('lists the versions of the selected project', async () => {
    globalThis.fetch = vi.fn(async () => jsonResponse([{ id: 101, name: '1.0' }, { id: 102, name: '2.0' }]))
    const { select, update } = mountVersion({ 'service:security:fortify:pkey': 12 })
    await flushPromises()
    expect(fetch.mock.calls[0][0]).toBe(`${VERSIONS}12`)
    expect(select().props('items')).toEqual([{ title: '1.0', value: 101 }, { title: '2.0', value: 102 }])
    expect(select().props('readonly')).toBe(false)
    expect(select().props('label')).toBe('Project Version *')
    expect(update).not.toHaveBeenCalled()
  })

  it('selects the only version of the project', async () => {
    globalThis.fetch = vi.fn(async () => jsonResponse([{ id: 101, name: '1.0' }]))
    const { select, update } = mountVersion({ 'service:security:fortify:pkey': 12 })
    await flushPromises()
    expect(update).toHaveBeenCalledWith(101)
    expect(select().props('readonly')).toBe(true)
  })

  it('reloads the versions when another project is picked, has none without a project', async () => {
    const formValues = reactive({})
    globalThis.fetch = vi.fn(async (url) => jsonResponse(url.endsWith('/12') ? [{ id: 101, name: '1.0' }, { id: 102, name: '2.0' }] : [{ id: 201, name: '3.0' }, { id: 202, name: '4.0' }]))
    const { select, update } = mountVersion(formValues, 101)
    await flushPromises()
    expect(fetch).not.toHaveBeenCalled()
    expect(select().props('items')).toEqual([])
    formValues['service:security:fortify:pkey'] = 12
    await flushPromises()
    expect(select().props('items').map((i) => i.value)).toEqual([101, 102])
    expect(update).not.toHaveBeenCalled()
    // The selected version belongs to the previous project
    formValues['service:security:fortify:pkey'] = 13
    await flushPromises()
    expect(fetch.mock.calls.map((c) => c[0])).toEqual([`${VERSIONS}12`, `${VERSIONS}13`])
    expect(select().props('items').map((i) => i.value)).toEqual([201, 202])
    expect(update).toHaveBeenCalledWith('')
  })
})
