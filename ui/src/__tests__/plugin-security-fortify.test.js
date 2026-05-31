/*
 * Contract tests for plugin-security-fortify, incl. the parent → child delegation:
 * when security-fortify is registered, plugin-security's renderFeatures/renderDetailsKey
 * resolve to this tool for a matching node.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'
import { pluginRegistry, useI18nStore } from '@ligoj/host'
import def from '../index.js'
import parentDef from '../../../../plugin-security/ui/src/index.js'

beforeEach(() => { setActivePinia(createPinia()) })

describe('plugin-security-fortify manifest', () => {
  it('exposes a valid tool-level manifest', () => {
    expect(def.id).toBe('security-fortify')
    expect(def.requires).toEqual(['security'])
    expect(def.routes).toBeUndefined()
    expect(typeof def.install).toBe('function')
    expect(typeof def.feature).toBe('function')
    expect(def.service).toBeTypeOf('object')
    expect(def.meta).toMatchObject({ icon: expect.any(String), color: expect.any(String) })
  })

  it('merges i18n on install', () => {
    const i18n = useI18nStore()
    def.install()
    expect(i18n.t('service:security:fortify:version')).toBeTypeOf('string')
    expect(i18n.t('service:security:fortify:version')).not.toBe('service:security:fortify:version')
  })

  it('throws for an unknown feature', () => {
    expect(() => def.feature('nope')).toThrow(/no feature "nope"/)
  })

  it('renderFeatures returns a home-link button when params are set', () => {
    def.install()
    const vnodes = def.feature('renderFeatures', { parameters: {"service:security:fortify:url":"https://ssc.example.org","service:security:fortify:version":"1001"} })
    expect(vnodes).toHaveLength(1)
    expect(vnodes[0].__v_isVNode).toBe(true)
    expect(vnodes[0].props.target).toBe('_blank')
  })

  it('renderFeatures returns [] without the required params', () => {
    def.install()
    expect(def.feature('renderFeatures', { parameters: {} })).toEqual([])
    expect(def.feature('renderFeatures', {})).toEqual([])
  })

  it('renderDetailsKey returns the resource chip when present', () => {
    def.install()
    expect(def.feature('renderDetailsKey', { parameters: { 'service:security:fortify:version': 'x' } })).toBeTruthy()
    expect(def.feature('renderDetailsKey', { parameters: {} })).toBeNull()
  })
})

describe('plugin-security → plugin-security-fortify delegation', () => {
  beforeEach(() => {
    parentDef.install({ router: { addRoute() {} } })
    def.install()
    pluginRegistry.register('security-fortify', def)
  })
  afterEach(() => { pluginRegistry.remove('security-fortify') })

  it('parent renderDetailsKey resolves to this tool for a matching node', () => {
    const out = parentDef.feature('renderDetailsKey', {
      node: { id: 'service:security:fortify:1' },
      parameters: { 'service:security:fortify:version': 'x' },
    })
    expect(Array.isArray(out)).toBe(true)
    expect(out.length).toBe(1)
    expect(out[0].__v_isVNode).toBe(true)
  })

  it('does not delegate for a different tool', () => {
    const out = parentDef.feature('renderDetailsKey', {
      node: { id: 'service:security:other:1' },
      parameters: {},
    })
    expect(out).toBeNull()
  })
})
