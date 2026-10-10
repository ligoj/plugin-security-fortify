<template>
  <!-- The version of the selected project, the legacy `registerFortifyProjectVersion`:
       loaded from `service/security/fortify/versions/<node>/<project>` each time
       a project is picked, selected when it is the only one. -->
  <LigojSelect
    :model-value="modelValue"
    :label="label"
    :items="items"
    :loading="loading"
    :readonly="items.length <= 1"
    :rules="mandatory ? REQUIRED : OPTIONAL"
    variant="outlined"
    density="comfortable"
    hide-details="auto"
    @update:model-value="(v) => emit('update:modelValue', v ?? '')"
  />
</template>

<script setup>
import { computed, ref, watch } from 'vue'
import { LigojSelect, useApi, useI18nStore } from '@ligoj/host'

const PARAM_PROJECT = 'service:security:fortify:pkey'

const props = defineProps({
  modelValue: { type: [String, Number, null], default: null },
  parameter: { type: Object, required: true },
  formValues: { type: Object, default: () => ({}) },
  instanceNodeId: { type: String, default: null },
})
const emit = defineEmits(['update:modelValue'])

const { t } = useI18nStore()
const api = useApi()

function tOrNull(key) { const v = t(key); return v === key ? null : v }

// Constant rule arrays: an inline array is a new reference on each render and makes v-form revalidate in a loop
const REQUIRED = [(v) => (v != null && String(v).trim() !== '') || (tOrNull('wizard.rule.required') ?? 'Required')]
const OPTIONAL = []
const mandatory = computed(() => !!(props.parameter?.mandatory || props.parameter?.required))
const label = computed(() => `${tOrNull(props.parameter?.id) ?? props.parameter?.id}${mandatory.value ? ' *' : ''}`)

const items = ref([])
const loading = ref(false)
const project = computed(() => props.formValues?.[PARAM_PROJECT])
// Only the versions of the latest picked project update the list
let pending = null

async function load() {
  const token = Symbol('versions')
  pending = token
  items.value = []
  if (!props.instanceNodeId || project.value == null || project.value === '') {
    loading.value = false
    return
  }
  loading.value = true
  try {
    const data = await api.get(`rest/service/security/fortify/versions/${encodeURIComponent(props.instanceNodeId)}/${encodeURIComponent(project.value)}`, { silent: true })
    if (pending !== token) return
    items.value = (Array.isArray(data) ? data : []).map((v) => ({ title: v.name ?? String(v.id), value: v.id }))
  } catch {
    if (pending === token) items.value = []
  } finally {
    if (pending === token) loading.value = false
  }
  if (pending !== token) return
  if (items.value.length === 1) {
    if (props.modelValue !== items.value[0].value) emit('update:modelValue', items.value[0].value)
  } else if (props.modelValue != null && props.modelValue !== '' && !items.value.some((i) => i.value === props.modelValue)) {
    // The selected version belongs to another project
    emit('update:modelValue', '')
  }
}

watch([project, () => props.instanceNodeId], load, { immediate: true })
</script>
