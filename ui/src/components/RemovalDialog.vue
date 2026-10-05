<!--
  Copyright (C) 2026 tebbi
  SPDX-License-Identifier: GPL-3.0-or-later
-->
<template>
  <!-- One dialog for the three removal steps of a deployment or a policy
       profile: start (with waiting period), cancel, delete when due. -->
  <NsModal
    :kind="step === 'cancel' ? 'default' : 'danger'"
    :visible="visible"
    :primary-button-disabled="loading"
    @modal-hidden="$emit('hidden')"
    @primary-click="submit"
  >
    <template slot="title">{{ $t("removal.title_" + step) }}</template>
    <template slot="content">
      <cv-form @submit.prevent>
        <p>{{ $t("removal." + kind + "_" + step, { name }) }}</p>
        <template v-if="step === 'start'">
          <template v-if="stays.length">
            <p class="sub">{{ $t("removal.policy_stays") }}</p>
            <ul class="bullets">
              <li v-for="id in stays" :key="id">
                {{ $t("policy_setting." + id + ".title") }}
              </li>
            </ul>
          </template>
          <NsTextInput
            :label="$t('removal.days_label')"
            v-model.number="days"
            type="number"
            min="1"
            max="365"
            :helper-text="$t('removal.days_help')"
            :invalid-message="daysError"
          />
        </template>
        <p v-if="step === 'delete' && until" class="muted small">
          {{ $t("removal.pending", { date: formatDate(until) }) }}
        </p>
        <NsTextInput
          :label="$t('policies.reason_label')"
          v-model.trim="reason"
          :helper-text="$t('policies.reason_help')"
          :invalid-message="reasonError"
        />
        <NsInlineNotification
          v-if="error"
          kind="error"
          :title="$t('removal.title_' + step)"
          :description="error"
          :showCloseButton="false"
        />
      </cv-form>
    </template>
    <template slot="secondary-button">{{ $t("common.cancel") }}</template>
    <template slot="primary-button">{{
      $t("removal.button_" + step)
    }}</template>
  </NsModal>
</template>

<script>
export default {
  name: "RemovalDialog",
  props: {
    visible: Boolean,
    // "deployment" or "policy"
    kind: { type: String, required: true },
    // "start", "cancel" or "delete"
    step: { type: String, default: "start" },
    name: { type: String, default: "" },
    graceDays: { type: Number, default: 14 },
    until: { type: String, default: "" },
    // policy settings that write the Windows default while waiting
    stays: { type: Array, default: () => [] },
    loading: Boolean,
    error: { type: String, default: "" },
  },
  data() {
    return {
      reason: "",
      days: this.graceDays,
      reasonError: "",
      daysError: "",
    };
  },
  watch: {
    visible(v) {
      if (v) {
        this.reason = "";
        this.days = this.graceDays;
        this.reasonError = this.daysError = "";
      }
    },
  },
  methods: {
    formatDate(iso) {
      const d = new Date(iso);
      return isNaN(d) ? iso : d.toLocaleString();
    },
    submit() {
      this.reasonError = this.daysError = "";
      let ok = true;
      if (this.reason.length < 3) {
        this.reasonError = this.$t("policies.reason_required");
        ok = false;
      }
      const days = Number(this.days);
      if (
        this.step === "start" &&
        !(Number.isInteger(days) && days >= 1 && days <= 365)
      ) {
        this.daysError = this.$t("removal.days_range");
        ok = false;
      }
      if (!ok) return;
      const data = { step: this.step, reason: this.reason };
      if (this.step === "start") data.days = days;
      this.$emit("submit", data);
    },
  },
};
</script>

<style scoped lang="scss">
@import "../styles/carbon-utils";
.sub {
  margin-top: $spacing-05;
}
.bullets {
  list-style: disc;
  margin: $spacing-03 0 $spacing-05 $spacing-06;
}
</style>
