<!--
  Copyright (C) 2026 tebbi
  SPDX-License-Identifier: GPL-3.0-or-later
-->
<template>
  <div class="dc-check">
    <cv-skeleton-text v-if="loading" :paragraph="true" :line-count="3" />
    <div v-else-if="!result" class="muted">{{ $t("dcs.not_checked") }}</div>
    <template v-else>
      <ul class="dcs">
        <li v-for="dc in result.dcs" :key="dc.name">
          <CheckmarkFilled16 v-if="dcOk(dc)" class="ok" />
          <WarningFilled16 v-else class="bad" />
          <span>
            <strong>{{ dc.name }}</strong>
            {{ dc.ips.length ? dc.ips.join(", ") : $t("dcs.no_address") }}
            <span v-if="!dc.reachable" class="bad-text">
              — {{ $t("dcs.unreachable") }}</span
            >
            <span v-else-if="dc.missing_gpos === null" class="bad-text">
              — {{ $t("dcs.sysvol_unreadable") }}</span
            >
            <span v-else-if="dc.missing_gpos.length" class="bad-text">
              —
              {{
                $tc("dcs.missing_gpos", dc.missing_gpos.length, {
                  n: dc.missing_gpos.length,
                })
              }}</span
            >
          </span>
        </li>
      </ul>
      <p v-if="foreignIps.length" class="bad-text">
        {{ $t("dcs.domain_ips", { ips: foreignIps.join(", ") }) }}
      </p>
      <p v-if="result.dcs.length > 1" class="muted">
        {{ $t("dcs.several", { n: result.dcs.length }) }}
      </p>
      <p class="muted small">
        {{ $t("dcs.checked", { time: formatTime(result.checked) }) }}
      </p>
    </template>
  </div>
</template>

<script>
import CheckmarkFilled16 from "@carbon/icons-vue/es/checkmark--filled/16";
import WarningFilled16 from "@carbon/icons-vue/es/warning--filled/16";

export function dcsOk(result) {
  if (!result) {
    return true;
  }
  const reachable = new Set();
  result.dcs
    .filter((dc) => dc.reachable)
    .forEach((dc) => dc.ips.forEach((ip) => reachable.add(ip)));
  return (
    result.dcs.every(
      (dc) => dc.reachable && dc.missing_gpos && !dc.missing_gpos.length
    ) && (result.domain_ips || []).every((ip) => reachable.has(ip))
  );
}

export default {
  name: "DcCheck",
  components: { CheckmarkFilled16, WarningFilled16 },
  props: {
    result: { type: Object, default: null },
    loading: { type: Boolean, default: false },
  },
  computed: {
    // addresses of the domain name (\\domain\SysVol) that belong to no
    // reachable DC: clients that pick them cannot read the GPOs
    foreignIps() {
      if (!this.result) {
        return [];
      }
      const ok = new Set();
      this.result.dcs
        .filter((dc) => dc.reachable)
        .forEach((dc) => dc.ips.forEach((ip) => ok.add(ip)));
      return (this.result.domain_ips || []).filter((ip) => !ok.has(ip));
    },
  },
  methods: {
    dcOk(dc) {
      return dc.reachable && dc.missing_gpos && !dc.missing_gpos.length;
    },
    formatTime(iso) {
      return iso ? new Date(iso).toLocaleString() : "";
    },
  },
};
</script>

<style scoped lang="scss">
@import "../styles/carbon-utils";
.muted {
  color: $text-02;
  margin-top: $spacing-03;
}
.small {
  font-size: 0.875rem;
}
.bad-text {
  color: $support-01;
  margin-top: $spacing-03;
}
.dcs {
  li {
    display: flex;
    align-items: flex-start;
    gap: $spacing-03;
    margin-bottom: $spacing-03;
  }
  .ok {
    fill: $support-02;
    flex-shrink: 0;
  }
  .bad {
    fill: $support-03;
    flex-shrink: 0;
  }
}
</style>
