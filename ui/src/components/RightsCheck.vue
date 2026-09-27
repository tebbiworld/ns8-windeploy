<!--
  Copyright (C) 2026 tebbi
  SPDX-License-Identifier: GPL-3.0-or-later
-->
<template>
  <div class="rights-check">
    <cv-skeleton-text v-if="loading" :paragraph="true" :line-count="3" />
    <div v-else-if="!rights" class="muted">
      {{ $t("settings.rights_unknown") }}
    </div>
    <template v-else>
      <div v-if="username" class="account">
        {{ $t("settings.rights_account", { user: username }) }}
      </div>
      <ul class="rights">
        <li v-for="key in keys" :key="key">
          <CheckmarkFilled16 v-if="rights[key]" class="ok" />
          <WarningFilled16 v-else class="bad" />
          {{ $t("settings.right_" + key) }}
        </li>
      </ul>
    </template>
  </div>
</template>

<script>
import CheckmarkFilled16 from "@carbon/icons-vue/es/checkmark--filled/16";
import WarningFilled16 from "@carbon/icons-vue/es/warning--filled/16";

export const RIGHT_KEYS = ["can_create_gpo", "can_link_domain", "sysvol"];

export function rightsComplete(rights) {
  return !!rights && RIGHT_KEYS.every((k) => rights[k]);
}

export default {
  name: "RightsCheck",
  components: { CheckmarkFilled16, WarningFilled16 },
  props: {
    rights: { type: Object, default: null },
    username: { type: String, default: "" },
    loading: { type: Boolean, default: false },
  },
  data() {
    return { keys: RIGHT_KEYS };
  },
};
</script>

<style scoped lang="scss">
@import "../styles/carbon-utils";
.account {
  margin-bottom: $spacing-04;
}
.muted {
  color: $text-02;
}
.rights {
  li {
    display: flex;
    align-items: center;
    gap: $spacing-03;
    margin-bottom: $spacing-03;
  }
  .ok {
    fill: $support-02;
  }
  .bad {
    fill: $support-03;
  }
}
</style>
