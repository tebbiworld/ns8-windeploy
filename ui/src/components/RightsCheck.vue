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
          <Information16 v-else-if="rights[key] === undefined" class="info" />
          <WarningFilled16 v-else class="bad" />
          {{ $t("settings.right_" + key) }}
        </li>
        <li v-for="key in optionalKeys" :key="key">
          <CheckmarkFilled16 v-if="rights[key]" class="ok" />
          <Information16 v-else class="info" />
          {{ $t("settings.right_" + key) }} ({{ $t("settings.optional") }})
        </li>
      </ul>
      <p v-if="rights.can_manage_gpos === false" class="foreign">
        {{
          $tc("settings.foreign_gpos", rights.foreign_gpos.length, {
            n: rights.foreign_gpos.length,
            group: rights.group,
          })
        }}
      </p>
      <p v-else-if="rights.group && !rights.in_group" class="muted">
        {{ $t("settings.not_in_group", { group: rights.group }) }}
      </p>
    </template>
  </div>
</template>

<script>
import CheckmarkFilled16 from "@carbon/icons-vue/es/checkmark--filled/16";
import WarningFilled16 from "@carbon/icons-vue/es/warning--filled/16";
import Information16 from "@carbon/icons-vue/es/information/16";

export const RIGHT_KEYS = [
  "can_create_gpo",
  "can_link_domain",
  "can_link_ous",
  "sysvol",
  "can_manage_gpos",
];

// checked since 0.1: missing in an older result means "not checked yet"
const NEWER_KEYS = ["can_manage_gpos"];

// shown, but not needed for deployments
export const OPTIONAL_KEYS = ["can_create_ou"];

export function rightsComplete(rights) {
  return (
    !!rights &&
    RIGHT_KEYS.every(
      (k) => rights[k] || (NEWER_KEYS.includes(k) && rights[k] === undefined)
    )
  );
}

export default {
  name: "RightsCheck",
  components: { CheckmarkFilled16, WarningFilled16, Information16 },
  props: {
    rights: { type: Object, default: null },
    username: { type: String, default: "" },
    loading: { type: Boolean, default: false },
  },
  data() {
    return { keys: RIGHT_KEYS, optionalKeys: OPTIONAL_KEYS };
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
.foreign,
.muted {
  margin-top: $spacing-03;
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
  .info {
    fill: $support-04;
  }
}
</style>
