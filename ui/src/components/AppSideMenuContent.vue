<!--
  Copyright (C) 2023 Nethesis S.r.l.
  SPDX-License-Identifier: GPL-3.0-or-later
-->
<template>
  <div class="app-side-menu-content">
    <div class="instance-name">
      <div v-if="instanceLabel">{{ instanceLabel }}</div>
      <div v-else-if="instanceName">{{ instanceName }}</div>
      <cv-skeleton-text
        v-else
        :width="instanceNameSkeletonWidth"
      ></cv-skeleton-text>
    </div>

    <cv-side-nav-items>
      <cv-side-nav-link
        @click="goToAppPage(instanceName, 'status')"
        :class="{ 'current-page': isLinkActive('status') }"
      >
        <template v-slot:nav-icon><Activity20 /></template>
        <span>{{ $t("status.title") }}</span>
      </cv-side-nav-link>
      <cv-side-nav-link
        @click="goToAppPage(instanceName, 'guide')"
        :class="{ 'current-page': isLinkActive('guide') }"
      >
        <template v-slot:nav-icon><Book20 /></template>
        <span>{{ $t("guide.title") }}</span>
      </cv-side-nav-link>
      <cv-side-nav-link
        @click="goToAppPage(instanceName, 'settings')"
        :class="{ 'current-page': isLinkActive('settings') }"
      >
        <template v-slot:nav-icon><Settings20 /></template>
        <span>{{ $t("settings.title") }}</span>
      </cv-side-nav-link>
      <cv-side-nav-link
        @click="goToAppPage(instanceName, 'deployments')"
        :class="{ 'current-page': isLinkActive('deployments') }"
      >
        <template v-slot:nav-icon><Deploy20 /></template>
        <span>{{ $t("deployments.title") }}</span>
      </cv-side-nav-link>
      <cv-side-nav-link
        @click="goToAppPage(instanceName, 'policies')"
        :class="{ 'current-page': isLinkActive('policies') }"
      >
        <template v-slot:nav-icon><Policy20 /></template>
        <span>{{ $t("policies.title") }}</span>
      </cv-side-nav-link>
      <cv-side-nav-link
        @click="goToAppPage(instanceName, 'logon')"
        :class="{ 'current-page': isLinkActive('logon') }"
      >
        <template v-slot:nav-icon><UserAccess20 /></template>
        <span>{{ $t("logon.title") }}</span>
      </cv-side-nav-link>
      <cv-side-nav-link
        @click="goToAppPage(instanceName, 'scripts')"
        :class="{ 'current-page': isLinkActive('scripts') }"
      >
        <template v-slot:nav-icon><Script20 /></template>
        <span>{{ $t("scripts.title") }}</span>
      </cv-side-nav-link>
      <cv-side-nav-link
        @click="goToAppPage(instanceName, 'dns')"
        :class="{ 'current-page': isLinkActive('dns') }"
      >
        <template v-slot:nav-icon><Dns20 /></template>
        <span>{{ $t("dns.title") }}</span>
      </cv-side-nav-link>
      <cv-side-nav-link
        @click="goToAppPage(instanceName, 'about')"
        :class="{ 'current-page': isLinkActive('about') }"
      >
        <template v-slot:nav-icon><Information20 /></template>
        <span>{{ $t("about.title") }}</span>
      </cv-side-nav-link>
    </cv-side-nav-items>
  </div>
</template>

<script>
import Settings20 from "@carbon/icons-vue/es/settings/20";
import Information20 from "@carbon/icons-vue/es/information/20";
import Activity20 from "@carbon/icons-vue/es/activity/20";
import Deploy20 from "@carbon/icons-vue/es/deploy/20";
import Policy20 from "@carbon/icons-vue/es/policy/20";
import UserAccess20 from "@carbon/icons-vue/es/user--access/20";
import Script20 from "@carbon/icons-vue/es/script/20";
import Dns20 from "@carbon/icons-vue/es/dns-services/20";
import Book20 from "@carbon/icons-vue/es/book/20";
import { mapState } from "vuex";
import { QueryParamService, UtilService } from "@nethserver/ns8-ui-lib";

export default {
  name: "AppSideMenuContent",
  components: {
    Settings20,
    Information20,
    Activity20,
    Deploy20,
    Policy20,
    UserAccess20,
    Script20,
    Dns20,
    Book20,
  },
  mixins: [QueryParamService, UtilService],
  data() {
    return {
      instanceNameSkeletonWidth: "70%",
    };
  },
  computed: {
    ...mapState(["instanceName", "instanceLabel", "core"]),
  },
  created() {
    // register to appNavigation event
    this.$root.$on("appNavigation", this.onAppNavigation);
  },
  beforeDestroy() {
    // remove event listener
    this.$root.$off("appNavigation");
  },
  methods: {
    isLinkActive(page) {
      return this.getPage() === page;
    },
    onAppNavigation() {
      // highlight current page in side menu
      this.$forceUpdate();
    },
  },
};
</script>

<style scoped lang="scss">
.instance-name span {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
</style>
