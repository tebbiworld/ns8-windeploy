<!--
  Copyright (C) 2026 tebbi
  SPDX-License-Identifier: GPL-3.0-or-later
-->
<template>
  <cv-grid fullWidth>
    <cv-row>
      <cv-column class="page-title">
        <h2>{{ $t("settings.title") }}</h2>
      </cv-column>
    </cv-row>
    <cv-row v-if="error.getConfiguration">
      <cv-column>
        <NsInlineNotification
          kind="error"
          :title="$t('action.get-configuration')"
          :description="error.getConfiguration"
          :showCloseButton="false"
        />
      </cv-column>
    </cv-row>
    <cv-row>
      <cv-column :md="4" :max="8">
        <cv-tile light>
          <h4 class="section-title">{{ $t("settings.connection_title") }}</h4>
          <p class="section-help">{{ $t("settings.connection_help") }}</p>
          <cv-form @submit.prevent="configureModule">
            <cv-dropdown
              :label="$t('settings.domain')"
              v-model="domain"
              :disabled="busy"
              class="field"
            >
              <cv-dropdown-item
                v-for="d in domains"
                :key="d.name"
                :value="d.name"
                >{{ d.name }}
                <span v-if="d.location === 'external'">
                  ({{ $t("settings.external") }})</span
                ></cv-dropdown-item
              >
              <cv-dropdown-item value="">{{
                $t("settings.other_domain")
              }}</cv-dropdown-item>
            </cv-dropdown>
            <template v-if="manualDc">
              <NsInlineNotification
                v-if="selectedDomain && selectedDomain.location === 'external'"
                kind="info"
                :title="$t('settings.external_title')"
                :description="$t('settings.external_desc')"
                :showCloseButton="false"
              />
              <NsTextInput
                :label="$t('settings.dc_host')"
                v-model.trim="dc_host"
                placeholder="dc01.ad.example.com"
                :helper-text="$t('settings.dc_host_helper')"
                :invalid-message="error.dc_host"
                :disabled="busy"
                ref="dc_host"
              />
              <NsTextInput
                :label="$t('settings.dc_ip')"
                v-model.trim="dc_ip"
                placeholder="192.168.1.10"
                :helper-text="$t('settings.dc_ip_helper')"
                :invalid-message="error.dc_ip"
                :disabled="busy"
                ref="dc_ip"
              />
              <NsTextInput
                :label="$t('settings.realm')"
                v-model.trim="realm"
                placeholder="AD.EXAMPLE.COM"
                :invalid-message="error.realm"
                :disabled="busy"
                ref="realm"
              />
              <NsTextInput
                :label="$t('settings.workgroup')"
                v-model.trim="workgroup"
                placeholder="EXAMPLE"
                :invalid-message="error.workgroup"
                :disabled="busy"
                ref="workgroup"
              />
            </template>
            <div v-else-if="effectiveDc" class="dc-info">
              {{ $t("settings.dc_from_domain", effectiveDc) }}
            </div>
            <NsTextInput
              :label="$t('settings.username')"
              v-model.trim="username"
              placeholder="svc-gpodeploy"
              :helper-text="$t('settings.username_helper')"
              :invalid-message="error.username"
              :disabled="busy"
              ref="username"
            />
            <NsTextInput
              :label="$t('settings.password')"
              type="password"
              v-model="password"
              :helper-text="
                password_set
                  ? $t('settings.password_keep')
                  : $t('settings.password_required')
              "
              :invalid-message="error.password"
              :disabled="busy"
              ref="password"
            />
            <cv-dropdown
              :label="$t('settings.default_delivery')"
              v-model="default_delivery"
              :disabled="busy"
              class="field"
            >
              <cv-dropdown-item value="sysvol">{{
                $t("delivery.sysvol")
              }}</cv-dropdown-item>
              <cv-dropdown-item value="embedded">{{
                $t("delivery.embedded")
              }}</cv-dropdown-item>
            </cv-dropdown>
            <NsInlineNotification
              v-if="error.configureModule"
              kind="error"
              :title="$t('action.configure-module')"
              :description="error.configureModule"
              :showCloseButton="false"
            />
            <NsButton
              kind="primary"
              :icon="Save20"
              :loading="loading.configureModule"
              :disabled="busy"
              >{{ $t("settings.save") }}</NsButton
            >
          </cv-form>
        </cv-tile>
      </cv-column>
      <cv-column :md="4" :max="8">
        <cv-tile light class="side-tile">
          <h4 class="section-title">{{ $t("settings.rights_title") }}</h4>
          <p class="section-help">{{ $t("settings.rights_help") }}</p>
          <cv-skeleton-text v-if="loading.getConfiguration" />
          <div v-else-if="!rights" class="section-help">
            {{ $t("settings.rights_unknown") }}
          </div>
          <ul v-else class="rights">
            <li v-for="key in rightKeys" :key="key">
              <CheckmarkFilled16 v-if="rights[key]" class="ok" />
              <WarningFilled16 v-else class="bad" />
              {{ $t("settings.right_" + key) }}
            </li>
          </ul>
          <NsInlineNotification
            v-if="rights && !allRights"
            kind="warning"
            :title="$t('settings.delegation_title')"
            :description="$t('settings.delegation_desc')"
            :showCloseButton="false"
          />
          <pre v-if="rights && !allRights" class="delegation">{{
            delegationCommands
          }}</pre>
        </cv-tile>
        <cv-tile light class="side-tile">
          <h4 class="section-title">{{ $t("settings.index_title") }}</h4>
          <p class="section-help">{{ $t("settings.index_help") }}</p>
          <div v-if="index.packages" class="index-info">
            <div>
              {{ $t("settings.index_packages", { n: index.packages }) }}
            </div>
            <div>
              {{
                $t("settings.index_cdn", {
                  date: formatDate(index.last_modified),
                })
              }}
            </div>
            <div>
              {{
                $t("settings.index_checked", {
                  date: formatDate(index.checked),
                })
              }}
            </div>
          </div>
          <div v-else class="section-help">
            {{ $t("settings.index_missing") }}
          </div>
          <NsInlineNotification
            v-if="error.refreshIndex"
            kind="error"
            :title="$t('action.refresh-index')"
            :description="error.refreshIndex"
            :showCloseButton="false"
          />
          <NsButton
            kind="secondary"
            :icon="Renew20"
            :loading="loading.refreshIndex"
            :disabled="loading.refreshIndex"
            @click="refreshIndex"
            >{{ $t("settings.index_refresh") }}</NsButton
          >
        </cv-tile>
      </cv-column>
    </cv-row>
  </cv-grid>
</template>

<script>
import { mapState } from "vuex";
import Renew20 from "@carbon/icons-vue/es/renew/20";
import CheckmarkFilled16 from "@carbon/icons-vue/es/checkmark--filled/16";
import WarningFilled16 from "@carbon/icons-vue/es/warning--filled/16";
import {
  QueryParamService,
  UtilService,
  IconService,
  PageTitleService,
} from "@nethserver/ns8-ui-lib";
import moduleTask from "@/mixins/moduleTask";

export default {
  name: "Settings",
  components: { CheckmarkFilled16, WarningFilled16 },
  mixins: [
    moduleTask,
    IconService,
    UtilService,
    QueryParamService,
    PageTitleService,
  ],
  pageTitle() {
    return this.$t("settings.title") + " - " + this.appName;
  },
  data() {
    return {
      q: { page: "settings" },
      urlCheckInterval: null,
      Renew20,
      domains: [],
      domain: "",
      dc_host: "",
      dc_ip: "",
      realm: "",
      workgroup: "",
      username: "",
      password: "",
      password_set: false,
      default_delivery: "sysvol",
      effective: {},
      rights: null,
      index: {},
      rightKeys: ["can_create_gpo", "can_link_domain", "sysvol"],
      loading: {
        getConfiguration: false,
        configureModule: false,
        refreshIndex: false,
      },
      error: {
        getConfiguration: "",
        configureModule: "",
        refreshIndex: "",
        dc_host: "",
        dc_ip: "",
        realm: "",
        workgroup: "",
        username: "",
        password: "",
      },
    };
  },
  computed: {
    ...mapState(["instanceName", "core", "appName"]),
    busy() {
      return this.loading.getConfiguration || this.loading.configureModule;
    },
    selectedDomain() {
      return this.domains.find((d) => d.name === this.domain);
    },
    manualDc() {
      return !this.selectedDomain || this.selectedDomain.providers.length === 0;
    },
    effectiveDc() {
      const p = this.selectedDomain && this.selectedDomain.providers[0];
      return p ? { host: p.hostname, ip: p.ip, realm: p.realm } : null;
    },
    allRights() {
      return this.rights && this.rightKeys.every((k) => this.rights[k]);
    },
    delegationCommands() {
      const sid = (this.rights && this.rights.account_sid) || "<SID>";
      const dn = (this.rights && this.rights.domain_dn) || "DC=...";
      return [
        `samba-tool dsacl set --objectdn="CN=Policies,CN=System,${dn}" \\`,
        `  --sddl="(OA;;CC;f30e3bc2-9ff0-11d1-b603-0000f80367c1;;${sid})"`,
        `samba-tool dsacl set --objectdn="${dn}" \\`,
        `  --sddl="(OA;;RPWP;f30e3bbe-9ff0-11d1-b603-0000f80367c1;;${sid})"`,
        `samba-tool dsacl set --objectdn="${dn}" \\`,
        `  --sddl="(OA;;RPWP;f30e3bbf-9ff0-11d1-b603-0000f80367c1;;${sid})"`,
      ].join("\n");
    },
  },
  beforeRouteEnter(to, from, next) {
    next((vm) => {
      vm.watchQueryData(vm);
      vm.urlCheckInterval = vm.initUrlBindingForApp(vm, vm.q.page);
    });
  },
  beforeRouteLeave(to, from, next) {
    clearInterval(this.urlCheckInterval);
    next();
  },
  created() {
    this.getConfiguration();
  },
  methods: {
    formatDate(iso) {
      if (!iso) return "-";
      const d = new Date(iso);
      return isNaN(d) ? iso : d.toLocaleString();
    },
    async getConfiguration() {
      this.loading.getConfiguration = true;
      this.error.getConfiguration = "";
      try {
        const c = await this.runModuleTask("get-configuration");
        this.domains = c.domains || [];
        this.domain =
          c.domain || (this.domains[0] && this.domains[0].name) || "";
        this.dc_host = c.dc_host;
        this.dc_ip = c.dc_ip;
        this.realm = c.realm;
        this.workgroup = c.workgroup;
        this.username = c.username;
        this.password = "";
        this.password_set = c.password_set;
        this.default_delivery = c.default_delivery || "sysvol";
        this.effective = c.effective || {};
        this.rights = c.rights;
        this.index = c.index || {};
      } catch (e) {
        this.error.getConfiguration = e.error || this.$t("error.generic_error");
      } finally {
        this.loading.getConfiguration = false;
      }
    },
    validate() {
      this.clearErrors(this);
      const required = ["username"];
      if (this.manualDc)
        required.push("dc_host", "dc_ip", "realm", "workgroup");
      if (!this.password_set) required.push("password");
      let ok = true;
      for (const f of required) {
        if (!this[f]) {
          this.error[f] = this.$t("common.required");
          if (ok) this.focusElement(f);
          ok = false;
        }
      }
      return ok;
    },
    async configureModule() {
      if (!this.validate()) return;
      this.loading.configureModule = true;
      this.error.configureModule = "";
      const manual = this.manualDc;
      try {
        await this.runModuleTask(
          "configure-module",
          {
            domain: this.domain,
            dc_host: manual ? this.dc_host : "",
            dc_ip: manual ? this.dc_ip : "",
            realm: manual ? this.realm : "",
            workgroup: manual ? this.workgroup : "",
            username: this.username,
            password: this.password,
            default_delivery: this.default_delivery,
          },
          {
            title: this.$t("settings.configure_instance", {
              instance: this.instanceName,
            }),
            hidden: false,
          }
        );
        this.getConfiguration();
      } catch (e) {
        if (e.validation) {
          for (const v of e.validation) {
            const field = v.field in this.error ? v.field : "configureModule";
            this.error[field] = this.$t("settings.error_" + v.error);
          }
        } else {
          this.error.configureModule = this.$t("error.generic_error");
        }
      } finally {
        this.loading.configureModule = false;
      }
    },
    async refreshIndex() {
      this.loading.refreshIndex = true;
      this.error.refreshIndex = "";
      try {
        this.index = await this.runModuleTask("refresh-index");
      } catch (e) {
        this.error.refreshIndex = this.$t("settings.index_refresh_failed");
      } finally {
        this.loading.refreshIndex = false;
      }
    },
  },
};
</script>

<style scoped lang="scss">
@import "../styles/carbon-utils";
.section-title {
  margin-bottom: $spacing-03;
}
.section-help {
  margin-bottom: $spacing-06;
}
.field {
  margin-bottom: $spacing-06;
}
.dc-info {
  margin-bottom: $spacing-06;
  color: $text-02;
}
.side-tile {
  margin-bottom: $spacing-06;
}
.rights {
  margin-bottom: $spacing-05;
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
.delegation {
  font-family: "IBM Plex Mono", monospace;
  font-size: 0.75rem;
  white-space: pre-wrap;
  word-break: break-all;
  margin: $spacing-05 0;
  padding: $spacing-04;
  background: $ui-01;
}
.index-info {
  margin-bottom: $spacing-05;
  div {
    margin-bottom: $spacing-02;
  }
}
</style>
