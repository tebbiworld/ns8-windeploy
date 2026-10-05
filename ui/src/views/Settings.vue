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
      <!-- left: connection, package index -->
      <cv-column :md="4" :max="8">
        <cv-tile light class="tile">
          <h4 class="section-title">{{ $t("settings.connection_title") }}</h4>
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
              placeholder="svc-windeploy"
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
        <cv-tile light class="tile">
          <h4 class="section-title">{{ $t("settings.index_title") }}</h4>
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
          <div v-else class="muted index-info">
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

      <!-- right: rights check, automatic setup -->
      <cv-column :md="4" :max="8">
        <cv-tile light class="tile">
          <h4 class="section-title">{{ $t("settings.rights_title") }}</h4>
          <RightsCheck
            :rights="rights"
            :username="rights ? username : ''"
            :loading="loading.getConfiguration"
          />
          <template v-if="rights && !allRights">
            <NsInlineNotification
              kind="warning"
              :title="$t('settings.delegation_title')"
              :description="$t('settings.delegation_short')"
              :showCloseButton="false"
            />
            <pre class="code">{{ delegationCommands }}</pre>
          </template>
        </cv-tile>
        <cv-tile light class="tile">
          <h4 class="section-title">{{ $t("guide.auto_title") }}</h4>
          <NsInlineNotification
            v-if="allRights"
            kind="success"
            :title="$t('guide.account_ok_title')"
            :description="$t('guide.account_ok_desc', { user: username })"
            :showCloseButton="false"
          />
          <p class="muted help">
            {{ $t("settings.auto_see_guide") }}
            <cv-link @click="goToAppPage(instanceName, 'guide')">{{
              $t("guide.title")
            }}</cv-link>
          </p>
          <p v-if="!internalDomains.length" class="muted help">
            {{ $t("guide.auto_no_domain") }}
          </p>
          <cv-form v-else @submit.prevent="setupAccount">
            <cv-dropdown
              :label="$t('settings.domain')"
              v-model="setup.domain"
              class="field"
            >
              <cv-dropdown-item
                v-for="d in internalDomains"
                :key="d.name"
                :value="d.name"
                >{{ d.name }}</cv-dropdown-item
              >
            </cv-dropdown>
            <NsTextInput
              :label="$t('guide.admin_user')"
              v-model.trim="setup.admin_user"
              placeholder="administrator"
              :helper-text="$t('guide.admin_user_helper')"
              :invalid-message="error.admin_user"
              ref="admin_user"
            />
            <NsTextInput
              :label="$t('guide.admin_password')"
              type="password"
              v-model="setup.admin_password"
              :helper-text="$t('guide.admin_password_helper')"
              :invalid-message="error.admin_password"
              ref="admin_password"
            />
            <NsTextInput
              :label="$t('settings.username')"
              v-model.trim="setup.username"
              :invalid-message="error.setup_username"
              ref="setup_username"
            />
            <NsInlineNotification
              v-if="error.setup"
              kind="error"
              :title="$t('action.setup-service-account')"
              :description="error.setup"
              :showCloseButton="false"
            />
            <NsInlineNotification
              v-if="setupDone"
              kind="success"
              :title="$t('guide.auto_done_title')"
              :description="$t('guide.auto_done_desc', { user: setupDone })"
              :showCloseButton="false"
            />
            <NsButton
              kind="secondary"
              :icon="UserFollow20"
              :loading="loading.setup"
              :disabled="loading.setup"
              >{{ $t("guide.auto_button") }}</NsButton
            >
          </cv-form>
        </cv-tile>
      </cv-column>
    </cv-row>
  </cv-grid>
</template>

<script>
import { mapState } from "vuex";
import Renew20 from "@carbon/icons-vue/es/renew/20";
import UserFollow20 from "@carbon/icons-vue/es/user--follow/20";
import {
  QueryParamService,
  UtilService,
  IconService,
  PageTitleService,
} from "@nethserver/ns8-ui-lib";
import moduleTask from "@/mixins/moduleTask";
import RightsCheck, { rightsComplete } from "@/components/RightsCheck";

export default {
  name: "Settings",
  components: { RightsCheck },
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
      UserFollow20,
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
      rights: null,
      index: {},
      setup: {
        domain: "",
        admin_user: "administrator",
        admin_password: "",
        username: "svc-windeploy",
      },
      setupDone: "",
      loading: {
        getConfiguration: false,
        configureModule: false,
        refreshIndex: false,
        setup: false,
      },
      error: {
        getConfiguration: "",
        configureModule: "",
        refreshIndex: "",
        setup: "",
        dc_host: "",
        dc_ip: "",
        realm: "",
        workgroup: "",
        username: "",
        password: "",
        admin_user: "",
        admin_password: "",
        setup_username: "",
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
    internalDomains() {
      return this.domains.filter((d) => d.location === "internal");
    },
    manualDc() {
      return !this.selectedDomain || this.selectedDomain.providers.length === 0;
    },
    effectiveDc() {
      const p = this.selectedDomain && this.selectedDomain.providers[0];
      return p ? { host: p.hostname, ip: p.ip, realm: p.realm } : null;
    },
    allRights() {
      return rightsComplete(this.rights);
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
        `samba-tool dsacl set --objectdn="${dn}" \\`,
        `  --sddl="(OA;CIIO;RPWP;f30e3bbe-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;${sid})"`,
        `samba-tool dsacl set --objectdn="${dn}" \\`,
        `  --sddl="(OA;CIIO;RPWP;f30e3bbf-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;${sid})"`,
        `samba-tool dsacl set --objectdn="${dn}" \\`,
        `  --sddl="(OA;;CC;bf967aa5-0de6-11d0-a285-00aa003049e2;;${sid})"`,
        `samba-tool dsacl set --objectdn="${dn}" \\`,
        `  --sddl="(OA;CIIO;CC;bf967aa5-0de6-11d0-a285-00aa003049e2;bf967aa5-0de6-11d0-a285-00aa003049e2;${sid})"`,
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
        this.rights = c.rights;
        this.index = c.index || {};
        const own = this.internalDomains.find((d) => d.name === this.domain);
        this.setup.domain = (own || this.internalDomains[0] || {}).name || "";
        if (c.username) this.setup.username = c.username;
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
    async setupAccount() {
      this.clearErrors(this);
      this.setupDone = "";
      const fields = {
        admin_user: this.setup.admin_user,
        admin_password: this.setup.admin_password,
        setup_username: this.setup.username,
      };
      let ok = true;
      for (const [f, v] of Object.entries(fields)) {
        if (!v) {
          this.error[f] = this.$t("common.required");
          if (ok) this.focusElement(f);
          ok = false;
        }
      }
      if (!ok) return;
      this.loading.setup = true;
      try {
        const res = await this.runModuleTask(
          "setup-service-account",
          {
            domain: this.setup.domain,
            admin_user: this.setup.admin_user,
            admin_password: this.setup.admin_password,
            username: this.setup.username,
          },
          {
            title: this.$t("guide.auto_task", { user: this.setup.username }),
            hidden: false,
          }
        );
        this.setupDone = res.username;
        this.getConfiguration();
      } catch (e) {
        if (e.validation) {
          const v = e.validation[0];
          const field = v.field in this.error ? v.field : "setup";
          this.error[field] = this.$t("guide.error_" + v.error);
        } else {
          this.error.setup = this.$t("guide.error_setup_failed");
        }
      } finally {
        // never keep the admin password in the page
        this.setup.admin_password = "";
        this.loading.setup = false;
      }
    },
  },
};
</script>

<style scoped lang="scss">
@import "../styles/carbon-utils";
.tile {
  margin-bottom: $spacing-06;
}
.section-title {
  margin-bottom: $spacing-05;
}
.help {
  margin-bottom: $spacing-05;
}
.field {
  margin-bottom: $spacing-06;
}
.dc-info {
  margin-bottom: $spacing-06;
  color: $text-02;
}
.muted {
  color: $text-02;
}
.index-info {
  margin-bottom: $spacing-05;
  div {
    margin-bottom: $spacing-02;
  }
}
.code {
  font-family: "IBM Plex Mono", monospace;
  font-size: 0.75rem;
  white-space: pre-wrap;
  word-break: break-all;
  margin: $spacing-05 0;
  padding: $spacing-04;
  background: $ui-01;
}
</style>
