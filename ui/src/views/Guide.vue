<!--
  Copyright (C) 2026 tebbi
  SPDX-License-Identifier: GPL-3.0-or-later
-->
<template>
  <cv-grid fullWidth>
    <cv-row>
      <cv-column class="page-title">
        <h2>{{ $t("guide.title") }}</h2>
      </cv-column>
    </cv-row>
    <cv-row>
      <cv-column :md="8" :max="12">
        <cv-tile light class="tile">
          <h4>{{ $t("guide.how_title") }}</h4>
          <ol class="steps">
            <li v-for="n in 5" :key="n">{{ $t("guide.how_" + n) }}</li>
          </ol>
        </cv-tile>

        <cv-tile light class="tile">
          <h4>{{ $t("guide.account_title") }}</h4>
          <p class="help">{{ $t("guide.account_help") }}</p>
          <ul class="bullets">
            <li>{{ $t("guide.right_group") }}</li>
            <li>{{ $t("guide.right_create") }}</li>
            <li>{{ $t("guide.right_link") }}</li>
          </ul>
          <NsInlineNotification
            v-if="rightsOk"
            kind="success"
            :title="$t('guide.account_ok_title')"
            :description="
              $t('guide.account_ok_desc', { user: config.username })
            "
            :showCloseButton="false"
          />

          <h5 class="sub">{{ $t("guide.auto_title") }}</h5>
          <p class="help">{{ $t("guide.auto_help") }}</p>
          <cv-form @submit.prevent="setupAccount">
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
            <p v-if="!internalDomains.length" class="help">
              {{ $t("guide.auto_no_domain") }}
            </p>
            <NsTextInput
              :label="$t('guide.admin_user')"
              v-model.trim="setup.admin_user"
              placeholder="administrator"
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
              :helper-text="$t('guide.username_helper')"
              :invalid-message="error.username"
              ref="username"
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
              kind="primary"
              :icon="UserFollow20"
              :loading="loading.setup"
              :disabled="loading.setup || !internalDomains.length"
              >{{ $t("guide.auto_button") }}</NsButton
            >
          </cv-form>

          <h5 class="sub">{{ $t("guide.manual_title") }}</h5>
          <p class="help">{{ $t("guide.manual_help") }}</p>
          <pre class="code">{{ manualCommands }}</pre>
          <p class="help">{{ $t("guide.manual_ou") }}</p>
        </cv-tile>

        <cv-tile light class="tile">
          <h4>{{ $t("guide.clients_title") }}</h4>
          <ul class="bullets">
            <li v-for="n in 4" :key="n">{{ $t("guide.clients_" + n) }}</li>
          </ul>
        </cv-tile>

        <cv-tile light class="tile">
          <h4>{{ $t("guide.check_title") }}</h4>
          <p class="help">{{ $t("guide.check_help") }}</p>
          <pre class="code">{{ checkCommands }}</pre>
        </cv-tile>

        <cv-tile light class="tile">
          <h4>{{ $t("guide.timing_title") }}</h4>
          <ul class="bullets">
            <li v-for="n in 3" :key="n">{{ $t("guide.timing_" + n) }}</li>
          </ul>
        </cv-tile>
      </cv-column>
    </cv-row>
  </cv-grid>
</template>

<script>
import { mapState } from "vuex";
import UserFollow20 from "@carbon/icons-vue/es/user--follow/20";
import {
  QueryParamService,
  UtilService,
  IconService,
  PageTitleService,
} from "@nethserver/ns8-ui-lib";
import moduleTask from "@/mixins/moduleTask";

export default {
  name: "Guide",
  mixins: [
    moduleTask,
    IconService,
    UtilService,
    QueryParamService,
    PageTitleService,
  ],
  pageTitle() {
    return this.$t("guide.title") + " - " + this.appName;
  },
  data() {
    return {
      q: { page: "guide" },
      urlCheckInterval: null,
      UserFollow20,
      config: {},
      setup: {
        domain: "",
        admin_user: "administrator",
        admin_password: "",
        username: "svc-windeploy",
      },
      setupDone: "",
      loading: { setup: false },
      error: { setup: "", admin_user: "", admin_password: "", username: "" },
    };
  },
  computed: {
    ...mapState(["instanceName", "core", "appName"]),
    internalDomains() {
      return (this.config.domains || []).filter(
        (d) => d.location === "internal"
      );
    },
    rightsOk() {
      const r = this.config.rights;
      return r && r.can_create_gpo && r.can_link_domain && r.sysvol;
    },
    domainInfo() {
      const d = this.internalDomains.find((x) => x.name === this.setup.domain);
      const p = d && d.providers[0];
      const realm =
        (p && p.realm) ||
        (this.config.effective && this.config.effective.realm) ||
        "AD.EXAMPLE.COM";
      const dn = realm
        .toLowerCase()
        .split(".")
        .map((part) => "DC=" + part)
        .join(",");
      return { module: (p && p.module_id) || "samba1", dn };
    },
    manualCommands() {
      const m = this.domainInfo.module;
      const dn = this.domainInfo.dn;
      const u = this.setup.username || "svc-windeploy";
      const run = `runagent -m ${m} podman exec`;
      return [
        `# 1. ${this.$t("guide.cmd_create")}`,
        `${run} -it samba-dc samba-tool user create ${u}`,
        `${run} samba-dc samba-tool user setexpiry ${u} --noexpiry`,
        `# 2. ${this.$t("guide.cmd_group")}`,
        `${run} samba-dc samba-tool group addmembers "Group Policy Creator Owners" ${u}`,
        `# 3. ${this.$t("guide.cmd_sid")}`,
        `SID=$(${run} samba-dc samba-tool user show ${u} --attributes=objectSid | sed -n 's/^objectSid: //p')`,
        `# 4. ${this.$t("guide.cmd_delegate")}`,
        `${run} samba-dc samba-tool dsacl set --objectdn="CN=Policies,CN=System,${dn}" --sddl="(OA;;CC;f30e3bc2-9ff0-11d1-b603-0000f80367c1;;$SID)"`,
        `${run} samba-dc samba-tool dsacl set --objectdn="${dn}" --sddl="(OA;;RPWP;f30e3bbe-9ff0-11d1-b603-0000f80367c1;;$SID)"`,
        `${run} samba-dc samba-tool dsacl set --objectdn="${dn}" --sddl="(OA;;RPWP;f30e3bbf-9ff0-11d1-b603-0000f80367c1;;$SID)"`,
      ].join("\n");
    },
    checkCommands() {
      return [
        "gpupdate /target:computer /force",
        "gpresult /scope computer /r",
        'Get-ScheduledTask -TaskName "windeploy*" | Get-ScheduledTaskInfo',
        'Start-ScheduledTask -TaskName "windeploy <Paket-ID>"',
        "Get-Content C:\\Windows\\Temp\\windeploy-<Paket-ID>.log -Tail 30",
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
    this.loadConfig();
  },
  methods: {
    async loadConfig() {
      try {
        this.config = await this.runModuleTask("get-configuration");
        const current = this.config.domain;
        this.setup.domain =
          (
            this.internalDomains.find((d) => d.name === current) ||
            this.internalDomains[0] ||
            {}
          ).name || "";
        if (this.config.username) this.setup.username = this.config.username;
      } catch (e) {
        this.config = {};
      }
    },
    async setupAccount() {
      this.clearErrors(this);
      this.setupDone = "";
      let ok = true;
      for (const f of ["admin_user", "admin_password", "username"]) {
        if (!this.setup[f]) {
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
        this.loadConfig();
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
h4 {
  margin-bottom: $spacing-04;
}
.sub {
  margin: $spacing-07 0 $spacing-03 0;
}
.help {
  margin-bottom: $spacing-05;
}
.field {
  margin-bottom: $spacing-06;
}
.steps,
.bullets {
  margin: 0 0 $spacing-05 $spacing-06;
  li {
    margin-bottom: $spacing-03;
  }
}
.steps {
  list-style: decimal;
}
.bullets {
  list-style: disc;
}
.code {
  font-family: "IBM Plex Mono", monospace;
  font-size: 0.75rem;
  white-space: pre-wrap;
  word-break: break-all;
  padding: $spacing-04;
  background: $ui-01;
  margin-bottom: $spacing-05;
}
</style>
