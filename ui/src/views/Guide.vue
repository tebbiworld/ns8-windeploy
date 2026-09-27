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
          <p class="help">
            {{ $t("guide.auto_help") }}
            <cv-link @click="goToAppPage(instanceName, 'settings')">{{
              $t("settings.title")
            }}</cv-link>
          </p>

          <h5 class="sub">{{ $t("guide.manual_title") }}</h5>
          <p class="help">{{ $t("guide.manual_help") }}</p>
          <pre class="code">{{ manualCommands }}</pre>
          <p class="help">{{ $t("guide.manual_ou") }}</p>
        </cv-tile>

        <cv-tile light class="tile">
          <h4>{{ $t("guide.options_title") }}</h4>
          <h5 class="sub first">{{ $t("deployments.delivery") }}</h5>
          <dl class="options">
            <dt>{{ $t("delivery.sysvol") }}</dt>
            <dd>{{ $t("guide.delivery_sysvol") }}</dd>
            <dt>{{ $t("delivery.embedded") }}</dt>
            <dd>{{ $t("guide.delivery_embedded") }}</dd>
          </dl>
          <p class="help">{{ $t("guide.delivery_choice") }}</p>
          <h5 class="sub">{{ $t("deployments.links") }}</h5>
          <dl class="options">
            <dt>{{ $t("guide.link_domain_title") }}</dt>
            <dd>{{ $t("guide.link_domain") }}</dd>
            <dt>{{ $t("guide.link_ou_title") }}</dt>
            <dd>{{ $t("guide.link_ou") }}</dd>
          </dl>
          <p class="help">{{ $t("guide.link_computers") }}</p>
          <h5 class="sub">{{ $t("deployments.packages") }}</h5>
          <dl class="options">
            <dt>{{ $t("mode.upgrade") }}</dt>
            <dd>{{ $t("guide.mode_upgrade") }}</dd>
            <dt>{{ $t("mode.install") }}</dt>
            <dd>{{ $t("guide.mode_install") }}</dd>
          </dl>
          <p class="help">{{ $t("guide.mode_msi") }}</p>
        </cv-tile>

        <cv-tile light class="tile">
          <h4>{{ $t("guide.clients_title") }}</h4>
          <ul class="bullets">
            <li v-for="n in 3" :key="n">{{ $t("guide.clients_" + n) }}</li>
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
      config: {},
      // domain and account name for the manual commands
      setup: { domain: "", username: "svc-windeploy" },
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
.options {
  margin-bottom: $spacing-04;
  dt {
    font-weight: 600;
    margin-top: $spacing-03;
  }
  dd {
    margin: $spacing-02 0 0 0;
  }
}
.sub.first {
  margin-top: $spacing-03;
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
