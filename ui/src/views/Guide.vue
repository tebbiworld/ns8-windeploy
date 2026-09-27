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
          <ul class="bullets">
            <li v-for="n in 6" :key="n">{{ $t("guide.how_" + n) }}</li>
          </ul>
        </cv-tile>

        <cv-tile light class="tile">
          <h4>{{ $t("guide.account_title") }}</h4>
          <p class="help">{{ $t("guide.account_help") }}</p>
          <ul class="bullets">
            <li>{{ $t("guide.right_group") }}</li>
            <li>{{ $t("guide.right_create") }}</li>
            <li>{{ $t("guide.right_link") }}</li>
          </ul>

          <h5 class="sub">{{ $t("guide.auto_heading") }}</h5>
          <i18n path="guide.auto_help" tag="p" class="help">
            <template v-slot:settings>
              <cv-link @click="goToAppPage(instanceName, 'settings')">{{
                $t("settings.title")
              }}</cv-link>
            </template>
          </i18n>

          <h5 class="sub">{{ $t("guide.manual_title") }}</h5>
          <p class="help">{{ $t("guide.manual_help") }}</p>
          <ol class="manual-steps">
            <li v-for="(step, i) in manualSteps" :key="i">
              <p class="step-text">{{ step.text }}</p>
              <pre class="code">{{ step.commands.join("\n") }}</pre>
            </li>
          </ol>
          <i18n path="guide.manual_ou" tag="p" class="help">
            <template v-slot:settings>
              <cv-link @click="goToAppPage(instanceName, 'settings')">{{
                $t("settings.title")
              }}</cv-link>
            </template>
          </i18n>

          <h5 class="sub">{{ $t("guide.switch_heading") }}</h5>
          <p class="help">{{ $t("guide.switch_help") }}</p>
        </cv-tile>

        <cv-tile light class="tile">
          <h4>{{ $t("guide.clients_title") }}</h4>
          <ul class="bullets">
            <li v-for="n in 4" :key="n">{{ $t("guide.clients_" + n) }}</li>
          </ul>
        </cv-tile>

        <cv-tile light class="tile">
          <h4>{{ $t("guide.options_title") }}</h4>

          <h5 class="sub first">{{ $t("guide.delivery_heading") }}</h5>
          <i18n path="guide.delivery_choice" tag="p" class="help">
            <template v-slot:settings>
              <cv-link @click="goToAppPage(instanceName, 'settings')">{{
                $t("settings.title")
              }}</cv-link>
            </template>
          </i18n>
          <dl class="options">
            <dt>{{ $t("delivery.sysvol") }}</dt>
            <dd>{{ $t("guide.delivery_sysvol") }}</dd>
            <dt>{{ $t("delivery.embedded") }}</dt>
            <dd>{{ $t("guide.delivery_embedded") }}</dd>
          </dl>

          <h5 class="sub">{{ $t("guide.link_heading") }}</h5>
          <dl class="options">
            <dt>{{ $t("guide.link_domain_title") }}</dt>
            <dd>{{ $t("guide.link_domain") }}</dd>
            <dt>{{ $t("guide.link_ou_title") }}</dt>
            <dd>{{ $t("guide.link_ou") }}</dd>
          </dl>
          <p class="help">{{ $t("guide.link_computers") }}</p>

          <h5 class="sub">{{ $t("guide.mode_heading") }}</h5>
          <dl class="options">
            <dt>{{ $t("mode.upgrade") }}</dt>
            <dd>{{ $t("guide.mode_upgrade") }}</dd>
            <dt>{{ $t("mode.install") }}</dt>
            <dd>{{ $t("guide.mode_install") }}</dd>
          </dl>
          <p class="help">{{ $t("guide.mode_msi") }}</p>
        </cv-tile>

        <cv-tile light class="tile">
          <h4>{{ $t("guide.check_title") }}</h4>
          <p class="help">{{ $t("guide.check_help") }}</p>
          <pre class="code">{{ checkCommands }}</pre>
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
    manualSteps() {
      const m = this.domainInfo.module;
      const dn = this.domainInfo.dn;
      const u = this.setup.username || "svc-windeploy";
      const g = "windeploy-admins";
      const run = `runagent -m ${m} podman exec`;
      const acl = (objdn, ace) =>
        `${run} samba-dc samba-tool dsacl set --objectdn="${objdn}" --sddl="${ace}"`;
      const OU = "bf967aa5-0de6-11d0-a285-00aa003049e2";
      const GPLINK = "f30e3bbe-9ff0-11d1-b603-0000f80367c1";
      const GPOPT = "f30e3bbf-9ff0-11d1-b603-0000f80367c1";
      return [
        {
          text: this.$t("guide.cmd_create"),
          commands: [
            `${run} -it samba-dc samba-tool user create ${u}`,
            `${run} samba-dc samba-tool user setexpiry ${u} --noexpiry`,
          ],
        },
        {
          text: this.$t("guide.cmd_group"),
          commands: [
            `${run} samba-dc samba-tool group add ${g}`,
            `${run} samba-dc samba-tool group addmembers ${g} ${u}`,
            `${run} samba-dc samba-tool group addmembers "Group Policy Creator Owners" ${g}`,
          ],
        },
        {
          text: this.$t("guide.cmd_sid"),
          commands: [
            `SID=$(${run} samba-dc samba-tool group show ${g} --attributes=objectSid | sed -n 's/^objectSid: //p')`,
          ],
        },
        {
          text: this.$t("guide.cmd_gpo"),
          commands: [
            acl(
              `CN=Policies,CN=System,${dn}`,
              "(OA;;CC;f30e3bc2-9ff0-11d1-b603-0000f80367c1;;$SID)"
            ),
          ],
        },
        {
          text: this.$t("guide.cmd_link"),
          commands: [
            acl(dn, `(OA;;RPWP;${GPLINK};;$SID)`),
            acl(dn, `(OA;;RPWP;${GPOPT};;$SID)`),
          ],
        },
        {
          text: this.$t("guide.cmd_link_ous"),
          commands: [
            acl(dn, `(OA;CIIO;RPWP;${GPLINK};${OU};$SID)`),
            acl(dn, `(OA;CIIO;RPWP;${GPOPT};${OU};$SID)`),
          ],
        },
        {
          text: this.$t("guide.cmd_create_ou"),
          commands: [
            acl(dn, `(OA;;CC;${OU};;$SID)`),
            acl(dn, `(OA;CIIO;CC;${OU};${OU};$SID)`),
          ],
        },
      ];
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
.manual-steps {
  list-style: decimal;
  margin: 0 0 $spacing-05 $spacing-06;
  li {
    margin-bottom: $spacing-05;
  }
  .step-text {
    margin-bottom: $spacing-03;
  }
  .code {
    margin-bottom: 0;
  }
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
