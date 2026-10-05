<!--
  Copyright (C) 2026 tebbi
  SPDX-License-Identifier: GPL-3.0-or-later
-->
<template>
  <cv-grid fullWidth>
    <cv-row>
      <cv-column class="page-title">
        <h2>{{ $t("policies.title") }}</h2>
      </cv-column>
    </cv-row>
    <cv-row>
      <cv-column>
        <p class="page-help">{{ $t("policies.help") }}</p>
      </cv-column>
    </cv-row>
    <cv-row v-if="error.list">
      <cv-column>
        <NsInlineNotification
          kind="error"
          :title="$t('action.list-policies')"
          :description="error.list"
          :showCloseButton="false"
        />
      </cv-column>
    </cv-row>

    <!-- what the domain itself says -->
    <cv-row v-if="domain">
      <cv-column>
        <cv-tile light class="domain">
          <h4>{{ $t("policies.domain_title") }}</h4>
          <p class="muted small">{{ $t("policies.domain_help") }}</p>
          <dl class="facts">
            <dt>{{ $t("policies.domain_password") }}</dt>
            <dd>
              {{
                $t("policies.domain_password_value", {
                  length: domain.min_password_length,
                  history: domain.password_history,
                  age:
                    domain.max_password_age_days === null
                      ? "∞"
                      : domain.max_password_age_days,
                })
              }}
              <span v-if="domain.password_complexity">{{
                $t("policies.domain_complexity")
              }}</span>
            </dd>
            <dt>{{ $t("policies.domain_lockout") }}</dt>
            <dd v-if="domain.lockout_threshold">
              {{
                $t("policies.domain_lockout_value", {
                  n: domain.lockout_threshold,
                  minutes: domain.lockout_duration_minutes,
                })
              }}
            </dd>
            <dd v-else class="warn">{{ $t("policies.domain_no_lockout") }}</dd>
            <dt>{{ $t("policies.domain_bitlocker") }}</dt>
            <dd v-if="domain.bitlocker_schema">
              {{ $t("policies.domain_bitlocker_yes") }}
            </dd>
            <dd v-else class="warn">
              {{ $t("policies.domain_bitlocker_no") }}
            </dd>
          </dl>
        </cv-tile>
      </cv-column>
    </cv-row>

    <cv-row>
      <cv-column class="toolbar">
        <NsButton kind="primary" :icon="Add20" @click="openEditor(null)">{{
          $t("policies.new")
        }}</NsButton>
        <NsButton
          kind="ghost"
          :icon="Renew20"
          :loading="loading.list"
          :disabled="loading.list"
          @click="listPolicies"
          >{{ $t("deployments.reload") }}</NsButton
        >
      </cv-column>
    </cv-row>
    <cv-row>
      <cv-column>
        <cv-tile light>
          <cv-skeleton-text
            v-if="loading.list && !profiles.length"
            :paragraph="true"
            :line-count="4"
          />
          <NsEmptyState
            v-else-if="!profiles.length"
            :title="$t('policies.empty')"
          >
            <template #description>{{ $t("policies.empty_desc") }}</template>
          </NsEmptyState>
          <table v-else class="profiles">
            <thead>
              <tr>
                <th>{{ $t("deployments.name") }}</th>
                <th>{{ $t("policies.settings") }}</th>
                <th>{{ $t("deployments.links") }}</th>
                <th>{{ $t("deployments.gpo") }}</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="p in profiles" :key="p.id">
                <td class="name">
                  {{ p.name }}
                  <div v-if="p.pending_delete" class="warn small">
                    {{
                      $t("removal.pending", {
                        date: formatDate(p.pending_delete.until),
                      })
                    }}
                  </div>
                  <div v-if="p.pending_delete" class="muted small">
                    {{ p.pending_delete.reason }}
                  </div>
                </td>
                <td>
                  <div v-for="s in settingList(p)" :key="s.id" class="setting">
                    {{ $t("policy_setting." + s.id + ".title") }}
                    <span v-if="s.detail" class="muted">{{ s.detail }}</span>
                    <span v-if="s.state === 'reset'" class="tag">{{
                      $t("policies.reset_tag")
                    }}</span>
                  </div>
                </td>
                <td>
                  <div v-for="dn in p.link_targets" :key="dn" class="dn">
                    {{ dn }}
                  </div>
                  <span v-if="!p.link_targets.length" class="muted">{{
                    $t("deployments.not_linked")
                  }}</span>
                </td>
                <td>
                  <div>
                    {{ $t("deployments.version", { v: p.version & 0xffff }) }}
                  </div>
                  <div class="muted guid">{{ p.gpo_guid }}</div>
                  <div class="muted small">{{ formatDate(p.changed) }}</div>
                </td>
                <td v-if="p.pending_delete" class="actions">
                  <NsButton
                    kind="ghost"
                    size="small"
                    :icon="Undo20"
                    @click="askRemove(p, 'cancel')"
                    >{{ $t("removal.button_cancel") }}</NsButton
                  >
                  <NsButton
                    kind="ghost"
                    size="small"
                    :icon="TrashCan20"
                    :disabled="!isDue(p.pending_delete)"
                    @click="askRemove(p, 'delete')"
                    >{{ $t("removal.button_delete") }}</NsButton
                  >
                </td>
                <td v-else class="actions">
                  <NsButton
                    kind="ghost"
                    size="small"
                    :icon="Edit20"
                    @click="openEditor(p)"
                    >{{ $t("deployments.edit") }}</NsButton
                  >
                  <NsButton
                    kind="ghost"
                    size="small"
                    :icon="TrashCan20"
                    @click="askRemove(p, 'start')"
                    >{{ $t("deployments.remove") }}</NsButton
                  >
                </td>
              </tr>
            </tbody>
          </table>
        </cv-tile>
      </cv-column>
    </cv-row>

    <!-- change log -->
    <cv-row v-if="log.length">
      <cv-column>
        <cv-tile light>
          <h4>{{ $t("policies.log_title") }}</h4>
          <table class="profiles">
            <thead>
              <tr>
                <th>{{ $t("policies.log_time") }}</th>
                <th>{{ $t("deployments.name") }}</th>
                <th>{{ $t("policies.log_change") }}</th>
                <th>{{ $t("policies.reason") }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="(l, i) in log" :key="i">
                <td class="nowrap">{{ formatDate(l.time) }}</td>
                <td>{{ l.profile }}</td>
                <td>
                  {{ $t("policies.change_" + l.change) }}
                  <div v-if="l.renamed_from" class="muted small">
                    {{ $t("policies.renamed_from", { name: l.renamed_from }) }}
                  </div>
                  <div v-for="d in logDiff(l)" :key="d" class="muted small">
                    {{ d }}
                  </div>
                </td>
                <td>{{ l.reason }}</td>
              </tr>
            </tbody>
          </table>
        </cv-tile>
      </cv-column>
    </cv-row>

    <!-- editor -->
    <NsModal
      size="large"
      :visible="editor.visible"
      :primary-button-disabled="loading.save"
      @modal-hidden="editor.visible = false"
      @primary-click="savePolicy"
    >
      <template slot="title">{{
        editor.id ? $t("policies.edit_title") : $t("policies.new_title")
      }}</template>
      <template slot="content">
        <cv-form @submit.prevent>
          <NsTextInput
            :label="$t('deployments.name')"
            v-model.trim="editor.name"
            :invalid-message="error.name"
            ref="name"
          />

          <div v-for="g in groups" :key="g" class="group">
            <h5 class="sub">{{ $t("policy_group." + g) }}</h5>
            <div v-for="s in catalogOf(g)" :key="s.id" class="entry">
              <cv-checkbox
                :value="s.id"
                :label="$t('policy_setting.' + s.id + '.title')"
                v-model="editor.on"
                @change="exclude(s)"
              />
              <p class="muted small desc">
                {{ $t("policy_setting." + s.id + ".desc") }}
                <span v-if="s.risk > 1" class="warn">{{
                  $t("policy_setting." + s.id + ".caution")
                }}</span>
                <span v-if="s.tattoo"> {{ $t("policies.stays_hint") }}</span>
              </p>
              <div v-if="editor.on.includes(s.id)" class="params">
                <template v-for="(p, name) in s.params">
                  <cv-select
                    v-if="p.values"
                    :key="name"
                    :label="$t('policy_param.' + name)"
                    v-model="editor.params[s.id][name]"
                    class="param"
                  >
                    <cv-select-option
                      v-for="v in p.values"
                      :key="v"
                      :value="v"
                      >{{ $t("policy_value." + v) }}</cv-select-option
                    >
                  </cv-select>
                  <cv-text-area
                    v-else-if="p.type === 'string' && p.maxlength > 200"
                    :key="name"
                    :label="$t('policy_param.' + name)"
                    v-model="editor.params[s.id][name]"
                    rows="3"
                  />
                  <NsTextInput
                    v-else
                    :key="name"
                    :label="$t('policy_param.' + name)"
                    :type="p.type === 'integer' ? 'number' : 'text'"
                    :helper-text="
                      p.type === 'integer'
                        ? $t('policies.range', { min: p.min, max: p.max })
                        : ''
                    "
                    v-model="editor.params[s.id][name]"
                    class="param"
                  />
                </template>
              </div>
              <div
                v-if="editor.resets.includes(s.id) && !editor.on.includes(s.id)"
                class="reset"
              >
                <span class="tag">{{ $t("policies.reset_tag") }}</span>
                {{ $t("policies.reset_help") }}
                <cv-checkbox
                  :value="s.id"
                  :label="$t('policies.reset_drop')"
                  v-model="editor.drop"
                />
              </div>
            </div>
          </div>

          <h5 class="sub">{{ $t("deployments.links") }}</h5>
          <p class="muted small">{{ $t("policies.links_help") }}</p>
          <cv-skeleton-text v-if="loading.targets" />
          <div v-else-if="error.targets" class="bad small">
            {{ error.targets }}
          </div>
          <div v-else class="targets">
            <cv-checkbox
              v-for="t in targets"
              :key="t.dn"
              :value="t.dn"
              :label="
                t.kind === 'domain'
                  ? $t('deployments.whole_domain', { name: t.name })
                  : t.dn
              "
              v-model="editor.link_targets"
            />
          </div>

          <h5 class="sub">{{ $t("policies.reason") }}</h5>
          <NsTextInput
            :label="$t('policies.reason_label')"
            :helper-text="$t('policies.reason_help')"
            v-model.trim="editor.reason"
            :invalid-message="error.reason"
          />
          <NsInlineNotification
            v-if="error.save"
            kind="error"
            :title="$t('action.save-policy')"
            :description="error.save"
            :showCloseButton="false"
          />
        </cv-form>
      </template>
      <template slot="secondary-button">{{ $t("common.cancel") }}</template>
      <template slot="primary-button">{{
        loading.save ? $t("common.processing") : $t("deployments.save")
      }}</template>
    </NsModal>

    <!-- remove -->
    <RemovalDialog
      kind="policy"
      :visible="remove.visible"
      :step="remove.step"
      :name="remove.name"
      :until="remove.until"
      :stays="remove.stays"
      :graceDays="graceDays"
      :loading="loading.remove"
      :error="error.remove"
      @hidden="remove.visible = false"
      @submit="removePolicy"
    />
  </cv-grid>
</template>

<script>
import { mapState } from "vuex";
import Add20 from "@carbon/icons-vue/es/add/20";
import Edit20 from "@carbon/icons-vue/es/edit/20";
import Renew20 from "@carbon/icons-vue/es/renew/20";
import TrashCan20 from "@carbon/icons-vue/es/trash-can/20";
import Undo20 from "@carbon/icons-vue/es/undo/20";
import RemovalDialog from "@/components/RemovalDialog";
import {
  QueryParamService,
  UtilService,
  IconService,
  PageTitleService,
} from "@nethserver/ns8-ui-lib";
import moduleTask from "@/mixins/moduleTask";

export default {
  name: "Policies",
  components: { RemovalDialog },
  mixins: [
    moduleTask,
    IconService,
    UtilService,
    QueryParamService,
    PageTitleService,
  ],
  pageTitle() {
    return this.$t("policies.title") + " - " + this.appName;
  },
  data() {
    return {
      q: { page: "policies" },
      urlCheckInterval: null,
      Add20,
      Edit20,
      Renew20,
      TrashCan20,
      Undo20,
      catalog: [],
      groups: [],
      profiles: [],
      log: [],
      domain: null,
      targets: [],
      editor: this.emptyEditor(),
      remove: {
        visible: false,
        id: "",
        name: "",
        step: "start",
        until: "",
        stays: [],
      },
      graceDays: 14,
      loading: { list: false, targets: false, save: false, remove: false },
      error: {
        list: "",
        targets: "",
        save: "",
        name: "",
        reason: "",
        remove: "",
      },
    };
  },
  computed: {
    ...mapState(["instanceName", "core", "appName"]),
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
    this.listPolicies();
  },
  methods: {
    emptyEditor() {
      return {
        visible: false,
        id: "",
        name: "",
        on: [],
        params: {},
        resets: [],
        drop: [],
        link_targets: [],
        reason: "",
      };
    },
    formatDate(iso) {
      if (!iso) return "-";
      const d = new Date(iso);
      return isNaN(d) ? iso : d.toLocaleString();
    },
    catalogOf(group) {
      return this.catalog.filter((s) => s.group === group);
    },
    byId(id) {
      return this.catalog.find((s) => s.id === id) || { params: {} };
    },
    detail(id, params) {
      // the parameters worth a glance in the list
      if (id === "session_lock")
        return this.$t("policies.seconds", { n: params.seconds });
      if (id === "bitlocker_policy")
        return this.$t("policy_value." + params.method);
      if (id === "eventlog_sizes") return params.security_mb + " MB";
      return "";
    },
    settingList(p) {
      return this.catalog
        .filter((s) => p.settings[s.id])
        .map((s) => ({
          id: s.id,
          state: p.settings[s.id].state,
          detail:
            p.settings[s.id].state === "on"
              ? this.detail(s.id, p.settings[s.id].params || {})
              : "",
        }));
    },
    logDiff(l) {
      const out = [];
      const title = (id) => this.$t("policy_setting." + id + ".title");
      const before = l.before || {};
      const after = l.after || {};
      for (const id of Object.keys(after)) {
        const a = after[id];
        const b = before[id];
        if (!b || b.state !== a.state)
          out.push(
            (a.state === "on" ? "+ " : "↺ ") +
              title(id) +
              " " +
              (a.state === "on" ? this.detail(id, a.params || {}) : "")
          );
        else if (JSON.stringify(a.params) !== JSON.stringify(b.params))
          out.push("~ " + title(id) + " " + this.detail(id, a.params || {}));
      }
      for (const id of Object.keys(before))
        if (!after[id]) out.push("− " + title(id));
      return out;
    },
    async listPolicies() {
      this.loading.list = true;
      this.error.list = "";
      try {
        const res = await this.runModuleTask("list-policies");
        this.catalog = res.catalog;
        this.groups = res.groups;
        this.profiles = res.profiles;
        this.log = res.log;
        this.graceDays = res.grace_days || 14;
        this.domain = res.domain;
      } catch (e) {
        this.error.list = this.$t("error.generic_error");
      } finally {
        this.loading.list = false;
      }
    },
    async loadTargets() {
      this.loading.targets = true;
      this.error.targets = "";
      try {
        const res = await this.runModuleTask("list-link-targets");
        this.targets = res.targets;
      } catch (e) {
        this.error.targets = this.$t("deployments.targets_failed");
      } finally {
        this.loading.targets = false;
      }
    },
    openEditor(p) {
      this.error.save = this.error.name = this.error.reason = "";
      const e = this.emptyEditor();
      // every setting gets its parameters, filled with the defaults
      for (const s of this.catalog) {
        e.params[s.id] = {};
        for (const [name, spec] of Object.entries(s.params))
          e.params[s.id][name] = spec.default;
      }
      if (p) {
        e.id = p.id;
        e.name = p.name;
        e.link_targets = [...p.link_targets];
        for (const [id, entry] of Object.entries(p.settings)) {
          if (entry.state === "on") {
            e.on.push(id);
            Object.assign(e.params[id], entry.params || {});
          } else {
            e.resets.push(id);
          }
        }
      }
      e.visible = true;
      this.editor = e;
      this.loadTargets();
    },
    exclude(s) {
      // Two settings that contradict each other: the one ticked last wins.
      // The list is changed in place and after the checkbox has updated
      // it: the checkboxes keep working on the array they were given.
      this.$nextTick(() => {
        const on = this.editor.on;
        if (!on.includes(s.id)) return;
        for (const other of s.excludes) {
          const i = on.indexOf(other);
          if (i !== -1) on.splice(i, 1);
        }
      });
    },
    async savePolicy() {
      const e = this.editor;
      this.error.save = this.error.name = this.error.reason = "";
      if (!e.name) this.error.name = this.$t("common.required");
      if (e.reason.length < 3)
        this.error.reason = this.$t("policies.reason_required");
      if (this.error.name || this.error.reason) return;
      const settings = {};
      for (const id of e.on) {
        const params = {};
        for (const [name, spec] of Object.entries(this.byId(id).params)) {
          const v = e.params[id][name];
          params[name] = spec.type === "integer" ? Number(v) : v;
        }
        settings[id] = { params };
      }
      const data = {
        name: e.name,
        reason: e.reason,
        settings,
        drop_resets: e.drop,
        link_targets: e.link_targets,
      };
      if (e.id) data.id = e.id;
      this.loading.save = true;
      try {
        await this.runModuleTask("save-policy", data, {
          title: this.$t("policies.saving", { name: e.name }),
          hidden: false,
        });
        this.editor.visible = false;
        this.listPolicies();
      } catch (err) {
        if (err.validation) {
          const v = err.validation[0];
          this.error.save = this.$t("policies.error_" + v.error, {
            value:
              v.error === "invalid_setting" && this.byId(v.value).id
                ? this.$t("policy_setting." + v.value + ".title")
                : v.value,
          });
        } else {
          this.error.save = this.$t("deployments.save_failed");
        }
      } finally {
        this.loading.save = false;
      }
    },
    isDue(pending) {
      return !!pending && new Date(pending.until) <= new Date();
    },
    askRemove(p, step) {
      this.error.remove = "";
      // settings Windows does not remove by itself: they write the
      // Windows defaults during the waiting period
      const stays = Object.keys(p.settings).filter(
        (id) => p.settings[id].state === "on" && this.byId(id).tattoo
      );
      this.remove = {
        visible: true,
        id: p.id,
        name: p.name,
        step,
        until: p.pending_delete ? p.pending_delete.until : "",
        stays: step === "start" ? stays : [],
      };
    },
    async removePolicy(data) {
      this.error.remove = "";
      this.loading.remove = true;
      try {
        await this.runModuleTask(
          "remove-policy",
          { id: this.remove.id, ...data },
          {
            title: this.$t("removal.task_" + data.step, {
              name: this.remove.name,
            }),
            hidden: false,
          }
        );
        this.remove.visible = false;
        this.listPolicies();
      } catch (e) {
        this.error.remove =
          e.validation && e.validation[0]
            ? this.$t("removal.error_" + e.validation[0].error)
            : this.$t("deployments.remove_failed");
      } finally {
        this.loading.remove = false;
      }
    },
  },
};
</script>

<style scoped lang="scss">
@import "../styles/carbon-utils";
.page-help {
  margin-bottom: $spacing-06;
}
.toolbar {
  display: flex;
  gap: $spacing-03;
  margin-bottom: $spacing-05;
}
.domain {
  margin-bottom: $spacing-05;
}
.facts {
  display: grid;
  grid-template-columns: max-content 1fr;
  gap: $spacing-02 $spacing-06;
  margin-top: $spacing-04;
  dt {
    font-weight: 600;
  }
}
@media (max-width: 40rem) {
  .facts {
    grid-template-columns: 1fr;
  }
}
table.profiles {
  width: 100%;
  border-collapse: collapse;
  th,
  td {
    text-align: left;
    vertical-align: top;
    padding: $spacing-04 $spacing-05;
    border-bottom: 1px solid $ui-03;
  }
  .name {
    font-weight: 600;
  }
  .actions {
    white-space: nowrap;
    text-align: right;
  }
}
.nowrap {
  white-space: nowrap;
}
.muted {
  color: $text-02;
}
.small {
  font-size: 0.75rem;
}
.guid {
  font-family: monospace;
  font-size: 0.75rem;
}
.bad {
  color: $support-01;
}
.warn {
  color: #8e6a00;
}
.tag {
  display: inline-block;
  padding: 0 $spacing-03;
  border: 1px solid $ui-04;
  border-radius: 1rem;
  font-size: 0.75rem;
}
.sub {
  margin: $spacing-07 0 $spacing-03;
}
.entry {
  margin-bottom: $spacing-04;
}
.desc {
  margin: 0 0 $spacing-03 1.75rem;
  max-width: 48rem;
}
.params {
  display: flex;
  flex-wrap: wrap;
  gap: $spacing-05;
  margin: 0 0 $spacing-05 1.75rem;
  .param {
    max-width: 16rem;
  }
}
.reset {
  margin: 0 0 $spacing-05 1.75rem;
  font-size: 0.875rem;
}
.targets {
  display: flex;
  flex-direction: column;
}
.bullets {
  list-style: disc;
  margin: $spacing-04 0 $spacing-04 $spacing-06;
}
</style>
