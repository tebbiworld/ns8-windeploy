<!--
  Copyright (C) 2026 tebbi
  SPDX-License-Identifier: GPL-3.0-or-later
-->
<template>
  <cv-grid fullWidth>
    <cv-row>
      <cv-column class="page-title">
        <h2>{{ $t("logon.title") }}</h2>
      </cv-column>
    </cv-row>
    <cv-row>
      <cv-column>
        <p class="page-help">{{ $t("logon.help") }}</p>
      </cv-column>
    </cv-row>
    <cv-row v-if="error.list">
      <cv-column>
        <NsInlineNotification
          kind="error"
          :title="$t('action.list-logon-rules')"
          :description="error.list"
          :showCloseButton="false"
        />
      </cv-column>
    </cv-row>

    <cv-row>
      <cv-column>
        <cv-tile light>
          <div class="toolbar">
            <NsButton kind="primary" :icon="Add20" @click="openEditor(null)">{{
              $t("logon.new")
            }}</NsButton>
            <NsButton
              kind="ghost"
              :icon="Renew20"
              :loading="loading.list"
              @click="listRules"
              >{{ $t("deployments.reload") }}</NsButton
            >
          </div>
          <cv-skeleton-text
            v-if="loading.list && !rules.length"
            :paragraph="true"
            :line-count="4"
          />
          <NsEmptyState v-else-if="!rules.length" :title="$t('logon.empty')">
            <template #description>{{ $t("logon.empty_desc") }}</template>
          </NsEmptyState>
          <table v-else class="rules">
            <thead>
              <tr>
                <th>{{ $t("deployments.name") }}</th>
                <th>{{ $t("logon.rights") }}</th>
                <th>{{ $t("deployments.links") }}</th>
                <th>{{ $t("deployments.gpo") }}</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="r in rules" :key="r.id">
                <td class="name">
                  {{ r.name }}
                  <div v-if="r.pending_delete" class="warn small">
                    {{
                      $t("removal.pending", {
                        date: formatDate(r.pending_delete.until),
                      })
                    }}
                  </div>
                  <div v-if="r.pending_delete" class="muted small">
                    {{ r.pending_delete.reason }}
                  </div>
                </td>
                <td>
                  <div v-for="key in rightKeys" :key="key">
                    <template v-if="r.rights[key]">
                      <span class="right">{{ $t("logon.right_" + key) }}:</span>
                      {{ r.rights[key].map((e) => e.name).join(", ") }}
                    </template>
                  </div>
                </td>
                <td>
                  <div v-for="dn in r.link_targets" :key="dn" class="dn">
                    {{ dn }}
                  </div>
                  <span v-if="!r.link_targets.length" class="muted">{{
                    $t("deployments.not_linked")
                  }}</span>
                </td>
                <td>
                  <div>
                    {{ $t("deployments.version", { v: r.version & 0xffff }) }}
                  </div>
                  <div class="muted guid">{{ r.gpo_guid }}</div>
                  <div class="muted small">{{ formatDate(r.changed) }}</div>
                </td>
                <td v-if="r.pending_delete" class="actions">
                  <NsButton
                    kind="ghost"
                    size="small"
                    :icon="Undo20"
                    @click="askRemove(r, 'cancel')"
                    >{{ $t("removal.button_cancel") }}</NsButton
                  >
                  <NsButton
                    kind="ghost"
                    size="small"
                    :icon="TrashCan20"
                    :disabled="!isDue(r.pending_delete)"
                    @click="askRemove(r, 'delete')"
                    >{{ $t("removal.button_delete") }}</NsButton
                  >
                </td>
                <td v-else class="actions">
                  <NsButton
                    kind="ghost"
                    size="small"
                    :icon="Edit20"
                    @click="openEditor(r)"
                    >{{ $t("deployments.edit") }}</NsButton
                  >
                  <NsButton
                    kind="ghost"
                    size="small"
                    :icon="TrashCan20"
                    @click="askRemove(r, 'start')"
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
          <table class="rules">
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
      @primary-click="saveRule"
    >
      <template slot="title">{{
        editor.id ? $t("logon.edit_title") : $t("logon.new_title")
      }}</template>
      <template slot="content">
        <cv-form @submit.prevent>
          <NsTextInput
            :label="$t('deployments.name')"
            v-model.trim="editor.name"
            :invalid-message="error.name"
          />

          <h5 class="sub">{{ $t("logon.rights") }}</h5>
          <p class="muted small">{{ $t("logon.rights_help") }}</p>
          <div v-for="key in rightKeys" :key="key" class="right-block">
            <div class="right-title">{{ $t("logon.right_" + key) }}</div>
            <p class="muted small">{{ $t("logon.right_" + key + "_help") }}</p>
            <div class="chosen">
              <span
                v-for="e in editor.rights[key]"
                :key="e.sid"
                class="tag"
                :title="e.sid"
              >
                {{ e.name }}
                <button
                  v-if="!(key !== 'deny_interactive' && e.sid === admins)"
                  type="button"
                  class="tag-remove"
                  :aria-label="$t('deployments.remove')"
                  @click="removePrincipal(key, e.sid)"
                >
                  ×
                </button>
              </span>
              <span
                v-if="key !== 'deny_interactive' && editor.rights[key].length"
                class="muted small"
                >{{ $t("logon.admins_kept") }}</span
              >
              <span v-if="!editor.rights[key].length" class="muted small">{{
                $t("logon.right_unset")
              }}</span>
            </div>
          </div>

          <h5 class="sub">{{ $t("logon.add_title") }}</h5>
          <div class="search">
            <NsTextInput
              :label="$t('logon.search_label')"
              v-model.trim="search.query"
              :invalid-message="error.search"
              @keydown.enter.prevent="searchPrincipals"
            />
            <NsButton
              kind="secondary"
              :icon="Search20"
              :loading="loading.search"
              @click="searchPrincipals"
              >{{ $t("logon.search") }}</NsButton
            >
          </div>
          <table class="rules results">
            <tbody>
              <tr v-for="p in candidates" :key="p.sid">
                <td>
                  {{ p.name }}
                  <span class="muted small">{{
                    $t("logon.kind_" + (p.kind || "group"))
                  }}</span>
                </td>
                <td class="actions">
                  <NsButton
                    v-for="key in rightKeys"
                    :key="key"
                    kind="ghost"
                    size="small"
                    :disabled="has(key, p.sid) || !allowed(key, p.sid)"
                    @click="addPrincipal(key, p)"
                    >{{ $t("logon.add_" + key) }}</NsButton
                  >
                </td>
              </tr>
            </tbody>
          </table>

          <h5 class="sub">{{ $t("deployments.links") }}</h5>
          <p class="muted small">{{ $t("logon.links_help") }}</p>
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
          <NsInlineNotification
            v-if="domainSelected"
            kind="warning"
            :title="$t('logon.domain_title')"
            :description="$t('logon.domain_desc')"
            :showCloseButton="false"
          />
          <cv-checkbox
            v-if="domainSelected"
            value="yes"
            :label="$t('logon.domain_confirm')"
            v-model="editor.confirmDomain"
          />

          <template v-if="conflicts">
            <NsInlineNotification
              v-if="conflicts.length"
              kind="warning"
              :title="$t('logon.conflicts_title')"
              :description="$t('logon.conflicts_desc')"
              :showCloseButton="false"
            />
            <table v-if="conflicts.length" class="rules">
              <tbody>
                <tr v-for="(c, i) in conflicts" :key="i">
                  <td>{{ $t("logon.right_" + c.right) }}</td>
                  <td>
                    {{ c.name }}
                    <div class="muted small">{{ c.container }}</div>
                  </td>
                  <td :class="c.wins ? 'bad' : 'muted'">
                    {{
                      c.wins ? $t("logon.other_wins") : $t("logon.rule_wins")
                    }}
                  </td>
                </tr>
              </tbody>
            </table>
            <cv-checkbox
              v-if="conflicts.length"
              value="yes"
              :label="$t('logon.conflicts_confirm')"
              v-model="editor.confirmConflicts"
            />
          </template>

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
            :title="$t('action.save-logon-rule')"
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

    <RemovalDialog
      kind="logon"
      :visible="remove.visible"
      :step="remove.step"
      :name="remove.name"
      :until="remove.until"
      :graceDays="graceDays"
      :loading="loading.remove"
      :error="error.remove"
      @hidden="remove.visible = false"
      @submit="removeRule"
    />
  </cv-grid>
</template>

<script>
import { mapState } from "vuex";
import Add20 from "@carbon/icons-vue/es/add/20";
import Edit20 from "@carbon/icons-vue/es/edit/20";
import Renew20 from "@carbon/icons-vue/es/renew/20";
import Search20 from "@carbon/icons-vue/es/search/20";
import TrashCan20 from "@carbon/icons-vue/es/trash-can/20";
import Undo20 from "@carbon/icons-vue/es/undo/20";
import {
  QueryParamService,
  UtilService,
  IconService,
  PageTitleService,
} from "@nethserver/ns8-ui-lib";
import moduleTask from "@/mixins/moduleTask";
import RemovalDialog from "@/components/RemovalDialog";

const RIGHT_KEYS = ["interactive", "remote", "deny_interactive"];

export default {
  name: "Logon",
  components: { RemovalDialog },
  mixins: [
    moduleTask,
    IconService,
    UtilService,
    QueryParamService,
    PageTitleService,
  ],
  pageTitle() {
    return this.$t("logon.title") + " - " + this.appName;
  },
  data() {
    return {
      q: { page: "logon" },
      urlCheckInterval: null,
      Add20,
      Edit20,
      Renew20,
      Search20,
      TrashCan20,
      Undo20,
      rightKeys: RIGHT_KEYS,
      rules: [],
      log: [],
      wellKnown: [],
      admins: "S-1-5-32-544",
      graceDays: 14,
      targets: [],
      editor: this.emptyEditor(),
      search: { query: "", results: [] },
      conflicts: null,
      remove: { visible: false, id: "", name: "", step: "start", until: "" },
      loading: {
        list: false,
        targets: false,
        save: false,
        remove: false,
        search: false,
      },
      error: {
        list: "",
        targets: "",
        save: "",
        remove: "",
        name: "",
        reason: "",
        search: "",
      },
    };
  },
  computed: {
    ...mapState(["instanceName", "core", "appName"]),
    candidates() {
      const found = this.search.results.filter(
        (p) => !this.wellKnown.some((w) => w.sid === p.sid)
      );
      return [
        ...this.wellKnown.map((w) => ({ ...w, kind: "builtin" })),
        ...found,
      ];
    },
    domainSelected() {
      return this.targets.some(
        (t) => t.kind === "domain" && this.editor.link_targets.includes(t.dn)
      );
    },
  },
  watch: {
    "editor.link_targets"() {
      this.conflicts = null;
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
    this.listRules();
  },
  methods: {
    emptyEditor() {
      return {
        visible: false,
        id: "",
        name: "",
        rights: { interactive: [], remote: [], deny_interactive: [] },
        link_targets: [],
        reason: "",
        confirmDomain: [],
        confirmConflicts: [],
      };
    },
    formatDate(iso) {
      if (!iso) return "-";
      const d = new Date(iso);
      return isNaN(d) ? iso : d.toLocaleString();
    },
    isDue(pending) {
      return !!pending && new Date(pending.until) <= new Date();
    },
    logDiff(l) {
      const out = [];
      for (const key of RIGHT_KEYS) {
        const names = (r) => ((r || {})[key] || []).map((e) => e.name);
        const before = names(l.before);
        const after = names(l.after);
        for (const n of after)
          if (!before.includes(n))
            out.push("+ " + this.$t("logon.right_" + key) + ": " + n);
        for (const n of before)
          if (!after.includes(n))
            out.push("− " + this.$t("logon.right_" + key) + ": " + n);
      }
      return out;
    },
    async listRules() {
      this.loading.list = true;
      this.error.list = "";
      try {
        const res = await this.runModuleTask("list-logon-rules");
        this.rules = res.rules;
        this.log = res.log;
        this.wellKnown = res.well_known;
        this.admins = res.admins;
        this.graceDays = res.grace_days || 14;
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
    openEditor(r) {
      this.error.save = this.error.name = this.error.reason = "";
      this.error.search = "";
      const e = this.emptyEditor();
      if (r) {
        e.id = r.id;
        e.name = r.name;
        e.link_targets = [...r.link_targets];
        for (const key of RIGHT_KEYS)
          e.rights[key] = (r.rights[key] || []).map((x) => ({ ...x }));
      }
      e.visible = true;
      this.editor = e;
      this.search = { query: "", results: [] };
      this.conflicts = null;
      this.loadTargets();
    },
    has(key, sid) {
      return this.editor.rights[key].some((e) => e.sid === sid);
    },
    allowed(key, sid) {
      // never deny the administrators (the backend refuses it as well)
      if (key !== "deny_interactive") return true;
      return sid !== this.admins && !/^S-1-5-21-.*-512$/.test(sid);
    },
    addPrincipal(key, p) {
      const list = this.editor.rights[key];
      // lockout protection: a right that grants a logon keeps the admins
      if (key !== "deny_interactive" && !list.length && p.sid !== this.admins)
        list.push({ sid: this.admins, name: "Administrators" });
      list.push({ sid: p.sid, name: p.name });
      this.conflicts = null;
    },
    removePrincipal(key, sid) {
      const list = this.editor.rights[key];
      list.splice(
        list.findIndex((e) => e.sid === sid),
        1
      );
      // only the admins left: the right is not set by the rule
      if (list.length === 1 && list[0].sid === this.admins) list.splice(0, 1);
      this.conflicts = null;
    },
    async searchPrincipals() {
      this.error.search = "";
      if (!/^[A-Za-z0-9 ._-]{1,64}$/.test(this.search.query)) {
        this.error.search = this.$t("logon.search_invalid");
        return;
      }
      this.loading.search = true;
      try {
        const res = await this.runModuleTask("search-principals", {
          query: this.search.query,
        });
        this.search.results = res.principals;
        if (!res.principals.length)
          this.error.search = this.$t("logon.search_none");
      } catch (e) {
        this.error.search = this.$t("logon.search_failed");
      } finally {
        this.loading.search = false;
      }
    },
    rightsPayload() {
      const out = {};
      for (const key of RIGHT_KEYS)
        if (this.editor.rights[key].length)
          out[key] = this.editor.rights[key].map((e) => ({
            sid: e.sid,
            name: e.name,
          }));
      return out;
    },
    async saveRule() {
      const e = this.editor;
      this.error.save = this.error.name = this.error.reason = "";
      if (!e.name) this.error.name = this.$t("common.required");
      if (e.reason.length < 3)
        this.error.reason = this.$t("policies.reason_required");
      const rights = this.rightsPayload();
      if (!Object.keys(rights).length)
        this.error.save = this.$t("logon.error_right_required");
      if (this.error.name || this.error.reason || this.error.save) return;
      if (this.domainSelected && !e.confirmDomain.length) {
        this.error.save = this.$t("logon.error_domain_confirm_required");
        return;
      }
      this.loading.save = true;
      try {
        // first show other GPOs that set the same rights
        if (e.link_targets.length && this.conflicts === null) {
          const res = await this.runModuleTask("check-logon-conflicts", {
            ...(e.id ? { id: e.id } : {}),
            rights,
            link_targets: e.link_targets,
          });
          this.conflicts = res.conflicts;
        }
        if (
          this.conflicts &&
          this.conflicts.length &&
          !e.confirmConflicts.length
        )
          return;
        const data = {
          name: e.name,
          reason: e.reason,
          rights,
          link_targets: e.link_targets,
          confirm_domain: !!e.confirmDomain.length,
          confirm_conflicts: !!e.confirmConflicts.length,
        };
        if (e.id) data.id = e.id;
        await this.runModuleTask("save-logon-rule", data, {
          title: this.$t("logon.saving", { name: e.name }),
          hidden: false,
        });
        this.editor.visible = false;
        this.listRules();
      } catch (err) {
        if (err.validation) {
          const v = err.validation[0];
          this.error.save = this.$t("logon.error_" + v.error, {
            value: v.value,
          });
          if (v.error === "conflicts_unconfirmed") this.conflicts = null;
        } else {
          this.error.save = this.$t("deployments.save_failed");
        }
      } finally {
        this.loading.save = false;
      }
    },
    askRemove(r, step) {
      this.error.remove = "";
      this.remove = {
        visible: true,
        id: r.id,
        name: r.name,
        step,
        until: r.pending_delete ? r.pending_delete.until : "",
      };
    },
    async removeRule(data) {
      this.error.remove = "";
      this.loading.remove = true;
      try {
        await this.runModuleTask(
          "remove-logon-rule",
          { id: this.remove.id, ...data },
          {
            title: this.$t("removal.task_" + data.step, {
              name: this.remove.name,
            }),
            hidden: false,
          }
        );
        this.remove.visible = false;
        this.listRules();
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
table.rules {
  width: 100%;
  border-collapse: collapse;
  margin-bottom: $spacing-05;
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
table.results td {
  padding: $spacing-02 $spacing-05;
}
.right {
  font-weight: 600;
}
.right-block {
  margin-bottom: $spacing-05;
}
.right-title {
  font-weight: 600;
}
.chosen {
  display: flex;
  flex-wrap: wrap;
  gap: $spacing-03;
  align-items: center;
}
.tag {
  display: inline-flex;
  align-items: center;
  gap: $spacing-02;
  padding: 0 $spacing-03;
  border: 1px solid $ui-04;
  border-radius: 1rem;
  font-size: 0.875rem;
}
.tag-remove {
  border: none;
  background: none;
  cursor: pointer;
  font-size: 1rem;
  line-height: 1;
}
.search {
  display: flex;
  gap: $spacing-03;
  align-items: flex-end;
  margin-bottom: $spacing-03;
}
.sub {
  margin: $spacing-07 0 $spacing-03;
}
.targets {
  margin-bottom: $spacing-05;
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
</style>
