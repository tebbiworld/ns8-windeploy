<!--
  Copyright (C) 2026 tebbi
  SPDX-License-Identifier: GPL-3.0-or-later
-->
<template>
  <cv-grid fullWidth>
    <cv-row>
      <cv-column class="page-title">
        <h2>{{ $t("scripts.title") }}</h2>
      </cv-column>
    </cv-row>
    <cv-row>
      <cv-column>
        <p class="page-help">{{ $t("scripts.help") }}</p>
      </cv-column>
    </cv-row>
    <cv-row v-if="error.list">
      <cv-column>
        <NsInlineNotification
          kind="error"
          :title="$t('action.list-scripts')"
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
              $t("scripts.new")
            }}</NsButton>
            <NsButton
              kind="ghost"
              :icon="Renew20"
              :loading="loading.list"
              @click="listSets"
              >{{ $t("deployments.reload") }}</NsButton
            >
          </div>
          <cv-skeleton-text
            v-if="loading.list && !sets.length"
            :paragraph="true"
            :line-count="4"
          />
          <NsEmptyState v-else-if="!sets.length" :title="$t('scripts.empty')">
            <template #description>{{ $t("scripts.empty_desc") }}</template>
          </NsEmptyState>
          <table v-else class="sets">
            <thead>
              <tr>
                <th>{{ $t("deployments.name") }}</th>
                <th>{{ $t("scripts.parts") }}</th>
                <th>{{ $t("deployments.links") }}</th>
                <th>{{ $t("deployments.gpo") }}</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="s in sets" :key="s.id">
                <td class="name">
                  {{ s.name }}
                  <div v-if="s.pending_delete" class="warn small">
                    {{
                      $t("removal.pending", {
                        date: formatDate(s.pending_delete.until),
                      })
                    }}
                  </div>
                  <div v-if="s.pending_delete" class="muted small">
                    {{ s.pending_delete.reason }}
                  </div>
                </td>
                <td>
                  <div v-for="part in partKeys" :key="part">
                    <template v-if="s.parts[part]">
                      <span class="part">{{ $t("scripts.part_" + part) }}</span>
                      <span class="muted small">
                        {{ lines(s.parts[part].script) }}
                        <template v-if="s.parts[part].cleanup">
                          · {{ $t("scripts.with_cleanup") }}</template
                        >
                      </span>
                    </template>
                  </div>
                </td>
                <td>
                  <div v-for="dn in s.link_targets" :key="dn" class="dn">
                    {{ dn }}
                  </div>
                  <span v-if="!s.link_targets.length" class="muted">{{
                    $t("deployments.not_linked")
                  }}</span>
                </td>
                <td>
                  <div>
                    {{
                      $t("scripts.version", {
                        c: s.version & 0xffff,
                        u: s.version >>> 16,
                      })
                    }}
                  </div>
                  <div class="muted guid">{{ s.gpo_guid }}</div>
                  <div class="muted small">{{ formatDate(s.changed) }}</div>
                </td>
                <td v-if="s.pending_delete" class="actions">
                  <NsButton
                    kind="ghost"
                    size="small"
                    :icon="Undo20"
                    @click="askRemove(s, 'cancel')"
                    >{{ $t("removal.button_cancel") }}</NsButton
                  >
                  <NsButton
                    kind="ghost"
                    size="small"
                    :icon="TrashCan20"
                    :disabled="!isDue(s.pending_delete)"
                    @click="askRemove(s, 'delete')"
                    >{{ $t("removal.button_delete") }}</NsButton
                  >
                </td>
                <td v-else class="actions">
                  <NsButton
                    kind="ghost"
                    size="small"
                    :icon="Edit20"
                    @click="openEditor(s)"
                    >{{ $t("deployments.edit") }}</NsButton
                  >
                  <NsButton
                    kind="ghost"
                    size="small"
                    :icon="TrashCan20"
                    @click="askRemove(s, 'start')"
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
          <p class="muted small">{{ $t("scripts.log_help") }}</p>
          <table class="sets">
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
      @primary-click="saveSet"
    >
      <template slot="title">{{
        editor.id ? $t("scripts.edit_title") : $t("scripts.new_title")
      }}</template>
      <template slot="content">
        <cv-form @submit.prevent>
          <NsTextInput
            :label="$t('deployments.name')"
            v-model.trim="editor.name"
            :invalid-message="error.name"
          />
          <NsInlineNotification
            kind="info"
            :title="$t('scripts.sysvol_title')"
            :description="$t('scripts.sysvol_desc')"
            :showCloseButton="false"
          />
          <div v-for="part in partKeys" :key="part" class="part-block">
            <h5 class="sub">{{ $t("scripts.part_" + part) }}</h5>
            <p class="muted small">
              {{ $t("scripts.part_" + part + "_help") }}
            </p>
            <cv-text-area
              :label="$t('scripts.script_label')"
              v-model="editor.parts[part].script"
              :rows="10"
              class="code"
            />
            <cv-text-area
              :label="$t('scripts.cleanup_label')"
              :helper-text="$t('scripts.cleanup_help')"
              v-model="editor.parts[part].cleanup"
              :rows="4"
              class="code"
            />
            <NsInlineNotification
              v-for="hit in secretsIn(part)"
              :key="part + hit.kind + hit.line"
              kind="warning"
              :title="$t('scripts.secret_title')"
              :description="
                $t('scripts.secret_desc', {
                  where: $t('scripts.' + hit.kind + '_label'),
                  line: hit.line,
                })
              "
              :showCloseButton="false"
            />
          </div>

          <h5 class="sub">{{ $t("deployments.links") }}</h5>
          <p class="muted small">{{ $t("scripts.links_help") }}</p>
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
            :title="$t('action.save-scripts')"
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
      kind="scripts"
      :visible="remove.visible"
      :step="remove.step"
      :name="remove.name"
      :until="remove.until"
      :graceDays="graceDays"
      :loading="loading.remove"
      :error="error.remove"
      @hidden="remove.visible = false"
      @submit="removeSet"
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
import {
  QueryParamService,
  UtilService,
  IconService,
  PageTitleService,
} from "@nethserver/ns8-ui-lib";
import moduleTask from "@/mixins/moduleTask";
import RemovalDialog from "@/components/RemovalDialog";

const PART_KEYS = ["logon", "startup"];
// lines that look like a password; the same patterns as the backend
// (pypkg/scriptgen.py), which also writes a warning to the task log
const SECRET_PATTERNS = [
  /cmdkey\b.*\s\/pass(word)?:/i,
  /net\s+use\b.*\s\/user:\S+\s+\S+/i,
  /ConvertTo-SecureString\b.*-AsPlainText/i,
  /-Password\s+['"]/i,
  /\b(passw(or)?d|kennwort|pwd)\s*=\s*['"][^'"]+['"]/i,
];

export default {
  name: "Scripts",
  components: { RemovalDialog },
  mixins: [
    moduleTask,
    IconService,
    UtilService,
    QueryParamService,
    PageTitleService,
  ],
  pageTitle() {
    return this.$t("scripts.title") + " - " + this.appName;
  },
  data() {
    return {
      q: { page: "scripts" },
      urlCheckInterval: null,
      Add20,
      Edit20,
      Renew20,
      TrashCan20,
      Undo20,
      partKeys: PART_KEYS,
      sets: [],
      log: [],
      graceDays: 14,
      targets: [],
      editor: this.emptyEditor(),
      remove: { visible: false, id: "", name: "", step: "start", until: "" },
      loading: { list: false, targets: false, save: false, remove: false },
      error: {
        list: "",
        targets: "",
        save: "",
        remove: "",
        name: "",
        reason: "",
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
    this.listSets();
  },
  methods: {
    emptyEditor() {
      return {
        visible: false,
        id: "",
        name: "",
        parts: {
          logon: { script: "", cleanup: "" },
          startup: { script: "", cleanup: "" },
        },
        link_targets: [],
        reason: "",
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
    lines(text) {
      const n = (text || "").split("\n").filter((l) => l.trim()).length;
      return this.$tc("scripts.lines", n, { n });
    },
    secretsIn(part) {
      const hits = [];
      for (const kind of ["script", "cleanup"]) {
        (this.editor.parts[part][kind] || "").split("\n").forEach((l, i) => {
          if (SECRET_PATTERNS.some((p) => p.test(l)))
            hits.push({ kind, line: i + 1 });
        });
      }
      return hits;
    },
    logDiff(l) {
      // the log keeps size and SHA-256 of each script, not the text
      const out = [];
      for (const part of PART_KEYS) {
        for (const kind of ["script", "cleanup"]) {
          const b = ((l.before || {})[part] || {})[kind];
          const a = ((l.after || {})[part] || {})[kind];
          if ((b && b.sha256) === (a && a.sha256)) continue;
          const label =
            this.$t("scripts.part_" + part) +
            " / " +
            this.$t("scripts." + kind + "_label");
          if (!b) out.push("+ " + label);
          else if (!a) out.push("− " + label);
          else out.push("~ " + label);
        }
      }
      return out;
    },
    async listSets() {
      this.loading.list = true;
      this.error.list = "";
      try {
        const res = await this.runModuleTask("list-scripts");
        this.sets = res.sets;
        this.log = res.log;
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
    openEditor(s) {
      this.error.save = this.error.name = this.error.reason = "";
      const e = this.emptyEditor();
      if (s) {
        e.id = s.id;
        e.name = s.name;
        e.link_targets = [...s.link_targets];
        for (const part of PART_KEYS)
          if (s.parts[part])
            e.parts[part] = {
              script: s.parts[part].script || "",
              cleanup: s.parts[part].cleanup || "",
            };
      }
      e.visible = true;
      this.editor = e;
      this.loadTargets();
    },
    async saveSet() {
      const e = this.editor;
      this.error.save = this.error.name = this.error.reason = "";
      if (!e.name) this.error.name = this.$t("common.required");
      if (e.reason.length < 3)
        this.error.reason = this.$t("policies.reason_required");
      if (!PART_KEYS.some((p) => e.parts[p].script.trim()))
        this.error.save = this.$t("scripts.error_script_required");
      if (this.error.name || this.error.reason || this.error.save) return;
      const parts = {};
      for (const part of PART_KEYS)
        if (e.parts[part].script.trim()) parts[part] = { ...e.parts[part] };
      const data = {
        name: e.name,
        reason: e.reason,
        parts,
        link_targets: e.link_targets,
      };
      if (e.id) data.id = e.id;
      this.loading.save = true;
      try {
        await this.runModuleTask("save-scripts", data, {
          title: this.$t("scripts.saving", { name: e.name }),
          hidden: false,
        });
        this.editor.visible = false;
        this.listSets();
      } catch (err) {
        if (err.validation) {
          const v = err.validation[0];
          this.error.save = this.$t("scripts.error_" + v.error, {
            value: v.value,
          });
        } else {
          this.error.save = this.$t("deployments.save_failed");
        }
      } finally {
        this.loading.save = false;
      }
    },
    askRemove(s, step) {
      this.error.remove = "";
      this.remove = {
        visible: true,
        id: s.id,
        name: s.name,
        step,
        until: s.pending_delete ? s.pending_delete.until : "",
      };
    },
    async removeSet(data) {
      this.error.remove = "";
      this.loading.remove = true;
      try {
        await this.runModuleTask(
          "remove-scripts",
          { id: this.remove.id, ...data },
          {
            title: this.$t("removal.task_" + data.step, {
              name: this.remove.name,
            }),
            hidden: false,
          }
        );
        this.remove.visible = false;
        this.listSets();
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
table.sets {
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
.part {
  font-weight: 600;
  margin-right: $spacing-03;
}
.code ::v-deep textarea {
  font-family: monospace;
  font-size: 0.8125rem;
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
