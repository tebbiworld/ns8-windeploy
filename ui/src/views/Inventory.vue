<!--
  Copyright (C) 2026 tebbi
  SPDX-License-Identifier: GPL-3.0-or-later
-->
<template>
  <cv-grid fullWidth>
    <cv-row>
      <cv-column class="page-title">
        <h2>{{ $t("inventory.title") }}</h2>
      </cv-column>
    </cv-row>
    <cv-row>
      <cv-column>
        <p class="page-help">{{ $t("inventory.help") }}</p>
      </cv-column>
    </cv-row>
    <cv-row v-if="error.list">
      <cv-column>
        <NsInlineNotification
          kind="error"
          :title="$t('action.list-gpo-inventory')"
          :description="error.list"
          :showCloseButton="false"
        />
      </cv-column>
    </cv-row>

    <cv-row>
      <cv-column>
        <cv-tile light>
          <div class="toolbar">
            <NsButton
              kind="primary"
              :icon="Renew20"
              :loading="loading.refresh"
              :disabled="loading.list || loading.refresh"
              @click="load(true)"
              >{{ $t("inventory.refresh") }}</NsButton
            >
            <span v-if="result.checked" class="muted small">
              {{
                $t("inventory.checked", { time: formatDate(result.checked) })
              }}
              <template v-if="result.own_count">
                ·
                {{
                  $tc("inventory.own_hidden", result.own_count, {
                    n: result.own_count,
                  })
                }}
              </template>
            </span>
          </div>
          <p v-if="loading.refresh" class="muted small">
            {{ $t("inventory.refresh_help") }}
          </p>
          <cv-skeleton-text
            v-if="(loading.list || loading.refresh) && !result.gpos.length"
            :paragraph="true"
            :line-count="5"
          />
          <NsEmptyState
            v-else-if="!result.checked"
            :title="$t('inventory.not_checked')"
          >
            <template #description>{{
              $t("inventory.not_checked_desc")
            }}</template>
          </NsEmptyState>
          <NsEmptyState
            v-else-if="!result.gpos.length"
            :title="$t('inventory.empty')"
          />
          <template v-else>
            <p v-if="unreachableDcs.length" class="warn small">
              {{
                $t("inventory.dcs_unreachable", {
                  dcs: unreachableDcs.join(", "),
                })
              }}
            </p>
            <table class="gpos">
              <colgroup>
                <col class="c-name" />
                <col class="c-links" />
                <col class="c-version" />
                <col class="c-changed" />
                <col class="c-sysvol" />
                <col class="c-content" />
                <col class="c-actions" />
              </colgroup>
              <thead>
                <tr>
                  <th>{{ $t("deployments.name") }}</th>
                  <th>{{ $t("deployments.links") }}</th>
                  <th>{{ $t("inventory.version") }}</th>
                  <th>{{ $t("inventory.changed") }}</th>
                  <th>{{ $t("inventory.sysvol") }}</th>
                  <th>{{ $t("inventory.content") }}</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                <template v-for="g in result.gpos">
                  <tr :key="g.guid" :class="{ open: open[g.guid] }">
                    <td class="name">
                      {{ g.name || g.guid }}
                      <div class="guid muted">{{ g.guid }}</div>
                      <div v-if="g.kind !== 'foreign'" class="kind muted small">
                        {{ $t("inventory.kind_" + g.kind) }}
                      </div>
                      <div v-if="g.wmi_filter" class="muted small">
                        {{ $t("inventory.wmi_filter") }}
                      </div>
                      <template v-if="retiring(g)">
                        <div class="warn small">
                          {{
                            $t("removal.pending", {
                              date: formatDate(
                                retiring(g).pending_delete.until
                              ),
                            })
                          }}
                        </div>
                        <div class="muted small">
                          {{ retiring(g).pending_delete.reason }}
                        </div>
                        <div
                          v-if="retiring(g).cancel_incomplete"
                          class="bad-text small"
                        >
                          {{ $t("retire.cancel_incomplete") }}
                        </div>
                      </template>
                    </td>
                    <td>
                      <div v-if="!g.links.length" class="muted">
                        {{ $t("inventory.not_linked") }}
                      </div>
                      <div v-for="l in g.links" :key="l.dn" class="link">
                        {{ shortDn(l.dn) }}
                        <span v-if="l.enforced" class="flag">{{
                          $t("inventory.enforced")
                        }}</span>
                        <span v-if="l.disabled" class="flag muted">{{
                          $t("inventory.link_disabled")
                        }}</span>
                      </div>
                    </td>
                    <td>
                      <div>
                        {{ $t("inventory.computer") }} {{ g.version_machine }}
                        <span v-if="g.machine_disabled" class="muted small">{{
                          $t("inventory.part_disabled")
                        }}</span>
                      </div>
                      <div>
                        {{ $t("inventory.user") }} {{ g.version_user }}
                        <span v-if="g.user_disabled" class="muted small">{{
                          $t("inventory.part_disabled")
                        }}</span>
                      </div>
                    </td>
                    <td>{{ formatDate(g.changed) }}</td>
                    <td>
                      <div v-for="d in g.dcs" :key="d.dc" class="dc">
                        <CheckmarkFilled16 v-if="d.present" class="ok" />
                        <WarningFilled16
                          v-else-if="d.present === false"
                          class="bad-icon"
                        />
                        <Help16 v-else class="unknown" />
                        <span :class="{ 'bad-text': d.present === false }">{{
                          shortHost(d.dc)
                        }}</span>
                        <span v-if="d.present === false" class="bad-text small">
                          {{ $t("inventory.folder_missing") }}</span
                        >
                      </div>
                    </td>
                    <td>
                      <span v-if="!g.readable" class="bad-text small">{{
                        $t("inventory.unreadable")
                      }}</span>
                      <span
                        v-else-if="!Object.keys(g.summary).length"
                        class="muted small"
                        >{{ $t("inventory.no_settings") }}</span
                      >
                      <span
                        v-for="e in effectsOf(g)"
                        :key="e"
                        :class="['chip', 'chip-' + effectClass(e)]"
                        >{{ g.summary[e] }}
                        {{ $t("inventory.short_" + e) }}</span
                      >
                    </td>
                    <td class="actions">
                      <NsButton
                        v-if="g.readable && g.items.length"
                        kind="ghost"
                        size="small"
                        :icon="open[g.guid] ? ChevronUp20 : ChevronDown20"
                        @click="toggle(g.guid)"
                        >{{ $t("inventory.details") }}</NsButton
                      >
                      <template v-if="retiring(g)">
                        <NsButton
                          kind="ghost"
                          size="small"
                          :icon="Undo20"
                          @click="openStep(g, 'cancel')"
                          >{{ $t("removal.button_cancel") }}</NsButton
                        >
                        <NsButton
                          v-if="
                            isDue(retiring(g).pending_delete) &&
                            !retiring(g).cancel_incomplete
                          "
                          kind="danger"
                          size="small"
                          :icon="TrashCan20"
                          @click="openStep(g, 'delete')"
                          >{{ $t("removal.button_delete") }}</NsButton
                        >
                      </template>
                      <NsButton
                        v-else-if="g.selectable && g.readable"
                        kind="ghost"
                        size="small"
                        :icon="TrashCan20"
                        @click="openRetire(g)"
                        >{{ $t("retire.button") }}</NsButton
                      >
                    </td>
                  </tr>
                  <tr
                    v-if="open[g.guid]"
                    :key="g.guid + '-items'"
                    class="items"
                  >
                    <td colspan="7">
                      <p v-if="g.truncated" class="warn small">
                        {{ $t("inventory.truncated") }}
                      </p>
                      <div
                        v-for="e in effectsOf(g)"
                        :key="e"
                        class="effect-group"
                      >
                        <h6 :class="'effect-' + effectClass(e)">
                          {{ $t("inventory.effect_" + e) }}
                        </h6>
                        <p class="muted small">
                          {{ $t("inventory.effect_" + e + "_help") }}
                        </p>
                        <ul>
                          <li
                            v-for="(i, n) in itemsOf(g, e)"
                            :key="n"
                            class="item"
                          >
                            <span class="part muted small">{{
                              $t("inventory." + i.part)
                            }}</span>
                            <span class="item-name">{{ i.name }}</span>
                            <span v-if="i.detail" class="muted small">
                              {{ i.detail }}</span
                            >
                          </li>
                        </ul>
                      </div>
                    </td>
                  </tr>
                </template>
              </tbody>
            </table>
          </template>
        </cv-tile>
      </cv-column>
    </cv-row>

    <cv-row v-if="result.retired && result.retired.length">
      <cv-column>
        <cv-tile light>
          <h4 class="sub-title">{{ $t("retire.history") }}</h4>
          <p class="muted small">{{ $t("retire.history_help") }}</p>
          <table class="history">
            <thead>
              <tr>
                <th>{{ $t("deployments.name") }}</th>
                <th>{{ $t("retire.deleted") }}</th>
                <th>{{ $t("policies.reason") }}</th>
                <th>{{ $t("retire.copy") }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="h in result.retired" :key="h.guid + h.stamp">
                <td>
                  {{ h.name }}
                  <div class="guid muted">{{ h.guid }}</div>
                </td>
                <td>
                  {{ formatDate(h.deleted) }}
                  <div v-if="h.by === 'timer'" class="muted small">
                    {{ $t("retire.by_timer") }}
                  </div>
                </td>
                <td>{{ h.reason }}</td>
                <td class="guid">{{ h.stamp }}</td>
              </tr>
            </tbody>
          </table>
        </cv-tile>
      </cv-column>
    </cv-row>

    <cv-row v-if="result.log && result.log.length">
      <cv-column>
        <cv-tile light>
          <h4 class="sub-title">{{ $t("policies.log_title") }}</h4>
          <table class="history">
            <thead>
              <tr>
                <th>{{ $t("policies.log_time") }}</th>
                <th>{{ $t("deployments.name") }}</th>
                <th>{{ $t("policies.log_change") }}</th>
                <th>{{ $t("policies.reason") }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="(l, n) in result.log" :key="n">
                <td>{{ formatDate(l.time) }}</td>
                <td>{{ l.name }}</td>
                <td>{{ $t("removal.change_" + l.change) }}</td>
                <td>{{ l.reason }}</td>
              </tr>
            </tbody>
          </table>
        </cv-tile>
      </cv-column>
    </cv-row>

    <NsModal
      kind="danger"
      size="large"
      :visible="start.visible"
      :primary-button-disabled="loading.retire"
      @modal-hidden="start.visible = false"
      @primary-click="submitRetire"
    >
      <template slot="title">{{
        $t("retire.title", { name: start.gpo ? start.gpo.name : "" })
      }}</template>
      <template slot="content">
        <cv-form v-if="start.gpo" @submit.prevent>
          <p>{{ $t("retire.intro") }}</p>
          <ol class="steps">
            <li v-for="n in 4" :key="n">{{ $t("retire.step_" + n) }}</li>
          </ol>
          <template v-if="planned(start.gpo, 'retire_delete').length">
            <h6 class="sub">{{ $t("retire.will_delete") }}</h6>
            <ul class="plan">
              <li v-for="i in planned(start.gpo, 'retire_delete')" :key="i.ref">
                <span class="item-name">{{ i.name }}</span>
                <span class="muted small"> {{ i.detail }}</span>
              </li>
            </ul>
          </template>
          <template v-if="planned(start.gpo, 'retire_members').length">
            <h6 class="sub">{{ $t("retire.will_remove_members") }}</h6>
            <ul class="plan">
              <li
                v-for="i in planned(start.gpo, 'retire_members')"
                :key="i.ref"
              >
                <span class="item-name">{{ i.name }}</span>
                <span class="muted small"> {{ i.detail }}</span>
              </li>
            </ul>
          </template>
          <template v-if="planned(start.gpo, 'retire_confirm').length">
            <h6 class="sub">{{ $t("retire.registry_title") }}</h6>
            <p class="muted small">{{ $t("retire.registry_help") }}</p>
            <cv-checkbox
              v-for="i in planned(start.gpo, 'retire_confirm')"
              :key="i.ref"
              :value="i.ref"
              :label="i.name + ' — ' + i.detail"
              v-model="start.registry"
            />
          </template>
          <p v-if="staysCount(start.gpo)" class="warn small sub">
            {{
              $tc("retire.stays", staysCount(start.gpo), {
                n: staysCount(start.gpo),
              })
            }}
          </p>
          <template v-if="hasAudit(start.gpo)">
            <NsInlineNotification
              kind="warning"
              :title="$t('inventory.effect_audit_cleared')"
              :description="$t('retire.audit_warning')"
              :showCloseButton="false"
            />
            <cv-checkbox
              value="audit"
              :label="$t('retire.audit_confirm')"
              v-model="start.audit"
            />
            <p v-if="error.audit" class="bad-text small">{{ error.audit }}</p>
          </template>
          <p v-if="start.gpo.links.length" class="muted small sub">
            {{
              $t("retire.links", {
                links: start.gpo.links.map((l) => shortDn(l.dn)).join(", "),
              })
            }}
          </p>
          <NsTextInput
            :label="$t('removal.days_label')"
            v-model.number="start.days"
            type="number"
            min="1"
            max="365"
            :helper-text="$t('removal.days_help')"
            :invalid-message="error.days"
          />
          <NsTextInput
            :label="$t('policies.reason_label')"
            v-model.trim="start.reason"
            :helper-text="$t('policies.reason_help')"
            :invalid-message="error.reason"
          />
          <p class="muted small">{{ $t("dns.grant_admin_help") }}</p>
          <NsTextInput
            :label="$t('dns.admin_user')"
            v-model.trim="start.admin_user"
            :helper-text="$t('dns.admin_user_helper')"
            :invalid-message="error.admin_user"
          />
          <NsTextInput
            :label="$t('dns.admin_password')"
            v-model="start.admin_password"
            type="password"
            :invalid-message="error.admin_password"
          />
          <NsInlineNotification
            v-if="error.retire"
            kind="error"
            :title="$t('action.retire-gpo')"
            :description="error.retire"
            :showCloseButton="false"
          />
        </cv-form>
      </template>
      <template slot="secondary-button">{{ $t("common.cancel") }}</template>
      <template slot="primary-button">{{
        loading.retire ? $t("common.processing") : $t("retire.button_start")
      }}</template>
    </NsModal>

    <RemovalDialog
      kind="gpo"
      :visible="step.visible"
      :step="step.step"
      :name="step.name"
      :until="step.until"
      :graceDays="result.grace_days || 14"
      :loading="loading.step"
      :error="error.step"
      :admin="step.step === 'cancel'"
      @hidden="step.visible = false"
      @submit="submitStep"
    />
  </cv-grid>
</template>

<script>
import { mapState } from "vuex";
import Renew20 from "@carbon/icons-vue/es/renew/20";
import ChevronDown20 from "@carbon/icons-vue/es/chevron--down/20";
import ChevronUp20 from "@carbon/icons-vue/es/chevron--up/20";
import CheckmarkFilled16 from "@carbon/icons-vue/es/checkmark--filled/16";
import WarningFilled16 from "@carbon/icons-vue/es/warning--filled/16";
import Help16 from "@carbon/icons-vue/es/help/16";
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

// the order of pypkg/gpoinventory.py EFFECTS: what needs attention first
const EFFECTS = [
  "audit_cleared",
  "retire_delete",
  "retire_members",
  "retire_confirm",
  "stays",
  "scripts",
  "unknown",
  "restored",
  "removed",
  "none",
];
const CLASS = {
  audit_cleared: "danger",
  retire_delete: "retire",
  retire_members: "retire",
  retire_confirm: "retire",
  stays: "warn",
  scripts: "warn",
  unknown: "warn",
  restored: "ok",
  removed: "ok",
  none: "ok",
};

export default {
  name: "Inventory",
  components: { CheckmarkFilled16, WarningFilled16, Help16, RemovalDialog },
  mixins: [
    moduleTask,
    IconService,
    UtilService,
    QueryParamService,
    PageTitleService,
  ],
  pageTitle() {
    return this.$t("inventory.title") + " - " + this.appName;
  },
  data() {
    return {
      q: { page: "inventory" },
      urlCheckInterval: null,
      Renew20,
      ChevronDown20,
      ChevronUp20,
      TrashCan20,
      Undo20,
      result: { checked: null, gpos: [], own_count: 0, dcs: [] },
      open: {},
      start: this.emptyStart(),
      step: { visible: false, guid: "", name: "", step: "cancel", until: "" },
      loading: { list: false, refresh: false, retire: false, step: false },
      error: {
        list: "",
        retire: "",
        step: "",
        reason: "",
        days: "",
        audit: "",
        admin_user: "",
        admin_password: "",
      },
    };
  },
  computed: {
    ...mapState(["instanceName", "core", "appName"]),
    unreachableDcs() {
      return (this.result.dcs || [])
        .filter((d) => !d.reachable)
        .map((d) => d.name);
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
    this.load(false);
  },
  methods: {
    emptyStart() {
      return {
        visible: false,
        gpo: null,
        registry: [],
        audit: [],
        days: 14,
        reason: "",
        admin_user: "",
        admin_password: "",
      };
    },
    retiring(g) {
      return (this.result.retiring || []).find((r) => r.guid === g.guid);
    },
    isDue(pending) {
      return !!pending && new Date(pending.until) <= new Date();
    },
    planned(g, effect) {
      return g.items.filter((i) => i.effect === effect);
    },
    staysCount(g) {
      return g.items.filter((i) =>
        ["stays", "scripts", "unknown"].includes(i.effect)
      ).length;
    },
    hasAudit(g) {
      return g.items.some((i) => i.effect === "audit_cleared");
    },
    clearErrors() {
      for (const k of Object.keys(this.error)) {
        if (k !== "list") this.error[k] = "";
      }
    },
    openRetire(g) {
      this.clearErrors();
      this.start = Object.assign(this.emptyStart(), {
        visible: true,
        gpo: g,
        days: this.result.grace_days || 14,
      });
    },
    async submitRetire() {
      this.clearErrors();
      const s = this.start;
      let ok = true;
      const days = Number(s.days);
      if (!(Number.isInteger(days) && days >= 1 && days <= 365)) {
        this.error.days = this.$t("removal.days_range");
        ok = false;
      }
      if (s.reason.length < 3) {
        this.error.reason = this.$t("policies.reason_required");
        ok = false;
      }
      if (this.hasAudit(s.gpo) && !s.audit.length) {
        this.error.audit = this.$t("retire.audit_required");
        ok = false;
      }
      if (!s.admin_user) {
        this.error.admin_user = this.$t("common.required");
        ok = false;
      }
      if (!s.admin_password) {
        this.error.admin_password = this.$t("common.required");
        ok = false;
      }
      if (!ok) return;
      this.loading.retire = true;
      try {
        await this.runModuleTask(
          "retire-gpo",
          {
            guid: s.gpo.guid,
            step: "start",
            reason: s.reason,
            days,
            admin_user: s.admin_user,
            admin_password: s.admin_password,
            confirm_registry: s.registry,
            confirm_audit: s.audit.length > 0,
          },
          { hidden: false }
        );
        this.start = this.emptyStart();
        await this.load(false);
      } catch (e) {
        this.start.admin_password = "";
        this.error.retire = this.taskError(e);
      } finally {
        this.loading.retire = false;
      }
    },
    openStep(g, step) {
      this.clearErrors();
      const r = this.retiring(g);
      this.step = {
        visible: true,
        guid: g.guid,
        name: g.name || g.guid,
        step,
        until: r ? r.pending_delete.until : "",
      };
    },
    async submitStep(data) {
      this.loading.step = true;
      this.error.step = "";
      try {
        await this.runModuleTask(
          "retire-gpo",
          Object.assign({ guid: this.step.guid }, data),
          { hidden: false }
        );
        this.step.visible = false;
        await this.load(false);
      } catch (e) {
        this.error.step = this.taskError(e);
      } finally {
        this.loading.step = false;
      }
    },
    taskError(e) {
      if (e.validation && e.validation.length) {
        const v = e.validation[0];
        const key = "retire.error_" + v.error;
        return this.$te(key) ? this.$t(key) : v.error;
      }
      return this.$t("retire.failed");
    },
    async load(refresh) {
      const key = refresh ? "refresh" : "list";
      this.loading[key] = true;
      this.error.list = "";
      try {
        const res = await this.runModuleTask(
          "list-gpo-inventory",
          refresh ? { refresh: true } : {},
          { hidden: !refresh }
        );
        this.result = res;
        this.open = {};
      } catch (e) {
        this.error.list =
          e.validation && e.validation.length
            ? this.$t("inventory.refresh_failed")
            : this.$t("error.generic_error");
      } finally {
        this.loading[key] = false;
      }
    },
    toggle(guid) {
      this.$set(this.open, guid, !this.open[guid]);
    },
    effectsOf(g) {
      return EFFECTS.filter((e) => g.summary[e]);
    },
    itemsOf(g, effect) {
      return g.items.filter((i) => i.effect === effect);
    },
    effectClass(e) {
      return CLASS[e] || "warn";
    },
    shortDn(dn) {
      // OU=Laptops,OU=Firma,DC=ad,DC=example,DC=com -> Firma/Laptops;
      // the domain itself -> ad.example.com
      const parts = dn.split(",").map((p) => p.trim());
      const ous = parts
        .filter((p) => /^(OU|CN)=/i.test(p))
        .map((p) => p.slice(3))
        .reverse();
      const dcs = parts.filter((p) => /^DC=/i.test(p)).map((p) => p.slice(3));
      return ous.length ? ous.join("/") : dcs.join(".");
    },
    shortHost(name) {
      return (name || "").split(".")[0];
    },
    formatDate(iso) {
      if (!iso) return "-";
      const d = new Date(iso);
      return isNaN(d) ? iso : d.toLocaleString();
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
  align-items: center;
  flex-wrap: wrap;
  gap: $spacing-05;
  margin-bottom: $spacing-05;
}
table.gpos {
  width: 100%;
  table-layout: fixed;
  border-collapse: collapse;
  .c-name {
    width: 20%;
  }
  .c-links {
    width: 14%;
  }
  .c-version {
    width: 11%;
  }
  .c-changed {
    width: 12%;
  }
  .c-sysvol {
    width: 10%;
  }
  .c-content {
    width: 21%;
  }
  .c-actions {
    width: 12%;
  }
  th,
  td {
    text-align: left;
    vertical-align: top;
    padding: $spacing-04 $spacing-05;
    border-bottom: 1px solid $ui-03;
    overflow-wrap: anywhere;
  }
  tr.open td {
    border-bottom: none;
  }
  .name {
    font-weight: 600;
  }
  .actions {
    white-space: nowrap;
    text-align: right;
  }
  tr.items td {
    background: $ui-01;
  }
}
.link,
.dc {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: $spacing-02;
  margin-bottom: $spacing-02;
}
.flag {
  font-size: 0.75rem;
  border: 1px solid $ui-04;
  border-radius: 0.5rem;
  padding: 0 $spacing-02;
}
.chip {
  display: inline-block;
  font-size: 0.75rem;
  border-radius: 0.75rem;
  padding: 0 $spacing-03;
  margin: 0 $spacing-02 $spacing-02 0;
  white-space: nowrap;
}
.chip-danger {
  background: #ffd7d9;
  color: #750e13;
}
.chip-retire {
  background: #d0e2ff;
  color: #002d9c;
}
.chip-warn {
  background: #fcf4d6;
  color: #684e00;
}
.chip-ok {
  background: #defbe6;
  color: #044317;
}
.effect-group {
  margin-bottom: $spacing-05;
  h6 {
    margin-bottom: $spacing-02;
  }
  ul {
    margin-top: $spacing-03;
  }
}
.effect-danger {
  color: $support-01;
}
.item {
  margin-bottom: $spacing-02;
  word-break: break-word;
  .part {
    display: inline-block;
    min-width: 5.5rem;
  }
  .item-name {
    font-family: monospace;
    font-size: 0.8125rem;
    margin-right: $spacing-03;
  }
}
.ok {
  fill: $support-02;
  flex-shrink: 0;
}
.bad-icon {
  fill: $support-01;
  flex-shrink: 0;
}
.unknown {
  fill: $text-02;
  flex-shrink: 0;
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
.sub-title {
  margin-bottom: $spacing-03;
}
table.history {
  width: 100%;
  border-collapse: collapse;
  margin-top: $spacing-05;
  th,
  td {
    text-align: left;
    vertical-align: top;
    padding: $spacing-03 $spacing-05;
    border-bottom: 1px solid $ui-03;
    overflow-wrap: anywhere;
  }
}
.steps {
  list-style: decimal;
  margin: $spacing-03 0 $spacing-05 $spacing-06;
}
.plan {
  margin: $spacing-02 0 $spacing-04 0;
  li {
    margin-bottom: $spacing-02;
    overflow-wrap: anywhere;
  }
}
.sub {
  margin-top: $spacing-05;
}
.guid {
  font-family: monospace;
  font-size: 0.75rem;
  font-weight: normal;
}
.kind {
  font-weight: normal;
}
.bad-text {
  color: $support-01;
}
.warn {
  color: #8e6a00;
}
</style>
