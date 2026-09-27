<!--
  Copyright (C) 2026 tebbi
  SPDX-License-Identifier: GPL-3.0-or-later
-->
<template>
  <cv-grid fullWidth>
    <cv-row>
      <cv-column class="page-title">
        <h2>{{ $t("deployments.title") }}</h2>
      </cv-column>
    </cv-row>
    <cv-row>
      <cv-column>
        <p class="page-help">{{ $t("deployments.help") }}</p>
      </cv-column>
    </cv-row>
    <cv-row v-if="error.list">
      <cv-column>
        <NsInlineNotification
          kind="error"
          :title="$t('action.list-deployments')"
          :description="error.list"
          :showCloseButton="false"
        />
      </cv-column>
    </cv-row>
    <cv-row v-if="runNow.message">
      <cv-column>
        <NsInlineNotification
          :kind="runNow.failed ? 'error' : 'success'"
          :title="$t('deployments.run_now')"
          :description="runNow.message"
          @close="runNow.message = ''"
        />
      </cv-column>
    </cv-row>
    <cv-row>
      <cv-column class="toolbar">
        <NsButton kind="primary" :icon="Add20" @click="openEditor(null)">{{
          $t("deployments.new")
        }}</NsButton>
        <NsButton
          kind="ghost"
          :icon="Renew20"
          :loading="loading.list"
          :disabled="loading.list"
          @click="listDeployments"
          >{{ $t("deployments.reload") }}</NsButton
        >
      </cv-column>
    </cv-row>
    <cv-row>
      <cv-column>
        <cv-tile light>
          <cv-skeleton-text
            v-if="loading.list && !deployments.length"
            :paragraph="true"
            :line-count="4"
          />
          <NsEmptyState
            v-else-if="!deployments.length"
            :title="$t('deployments.empty')"
          >
            <template #description>{{ $t("deployments.empty_desc") }}</template>
          </NsEmptyState>
          <table v-else class="deployments">
            <thead>
              <tr>
                <th>{{ $t("deployments.name") }}</th>
                <th>{{ $t("deployments.packages") }}</th>
                <th>{{ $t("deployments.schedule") }}</th>
                <th>{{ $t("deployments.links") }}</th>
                <th>{{ $t("deployments.gpo") }}</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="d in deployments" :key="d.id">
                <td class="name">{{ d.name }}</td>
                <td>
                  <div v-for="p in d.packages" :key="p.id" class="pkg">
                    <a
                      :href="manifestUrl(p.id)"
                      target="_blank"
                      rel="noopener noreferrer"
                      :title="$t('deployments.package_link')"
                      ><code>{{ p.id }}</code></a
                    >
                    <span class="mode">{{ $t("mode." + p.mode) }}</span>
                  </div>
                </td>
                <td>{{ scheduleText(d.schedule) }}</td>
                <td>
                  <div v-for="dn in d.link_targets" :key="dn" class="dn">
                    {{ dn }}
                  </div>
                  <span v-if="!d.link_targets.length" class="muted">{{
                    $t("deployments.not_linked")
                  }}</span>
                </td>
                <td>
                  <template v-if="d.gpo && d.gpo.exists">
                    <div>
                      {{
                        $t("deployments.version", { v: d.gpo.version & 0xffff })
                      }}
                    </div>
                    <div class="muted guid">{{ d.gpo_guid }}</div>
                    <div v-if="d.run_now_at" class="muted small">
                      {{
                        $t("deployments.run_now_at", {
                          date: formatDate(d.run_now_at),
                        })
                      }}
                    </div>
                  </template>
                  <span v-else-if="d.gpo" class="bad">{{
                    $t("deployments.gpo_missing")
                  }}</span>
                  <span v-else class="muted">{{ d.gpo_guid || "-" }}</span>
                </td>
                <td class="actions">
                  <NsButton
                    kind="ghost"
                    size="small"
                    :icon="Play20"
                    :loading="runNow.id === d.id"
                    :disabled="!!runNow.id"
                    @click="runDeploymentNow(d)"
                    >{{ $t("deployments.run_now") }}</NsButton
                  >
                  <NsButton
                    kind="ghost"
                    size="small"
                    :icon="Edit20"
                    @click="openEditor(d)"
                    >{{ $t("deployments.edit") }}</NsButton
                  >
                  <NsButton
                    kind="ghost"
                    size="small"
                    :icon="TrashCan20"
                    @click="askRemove(d)"
                    >{{ $t("deployments.remove") }}</NsButton
                  >
                </td>
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
      @primary-click="saveDeployment"
    >
      <template slot="title">{{
        editor.id ? $t("deployments.edit_title") : $t("deployments.new_title")
      }}</template>
      <template slot="content">
        <cv-form @submit.prevent="saveDeployment">
          <NsTextInput
            :label="$t('deployments.name')"
            v-model.trim="editor.name"
            :invalid-message="error.name"
            ref="name"
          />

          <h5 class="sub">{{ $t("deployments.packages") }}</h5>
          <div v-if="!editor.packages.length" class="muted small">
            {{ $t("deployments.no_packages") }}
          </div>
          <div v-for="(p, i) in editor.packages" :key="p.id" class="pkg-row">
            <code class="pkg-id">{{ p.id }}</code>
            <cv-dropdown v-model="p.mode" class="mode-select" :inline="true">
              <cv-dropdown-item value="upgrade">{{
                $t("mode.upgrade")
              }}</cv-dropdown-item>
              <cv-dropdown-item value="install">{{
                $t("mode.install")
              }}</cv-dropdown-item>
            </cv-dropdown>
            <NsButton
              kind="ghost"
              size="small"
              :icon="TrashCan20"
              @click="editor.packages.splice(i, 1)"
              >{{ $t("deployments.remove_package") }}</NsButton
            >
          </div>
          <div v-if="error.packages" class="bad small">
            {{ error.packages }}
          </div>

          <div class="search">
            <cv-search
              :label="$t('deployments.search')"
              :placeholder="$t('deployments.search_placeholder')"
              v-model="search.query"
              @input="onSearchInput"
              size="lg"
            />
            <div v-if="search.error" class="bad small">{{ search.error }}</div>
            <div v-if="search.results.length" class="results">
              <div
                v-for="r in search.results"
                :key="r.id"
                class="result"
                :class="{ selected: isSelected(r.id) }"
              >
                <div class="result-main" @click="showDetails(r)">
                  <div class="result-name">{{ r.name }}</div>
                  <code class="muted">{{ r.id }}</code>
                  <span class="muted"> · {{ r.latest_version }}</span>
                  <a
                    :href="manifestUrl(r.id)"
                    target="_blank"
                    rel="noopener noreferrer"
                    class="pkg-link"
                    :title="$t('deployments.package_link')"
                    @click.stop
                    ><Launch16 /> {{ $t("deployments.package_link") }}</a
                  >
                </div>
                <NsButton
                  kind="ghost"
                  size="small"
                  :icon="Add20"
                  :disabled="isSelected(r.id)"
                  @click="addPackage(r)"
                  >{{ $t("deployments.add") }}</NsButton
                >
              </div>
            </div>
            <div v-else-if="search.done && search.query" class="muted small">
              {{ $t("deployments.no_results") }}
            </div>
            <div v-if="details.loading" class="details">
              <cv-skeleton-text :paragraph="true" :line-count="3" />
            </div>
            <div v-else-if="details.data" class="details">
              <strong>{{ details.data.name }}</strong>
              <span class="muted">
                {{ details.data.version }} · {{ details.data.publisher }}</span
              >
              <p>{{ details.data.short_description }}</p>
              <div class="muted small">
                {{ $t("deployments.license") }}:
                {{ details.data.license || "-" }} ·
                {{ $t("deployments.installers") }}:
                {{
                  details.data.installers
                    .map(
                      (i) =>
                        i.architecture +
                        "/" +
                        i.type +
                        (i.scope ? "/" + i.scope : "")
                    )
                    .join(", ")
                }}
              </div>
              <div class="muted small">
                <a
                  v-if="details.data.homepage"
                  :href="details.data.homepage"
                  target="_blank"
                  rel="noopener noreferrer"
                  >{{ details.data.homepage }}</a
                >
              </div>
            </div>
            <div v-if="index.last_modified" class="muted small index-age">
              {{
                $t("deployments.index_age", {
                  date: formatDate(index.last_modified),
                  n: index.packages,
                })
              }}
            </div>
          </div>

          <h5 class="sub">{{ $t("deployments.schedule") }}</h5>
          <div class="schedule">
            <cv-dropdown
              :label="$t('deployments.frequency')"
              v-model="editor.schedule.frequency"
              class="sched-field"
            >
              <cv-dropdown-item value="weekly">{{
                $t("deployments.weekly")
              }}</cv-dropdown-item>
              <cv-dropdown-item value="daily">{{
                $t("deployments.daily")
              }}</cv-dropdown-item>
            </cv-dropdown>
            <NsTextInput
              :label="$t('deployments.time')"
              v-model.trim="editor.schedule.time"
              placeholder="12:30"
              :invalid-message="error.time"
              class="sched-field"
              ref="time"
            />
            <NsTextInput
              :label="$t('deployments.start_date')"
              v-model.trim="editor.schedule.start_date"
              placeholder="2026-09-28"
              :invalid-message="error.start_date"
              class="sched-field"
              ref="start_date"
            />
            <cv-number-input
              :label="$t('deployments.random_delay')"
              v-model="editor.schedule.random_delay_minutes"
              :min="0"
              :max="1440"
              class="sched-field"
            />
          </div>
          <div v-if="editor.schedule.frequency === 'weekly'" class="days">
            <cv-checkbox
              v-for="day in weekdays"
              :key="day"
              :value="day"
              :label="$t('day.' + day)"
              v-model="editor.schedule.days"
            />
            <div v-if="error.days" class="bad small">{{ error.days }}</div>
          </div>

          <h5 class="sub">{{ $t("deployments.delivery") }}</h5>
          <cv-radio-group :vertical="true">
            <cv-radio-button
              v-model="editor.delivery"
              value="sysvol"
              :label="$t('delivery.sysvol')"
              name="delivery"
            />
            <cv-radio-button
              v-model="editor.delivery"
              value="embedded"
              :label="$t('delivery.embedded')"
              name="delivery"
            />
          </cv-radio-group>
          <p class="muted small">{{ $t("deployments.delivery_help") }}</p>

          <h5 class="sub">{{ $t("deployments.links") }}</h5>
          <p class="muted small">{{ $t("deployments.links_help") }}</p>
          <cv-skeleton-text v-if="loading.targets" />
          <div v-else-if="error.targets" class="bad small">
            {{ error.targets }}
          </div>
          <div v-else class="targets">
            <cv-checkbox
              v-for="t in allTargets"
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
          <div class="ou-add">
            <NsTextInput
              :label="$t('deployments.ou_input')"
              v-model.trim="ouInput"
              :placeholder="ouPlaceholder"
              :helper-text="$t('deployments.ou_helper')"
              :invalid-message="error.ou"
              class="ou-field"
              @keydown.enter.prevent="addOu"
            />
            <NsButton
              kind="tertiary"
              size="field"
              :icon="Add20"
              @click="addOu"
              >{{ $t("deployments.add") }}</NsButton
            >
          </div>

          <NsInlineNotification
            v-if="error.save"
            kind="error"
            :title="$t('action.save-deployment')"
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
    <NsModal
      kind="danger"
      :visible="remove.visible"
      :primary-button-disabled="loading.remove"
      @modal-hidden="remove.visible = false"
      @primary-click="removeDeployment"
    >
      <template slot="title">{{ $t("deployments.remove_title") }}</template>
      <template slot="content">
        <p>{{ $t("deployments.remove_desc", { name: remove.name }) }}</p>
        <cv-checkbox
          value="delete_gpo"
          :label="$t('deployments.remove_delete_gpo')"
          v-model="remove.deleteGpo"
        />
        <NsInlineNotification
          kind="info"
          :title="$t('deployments.remove_clients_title')"
          :description="$t('deployments.remove_clients_desc')"
          :showCloseButton="false"
        />
        <NsInlineNotification
          v-if="error.remove"
          kind="error"
          :title="$t('action.remove-deployment')"
          :description="error.remove"
          :showCloseButton="false"
        />
      </template>
      <template slot="secondary-button">{{ $t("common.cancel") }}</template>
      <template slot="primary-button">{{ $t("deployments.remove") }}</template>
    </NsModal>
  </cv-grid>
</template>

<script>
import { mapState } from "vuex";
import Add20 from "@carbon/icons-vue/es/add/20";
import Edit20 from "@carbon/icons-vue/es/edit/20";
import Renew20 from "@carbon/icons-vue/es/renew/20";
import TrashCan20 from "@carbon/icons-vue/es/trash-can/20";
import Play20 from "@carbon/icons-vue/es/play/20";
import Launch16 from "@carbon/icons-vue/es/launch/16";
import {
  QueryParamService,
  UtilService,
  IconService,
  PageTitleService,
} from "@nethserver/ns8-ui-lib";
import moduleTask from "@/mixins/moduleTask";

const WEEKDAYS = [
  "Monday",
  "Tuesday",
  "Wednesday",
  "Thursday",
  "Friday",
  "Saturday",
  "Sunday",
];

function today() {
  const d = new Date();
  return d.toISOString().slice(0, 10);
}

export default {
  name: "Deployments",
  components: { Launch16 },
  mixins: [
    moduleTask,
    IconService,
    UtilService,
    QueryParamService,
    PageTitleService,
  ],
  pageTitle() {
    return this.$t("deployments.title") + " - " + this.appName;
  },
  data() {
    return {
      q: { page: "deployments" },
      urlCheckInterval: null,
      Add20,
      Edit20,
      Renew20,
      TrashCan20,
      Play20,
      runNow: { id: "", message: "", failed: false },
      weekdays: WEEKDAYS,
      ouInput: "",
      customTargets: [],
      deployments: [],
      targets: [],
      index: {},
      defaultDelivery: "sysvol",
      editor: this.emptyEditor(),
      search: {
        query: "",
        results: [],
        done: false,
        error: "",
        timer: null,
        seq: 0,
      },
      details: { loading: false, data: null },
      remove: { visible: false, id: "", name: "", deleteGpo: true },
      loading: { list: false, save: false, remove: false, targets: false },
      error: {
        list: "",
        save: "",
        remove: "",
        targets: "",
        name: "",
        packages: "",
        time: "",
        start_date: "",
        days: "",
        ou: "",
      },
    };
  },
  computed: {
    ...mapState(["instanceName", "core", "appName"]),
    allTargets() {
      // targets read from AD plus OUs entered by hand (checked on save)
      const known = new Set(this.targets.map((t) => t.dn.toLowerCase()));
      const extra = [...this.customTargets, ...this.editor.link_targets]
        .filter((dn, i, a) => a.indexOf(dn) === i)
        .filter((dn) => !known.has(dn.toLowerCase()))
        .map((dn) => ({ dn, name: dn, kind: "ou" }));
      return [...this.targets, ...extra];
    },
    domainDn() {
      const d = this.targets.find((t) => t.kind === "domain");
      return d ? d.dn : "DC=example,DC=com";
    },
    ouPlaceholder() {
      return "OU=Laptops," + this.domainDn;
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
    this.listDeployments();
    this.loadConfig();
  },
  methods: {
    emptyEditor() {
      return {
        visible: false,
        id: "",
        name: "",
        packages: [],
        schedule: {
          frequency: "weekly",
          days: ["Monday"],
          time: "12:30",
          start_date: today(),
          random_delay_minutes: 30,
        },
        delivery: this.defaultDelivery || "sysvol",
        link_targets: [],
      };
    },
    manifestUrl(id) {
      // package folder in the official winget-pkgs repository
      const parts = id.split(".").map(encodeURIComponent).join("/");
      return (
        "https://github.com/microsoft/winget-pkgs/tree/master/manifests/" +
        id.charAt(0).toLowerCase() +
        "/" +
        parts
      );
    },
    formatDate(iso) {
      if (!iso) return "-";
      const d = new Date(iso);
      return isNaN(d) ? iso : d.toLocaleString();
    },
    scheduleText(s) {
      if (!s) return "-";
      const when =
        s.frequency === "daily"
          ? this.$t("deployments.daily")
          : (s.days || []).map((d) => this.$t("day_short." + d)).join(", ");
      let text = `${when} ${s.time}`;
      if (s.random_delay_minutes) text += ` (+${s.random_delay_minutes} min)`;
      return text;
    },
    async loadConfig() {
      try {
        const c = await this.runModuleTask("get-configuration");
        this.index = c.index || {};
        this.defaultDelivery = c.default_delivery || "sysvol";
      } catch (e) {
        // the page works without it
      }
    },
    async listDeployments() {
      this.loading.list = true;
      this.error.list = "";
      try {
        const res = await this.runModuleTask("list-deployments");
        this.deployments = res.deployments;
        if (res.error) this.error.list = res.error;
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
    openEditor(d) {
      this.clearErrors(this);
      const e = this.emptyEditor();
      if (d) {
        e.id = d.id;
        e.name = d.name;
        e.packages = d.packages.map((p) => ({
          id: p.id,
          mode: p.mode || "upgrade",
        }));
        e.schedule = Object.assign(
          e.schedule,
          JSON.parse(JSON.stringify(d.schedule))
        );
        if (!e.schedule.days) e.schedule.days = [];
        e.delivery = d.delivery || "sysvol";
        e.link_targets = [...(d.link_targets || [])];
      }
      e.visible = true;
      this.editor = e;
      this.search.query = "";
      this.search.results = [];
      this.search.done = false;
      this.details.data = null;
      this.loadTargets();
    },
    onSearchInput() {
      clearTimeout(this.search.timer);
      this.search.timer = setTimeout(this.runSearch, 350);
    },
    async runSearch() {
      const query = (this.search.query || "").trim();
      if (query.length < 2) {
        this.search.results = [];
        this.search.done = false;
        return;
      }
      const seq = ++this.search.seq;
      this.search.error = "";
      try {
        const res = await this.runModuleTask("search-packages", {
          query,
          limit: 30,
        });
        if (seq !== this.search.seq) return; // a newer search is running
        this.search.results = res.packages;
        this.index = res.index || this.index;
        this.search.done = true;
      } catch (e) {
        if (seq === this.search.seq)
          this.search.error = this.$t("deployments.search_failed");
      }
    },
    async showDetails(r) {
      this.details.loading = true;
      this.details.data = null;
      try {
        this.details.data = await this.runModuleTask("get-package", {
          id: r.id,
        });
      } catch (e) {
        this.details.data = null;
      } finally {
        this.details.loading = false;
      }
    },
    addOu() {
      this.error.ou = "";
      const dn = this.ouInput;
      if (!dn) return;
      if (
        !/^OU=[^,]+(,(OU|CN)=[^,]+)*,DC=/i.test(dn) ||
        !dn.toLowerCase().endsWith(this.domainDn.toLowerCase())
      ) {
        this.error.ou = this.$t("deployments.ou_invalid", {
          dn: this.domainDn,
        });
        return;
      }
      if (!this.customTargets.includes(dn)) this.customTargets.push(dn);
      if (!this.editor.link_targets.includes(dn))
        this.editor.link_targets.push(dn);
      this.ouInput = "";
    },
    isSelected(id) {
      return this.editor.packages.some((p) => p.id === id);
    },
    addPackage(r) {
      if (!this.isSelected(r.id))
        this.editor.packages.push({ id: r.id, mode: "upgrade" });
      this.error.packages = "";
    },
    validate() {
      this.clearErrors(this);
      let ok = true;
      const e = this.editor;
      if (!e.name) {
        this.error.name = this.$t("common.required");
        this.focusElement("name");
        ok = false;
      }
      if (!e.packages.length) {
        this.error.packages = this.$t("deployments.need_package");
        ok = false;
      }
      if (!/^([01]\d|2[0-3]):[0-5]\d$/.test(e.schedule.time)) {
        this.error.time = this.$t("deployments.invalid_time");
        ok = false;
      }
      if (!/^\d{4}-\d{2}-\d{2}$/.test(e.schedule.start_date)) {
        this.error.start_date = this.$t("deployments.invalid_date");
        ok = false;
      }
      if (e.schedule.frequency === "weekly" && !e.schedule.days.length) {
        this.error.days = this.$t("deployments.need_day");
        ok = false;
      }
      return ok;
    },
    async saveDeployment() {
      if (!this.validate()) return;
      const e = this.editor;
      const schedule = {
        frequency: e.schedule.frequency,
        time: e.schedule.time,
        start_date: e.schedule.start_date,
        random_delay_minutes: Number(e.schedule.random_delay_minutes) || 0,
      };
      if (schedule.frequency === "weekly") schedule.days = e.schedule.days;
      const data = {
        name: e.name,
        packages: e.packages,
        schedule,
        delivery: e.delivery,
        link_targets: e.link_targets,
      };
      if (e.id) data.id = e.id;
      this.loading.save = true;
      this.error.save = "";
      try {
        await this.runModuleTask("save-deployment", data, {
          title: this.$t("deployments.saving", { name: e.name }),
          hidden: false,
        });
        this.editor.visible = false;
        this.listDeployments();
      } catch (err) {
        if (err.validation) {
          const v = err.validation[0];
          this.error.save = this.$t("deployments.error_" + v.error, {
            value: v.value,
          });
        } else {
          this.error.save = this.$t("deployments.save_failed");
        }
      } finally {
        this.loading.save = false;
      }
    },
    async runDeploymentNow(d) {
      this.runNow = { id: d.id, message: "", failed: false };
      try {
        await this.runModuleTask(
          "run-deployment-now",
          { id: d.id },
          {
            title: this.$t("deployments.run_now_task", { name: d.name }),
            hidden: false,
          }
        );
        this.runNow = {
          id: "",
          message: this.$t("deployments.run_now_done", { name: d.name }),
          failed: false,
        };
        this.listDeployments();
      } catch (e) {
        this.runNow = {
          id: "",
          message: this.$t("deployments.run_now_failed"),
          failed: true,
        };
      }
    },
    askRemove(d) {
      this.error.remove = "";
      this.remove = { visible: true, id: d.id, name: d.name, deleteGpo: true };
    },
    async removeDeployment() {
      this.loading.remove = true;
      this.error.remove = "";
      try {
        await this.runModuleTask(
          "remove-deployment",
          { id: this.remove.id, delete_gpo: !!this.remove.deleteGpo },
          {
            title: this.$t("deployments.removing", { name: this.remove.name }),
            hidden: false,
          }
        );
        this.remove.visible = false;
        this.listDeployments();
      } catch (e) {
        this.error.remove = this.$t("deployments.remove_failed");
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
  max-width: 60rem;
}
.toolbar {
  display: flex;
  gap: $spacing-03;
  margin-bottom: $spacing-05;
}
table.deployments {
  width: 100%;
  border-collapse: collapse;
  th {
    text-align: left;
    font-weight: 600;
    padding: $spacing-03;
    border-bottom: 1px solid $ui-03;
  }
  td {
    padding: $spacing-03;
    vertical-align: top;
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
.pkg {
  margin-bottom: $spacing-02;
}
.mode {
  margin-left: $spacing-03;
  color: $text-02;
  font-size: 0.75rem;
}
.dn,
.guid {
  font-size: 0.75rem;
  word-break: break-all;
}
.muted {
  color: $text-02;
}
.small {
  font-size: 0.75rem;
}
.bad {
  color: $support-01;
}
.sub {
  margin: $spacing-07 0 $spacing-04 0;
}
.pkg-row {
  display: flex;
  align-items: center;
  gap: $spacing-05;
  margin-bottom: $spacing-03;
  .pkg-id {
    min-width: 16rem;
  }
}
.search {
  margin-top: $spacing-05;
}
.results {
  max-height: 16rem;
  overflow-y: auto;
  border: 1px solid $ui-03;
  margin-top: $spacing-03;
}
.result {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: $spacing-03 $spacing-04;
  border-bottom: 1px solid $ui-03;
  &.selected {
    background: $ui-01;
  }
  .result-main {
    cursor: pointer;
    flex: 1;
  }
  .result-name {
    font-weight: 600;
  }
}
.pkg-link {
  margin-left: $spacing-04;
  font-size: 0.75rem;
  white-space: nowrap;
  svg {
    vertical-align: middle;
    fill: currentColor;
  }
}
.details {
  margin-top: $spacing-04;
  padding: $spacing-04;
  background: $ui-01;
  p {
    margin: $spacing-03 0;
  }
}
.index-age {
  margin-top: $spacing-03;
}
.schedule {
  display: flex;
  flex-wrap: wrap;
  gap: $spacing-05;
  .sched-field {
    min-width: 10rem;
    max-width: 14rem;
  }
}
.days {
  display: flex;
  flex-wrap: wrap;
  gap: $spacing-05;
  margin-top: $spacing-04;
}
.ou-add {
  display: flex;
  align-items: flex-start;
  gap: $spacing-03;
  margin-top: $spacing-05;
  .ou-field {
    flex: 1;
  }
  .bx--btn {
    margin-top: 1.5rem;
  }
}
.targets {
  display: flex;
  flex-direction: column;
}
</style>
