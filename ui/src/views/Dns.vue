<!--
  Copyright (C) 2026 tebbi
  SPDX-License-Identifier: GPL-3.0-or-later
-->
<template>
  <cv-grid fullWidth>
    <cv-row>
      <cv-column class="page-title">
        <h2>{{ $t("dns.title") }}</h2>
      </cv-column>
    </cv-row>
    <cv-row>
      <cv-column>
        <p class="page-help">{{ $t("dns.help") }}</p>
      </cv-column>
    </cv-row>
    <cv-row v-if="error.zones">
      <cv-column>
        <NsInlineNotification
          kind="error"
          :title="$t('action.list-dns-zones')"
          :description="error.zones"
          :showCloseButton="false"
        />
      </cv-column>
    </cv-row>

    <!-- zones -->
    <cv-row>
      <cv-column>
        <cv-tile light class="zones">
          <h4>{{ $t("dns.zones") }}</h4>
          <div class="toolbar">
            <NsButton kind="secondary" :icon="Add20" @click="askCreateZone">{{
              $t("dns.zone_new")
            }}</NsButton>
          </div>
          <cv-skeleton-text
            v-if="loading.zones && !zones.length"
            :paragraph="true"
            :line-count="3"
          />
          <table v-else class="list">
            <tbody>
              <tr
                v-for="z in zones"
                :key="z.name"
                :class="{ selected: z.name === zone }"
              >
                <td class="name">
                  <cv-link @click="selectZone(z.name)">{{ z.name }}</cv-link>
                </td>
                <td>
                  <span v-if="z.reverse" class="tag">{{
                    $t("dns.reverse")
                  }}</span>
                </td>
                <td>
                  <span v-if="z.ad_zone" class="muted">{{
                    $t("dns.zone_ad")
                  }}</span>
                  <span v-else-if="z.writable">{{
                    $t("dns.zone_writable")
                  }}</span>
                  <span v-else class="warn">{{
                    $t("dns.zone_read_only")
                  }}</span>
                </td>
                <td class="actions">
                  <NsButton
                    v-if="!z.ad_zone"
                    kind="ghost"
                    size="small"
                    :icon="z.writable ? Locked20 : Unlocked20"
                    @click="askGrant(z)"
                    >{{
                      z.writable ? $t("dns.revoke") : $t("dns.grant")
                    }}</NsButton
                  >
                  <NsButton
                    v-if="!z.locked"
                    kind="ghost"
                    size="small"
                    :icon="TrashCan20"
                    @click="askRemoveZone(z)"
                    >{{ $t("dns.zone_remove") }}</NsButton
                  >
                </td>
              </tr>
            </tbody>
          </table>
        </cv-tile>
      </cv-column>
    </cv-row>

    <!-- records -->
    <cv-row v-if="zone">
      <cv-column>
        <cv-tile light>
          <h4>{{ $t("dns.records_of", { zone }) }}</h4>
          <NsInlineNotification
            v-if="error.records"
            kind="error"
            :title="$t('action.list-dns-records')"
            :description="error.records"
            :showCloseButton="false"
          />
          <div class="toolbar">
            <NsButton
              kind="primary"
              :icon="Add20"
              :disabled="!currentZone.writable"
              @click="openEditor(null)"
              >{{ $t("dns.new") }}</NsButton
            >
            <NsButton
              kind="ghost"
              :icon="Renew20"
              :loading="loading.records"
              :disabled="loading.records"
              @click="listRecords"
              >{{ $t("deployments.reload") }}</NsButton
            >
            <NsTextInput
              :label="$t('dns.search')"
              v-model.trim="filter.text"
              class="search"
              :placeholder="$t('dns.search_placeholder')"
            />
            <cv-checkbox
              value="own"
              :label="$t('dns.only_changeable')"
              v-model="filter.own"
              class="own"
            />
          </div>
          <div v-if="!currentZone.reverse" class="compare-bar">
            <NsButton
              kind="tertiary"
              size="small"
              :icon="Compare20"
              :loading="loading.compare"
              :disabled="loading.compare"
              @click="compareZone"
              >{{ $t("dns.compare") }}</NsButton
            >
            <span class="muted small">{{ $t("dns.compare_help") }}</span>
          </div>
          <NsInlineNotification
            v-if="error.compare"
            kind="error"
            :title="$t('action.compare-dns-zone')"
            :description="error.compare"
            :showCloseButton="false"
          />
          <div v-if="comparison" class="comparison">
            <NsInlineNotification
              v-if="!comparison.public"
              kind="info"
              :title="$t('dns.compare_not_public_title')"
              :description="$t('dns.compare_not_public', { zone })"
              @close="comparison = null"
            />
            <template v-else>
              <h5>
                {{
                  $t("dns.compare_summary", {
                    differs: compareCount("differs"),
                    only: compareCount("internal_only"),
                    same: compareCount("same"),
                  })
                }}
              </h5>
              <cv-checkbox
                value="all"
                :label="$t('dns.compare_show_all')"
                v-model="compareAll"
              />
              <p
                v-if="comparison.dnshelper && comparison.dnshelper.length"
                class="small helper"
              >
                {{ $t("dns.compare_dnshelper") }}
                <cv-link
                  v-for="h in comparison.dnshelper"
                  :key="h"
                  @click="core.$router.push('/apps/' + h)"
                  >{{ h }}</cv-link
                >
              </p>
              <p v-else class="muted small">
                {{ $t("dns.compare_no_dnshelper") }}
              </p>
              <p v-if="comparison.skipped" class="warn small">
                {{ $t("dns.compare_skipped", { n: comparison.skipped }) }}
              </p>
              <p v-if="!compareRows.length" class="muted">
                {{ $t("dns.compare_nothing") }}
              </p>
              <table v-else class="list compare">
                <thead>
                  <tr>
                    <th>{{ $t("dns.name") }}</th>
                    <th>{{ $t("dns.compare_internal") }}</th>
                    <th>{{ $t("dns.compare_public") }}</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="r in compareRows" :key="r.name + r.type">
                    <td class="name">{{ r.name }}</td>
                    <td class="data">
                      <div v-for="v in r.internal" :key="v">
                        {{ r.type }} {{ v }}
                      </div>
                    </td>
                    <td class="data">
                      <div v-for="v in r.public" :key="v">
                        {{ r.public_type }} {{ v }}
                      </div>
                      <span v-if="!r.public.length" class="muted">{{
                        $t("dns.compare_none")
                      }}</span>
                    </td>
                    <td class="actions">
                      <span v-if="r.status !== 'differs'" class="muted small">{{
                        $t("dns.compare_" + r.status)
                      }}</span>
                      <template v-else-if="currentZone.writable">
                        <NsButton
                          kind="ghost"
                          size="small"
                          :icon="Download20"
                          @click="askAdopt(r, 'public')"
                          >{{ $t("dns.adopt") }}</NsButton
                        >
                        <NsButton
                          kind="ghost"
                          size="small"
                          :icon="TrashCan20"
                          @click="askAdopt(r, 'delete')"
                          >{{ $t("dns.adopt_delete") }}</NsButton
                        >
                      </template>
                      <span v-else class="warn small">{{
                        $t("dns.compare_differs")
                      }}</span>
                    </td>
                  </tr>
                </tbody>
              </table>
            </template>
          </div>
          <cv-skeleton-text
            v-if="loading.records && !records.length"
            :paragraph="true"
            :line-count="5"
          />
          <NsEmptyState v-else-if="!shown.length" :title="$t('dns.empty')" />
          <table v-else class="list records">
            <thead>
              <tr>
                <th>{{ $t("dns.name") }}</th>
                <th>{{ $t("dns.type") }}</th>
                <th>{{ $t("dns.data") }}</th>
                <th>{{ $t("dns.ttl") }}</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="r in shown" :key="r.name + r.type + r.data">
                <td class="name">{{ r.name }}</td>
                <td>{{ r.type }}</td>
                <td class="data">{{ r.data }}</td>
                <td class="nowrap">{{ r.ttl }}</td>
                <td class="actions">
                  <span v-if="r.locked" class="muted small">{{
                    $t("dns.locked_" + r.locked)
                  }}</span>
                  <template v-else-if="currentZone.writable">
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
                      @click="askRemove(r)"
                      >{{ $t("deployments.remove") }}</NsButton
                    >
                  </template>
                </td>
              </tr>
            </tbody>
          </table>
          <p class="muted small count">
            {{ $t("dns.count", { shown: shown.length, all: records.length }) }}
          </p>
        </cv-tile>
      </cv-column>
    </cv-row>

    <!-- changes -->
    <cv-row v-if="log.length">
      <cv-column>
        <cv-tile light>
          <h4>{{ $t("policies.log_title") }}</h4>
          <table class="list">
            <thead>
              <tr>
                <th>{{ $t("policies.log_time") }}</th>
                <th>{{ $t("dns.zone") }}</th>
                <th>{{ $t("policies.log_change") }}</th>
                <th>{{ $t("dns.record") }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="(l, i) in log" :key="i">
                <td class="nowrap">{{ formatDate(l.time) }}</td>
                <td>{{ l.zone }}</td>
                <td>{{ $t("dns.change_" + l.change) }}</td>
                <td v-if="l.change === 'zone_deleted'" class="small">
                  {{
                    $t("dns.zone_backup", {
                      n: l.before.name,
                      file: l.before.data,
                    })
                  }}
                </td>
                <td v-else class="data">
                  <div v-if="l.before" :class="{ struck: l.after }">
                    {{ recordText(l.before) }}
                  </div>
                  <div v-if="l.after">{{ recordText(l.after) }}</div>
                  <div v-if="l.pointer" class="muted small">
                    {{ $t("dns.pointer_" + l.pointer) }}
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </cv-tile>
      </cv-column>
    </cv-row>

    <!-- editor -->
    <NsModal
      :visible="editor.visible"
      :primary-button-disabled="loading.save"
      @modal-hidden="editor.visible = false"
      @primary-click="saveRecord"
    >
      <template slot="title">{{
        editor.replaces ? $t("dns.edit_title") : $t("dns.new_title")
      }}</template>
      <template slot="content">
        <cv-form @submit.prevent>
          <NsTextInput
            :label="$t('dns.name')"
            v-model.trim="editor.name"
            :helper-text="$t('dns.name_help', { zone })"
            :invalid-message="error.name"
            :disabled="!!editor.replaces"
          />
          <cv-select
            :label="$t('dns.type')"
            v-model="editor.type"
            :disabled="!!editor.replaces"
          >
            <cv-select-option v-for="t in editorTypes" :key="t" :value="t">{{
              t + " – " + $t("dns.type_" + t)
            }}</cv-select-option>
          </cv-select>
          <NsTextInput
            :label="$t('dns.data_' + editor.type)"
            v-model.trim="editor.value"
            :invalid-message="error.value"
          />
          <div v-if="editor.type === 'MX'" class="fields">
            <NsTextInput
              :label="$t('dns.preference')"
              type="number"
              v-model="editor.preference"
              class="field"
            />
          </div>
          <div v-if="editor.type === 'SRV'" class="fields">
            <NsTextInput
              :label="$t('dns.port')"
              type="number"
              v-model="editor.port"
              class="field"
            />
            <NsTextInput
              :label="$t('dns.priority')"
              type="number"
              v-model="editor.priority"
              class="field"
            />
            <NsTextInput
              :label="$t('dns.weight')"
              type="number"
              v-model="editor.weight"
              class="field"
            />
          </div>
          <NsTextInput
            :label="$t('dns.ttl_seconds')"
            type="number"
            v-model="editor.ttl"
            :helper-text="$t('policies.range', { min: ttl.min, max: ttl.max })"
            :invalid-message="error.ttl"
            class="field"
          />
          <cv-checkbox
            v-if="editor.type === 'A' || editor.type === 'AAAA'"
            value="pointer"
            :label="$t('dns.pointer')"
            v-model="editor.pointer"
          />
          <NsInlineNotification
            v-if="error.save"
            kind="error"
            :title="$t('action.save-dns-record')"
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
      @primary-click="removeRecord"
    >
      <template slot="title">{{ $t("dns.remove_title") }}</template>
      <template slot="content">
        <cv-form @submit.prevent>
          <p>{{ $t("dns.remove_desc") }}</p>
          <p class="data record">
            {{ remove.record ? recordText(remove.record) : "" }}
          </p>
          <cv-checkbox
            v-if="
              remove.record &&
              (remove.record.type === 'A' || remove.record.type === 'AAAA')
            "
            value="pointer"
            :label="$t('dns.pointer_remove')"
            v-model="remove.pointer"
          />
          <NsInlineNotification
            v-if="error.remove"
            kind="error"
            :title="$t('action.remove-dns-record')"
            :description="error.remove"
            :showCloseButton="false"
          />
        </cv-form>
      </template>
      <template slot="secondary-button">{{ $t("common.cancel") }}</template>
      <template slot="primary-button">{{ $t("deployments.remove") }}</template>
    </NsModal>

    <!-- take the public value or drop the internal record -->
    <NsModal
      :kind="adopt.mode === 'delete' ? 'danger' : 'default'"
      :visible="adopt.visible"
      :primary-button-disabled="loading.adopt"
      @modal-hidden="adopt.visible = false"
      @primary-click="adoptRecord"
    >
      <template slot="title">{{
        adopt.mode === "delete"
          ? $t("dns.adopt_delete_title")
          : $t("dns.adopt_title")
      }}</template>
      <template slot="content">
        <cv-form v-if="adopt.row" @submit.prevent>
          <p>
            {{
              adopt.mode === "delete"
                ? $t("dns.adopt_delete_desc", {
                    name: adopt.row.name,
                    zone,
                  })
                : $t("dns.adopt_desc", { name: adopt.row.name })
            }}
          </p>
          <dl class="pairs">
            <dt>{{ $t("dns.compare_internal") }}</dt>
            <dd class="data struck">
              <div v-for="v in adopt.row.internal" :key="v">
                {{ adopt.row.type }} {{ v }}
              </div>
            </dd>
            <template v-if="adopt.mode === 'public'">
              <dt>{{ $t("dns.compare_public") }}</dt>
              <dd class="data">
                <div v-for="v in adopt.row.public" :key="v">
                  {{ adopt.row.public_type }} {{ v }}
                </div>
              </dd>
            </template>
          </dl>
          <p
            v-if="adopt.mode === 'public' && adopt.row.public_type === 'CNAME'"
            class="muted small"
          >
            {{ $t("dns.adopt_alias_note") }}
          </p>
          <NsInlineNotification
            v-if="error.adopt"
            kind="error"
            :title="$t('action.adopt-dns-record')"
            :description="error.adopt"
            :showCloseButton="false"
          />
        </cv-form>
      </template>
      <template slot="secondary-button">{{ $t("common.cancel") }}</template>
      <template slot="primary-button">{{
        adopt.mode === "delete" ? $t("dns.adopt_delete") : $t("dns.adopt")
      }}</template>
    </NsModal>

    <!-- new zone -->
    <NsModal
      :visible="newZone.visible"
      :primary-button-disabled="loading.zone"
      @modal-hidden="closeZoneDialogs"
      @primary-click="createZone"
    >
      <template slot="title">{{ $t("dns.zone_new_title") }}</template>
      <template slot="content">
        <cv-form @submit.prevent>
          <cv-radio-group vertical>
            <cv-radio-button
              v-model="newZone.kind"
              value="forward"
              :label="$t('dns.zone_forward')"
              name="zone-kind"
            />
            <cv-radio-button
              v-model="newZone.kind"
              value="reverse"
              :label="$t('dns.zone_reverse')"
              name="zone-kind"
            />
          </cv-radio-group>
          <NsTextInput
            v-if="newZone.kind === 'forward'"
            :label="$t('dns.zone_name')"
            v-model.trim="newZone.zone"
            placeholder="lab.example.net"
            :helper-text="$t('dns.zone_name_help')"
            :invalid-message="error.zoneName"
          />
          <NsTextInput
            v-else
            :label="$t('dns.zone_network')"
            v-model.trim="newZone.network"
            placeholder="192.168.1.0/24"
            :helper-text="$t('dns.zone_network_help')"
            :invalid-message="error.zoneName"
          />
          <cv-checkbox
            value="grant"
            :label="$t('dns.zone_grant')"
            v-model="newZone.grant"
          />
          <NsInlineNotification
            v-if="newZone.kind === 'forward'"
            kind="info"
            :title="$t('dns.zone_shadow_title')"
            :description="$t('dns.zone_shadow')"
            :showCloseButton="false"
          />
          <p class="muted small">{{ $t("dns.grant_admin_help") }}</p>
          <NsTextInput
            :label="$t('dns.admin_user')"
            v-model.trim="admin.user"
            autocomplete="off"
          />
          <NsTextInput
            :label="$t('dns.admin_password')"
            type="password"
            v-model="admin.password"
            autocomplete="off"
            :invalid-message="error.zoneAdmin"
          />
        </cv-form>
      </template>
      <template slot="secondary-button">{{ $t("common.cancel") }}</template>
      <template slot="primary-button">{{ $t("dns.zone_create") }}</template>
    </NsModal>

    <!-- delete zone -->
    <NsModal
      kind="danger"
      :visible="dropZone.visible"
      :primary-button-disabled="loading.zone"
      @modal-hidden="closeZoneDialogs"
      @primary-click="removeZone"
    >
      <template slot="title">{{ $t("dns.zone_remove_title") }}</template>
      <template slot="content">
        <cv-form @submit.prevent>
          <p>{{ $t("dns.zone_remove_desc", { zone: dropZone.zone }) }}</p>
          <p class="muted small">{{ $t("dns.zone_remove_backup") }}</p>
          <NsTextInput
            :label="$t('dns.zone_confirm', { zone: dropZone.zone })"
            v-model.trim="dropZone.confirm"
            autocomplete="off"
            :invalid-message="error.zoneName"
          />
          <p class="muted small">{{ $t("dns.grant_admin_help") }}</p>
          <NsTextInput
            :label="$t('dns.admin_user')"
            v-model.trim="admin.user"
            autocomplete="off"
          />
          <NsTextInput
            :label="$t('dns.admin_password')"
            type="password"
            v-model="admin.password"
            autocomplete="off"
            :invalid-message="error.zoneAdmin"
          />
        </cv-form>
      </template>
      <template slot="secondary-button">{{ $t("common.cancel") }}</template>
      <template slot="primary-button">{{ $t("dns.zone_remove") }}</template>
    </NsModal>

    <!-- rights on a zone -->
    <NsModal
      :visible="grant.visible"
      :primary-button-disabled="loading.grant"
      @modal-hidden="closeGrant"
      @primary-click="grantZone"
    >
      <template slot="title">{{
        grant.give ? $t("dns.grant_title") : $t("dns.revoke_title")
      }}</template>
      <template slot="content">
        <cv-form @submit.prevent>
          <p>
            {{
              $t(grant.give ? "dns.grant_desc" : "dns.revoke_desc", {
                zone: grant.zone,
              })
            }}
          </p>
          <p class="muted small">{{ $t("dns.grant_admin_help") }}</p>
          <NsTextInput
            :label="$t('dns.admin_user')"
            v-model.trim="grant.user"
            autocomplete="off"
          />
          <NsTextInput
            :label="$t('dns.admin_password')"
            type="password"
            v-model="grant.password"
            autocomplete="off"
            :invalid-message="error.grant"
          />
        </cv-form>
      </template>
      <template slot="secondary-button">{{ $t("common.cancel") }}</template>
      <template slot="primary-button">{{
        grant.give ? $t("dns.grant") : $t("dns.revoke")
      }}</template>
    </NsModal>
  </cv-grid>
</template>

<script>
import { mapState } from "vuex";
import Add20 from "@carbon/icons-vue/es/add/20";
import Edit20 from "@carbon/icons-vue/es/edit/20";
import Renew20 from "@carbon/icons-vue/es/renew/20";
import TrashCan20 from "@carbon/icons-vue/es/trash-can/20";
import Locked20 from "@carbon/icons-vue/es/locked/20";
import Unlocked20 from "@carbon/icons-vue/es/unlocked/20";
import Compare20 from "@carbon/icons-vue/es/compare/20";
import Download20 from "@carbon/icons-vue/es/download/20";
import {
  QueryParamService,
  UtilService,
  IconService,
  PageTitleService,
} from "@nethserver/ns8-ui-lib";
import moduleTask from "@/mixins/moduleTask";

const TYPES = ["A", "AAAA", "CNAME", "MX", "PTR", "SRV", "TXT"];

export default {
  name: "Dns",
  mixins: [
    moduleTask,
    IconService,
    UtilService,
    QueryParamService,
    PageTitleService,
  ],
  pageTitle() {
    return this.$t("dns.title") + " - " + this.appName;
  },
  data() {
    return {
      q: { page: "dns" },
      urlCheckInterval: null,
      Add20,
      Edit20,
      Renew20,
      TrashCan20,
      Locked20,
      Unlocked20,
      Compare20,
      Download20,
      comparison: null,
      compareAll: false,
      adopt: { visible: false, row: null, mode: "public" },
      zones: [],
      zone: "",
      records: [],
      log: [],
      ttl: { min: 60, max: 604800, default: 3600 },
      filter: { text: "", own: false },
      editor: this.emptyEditor(),
      remove: { visible: false, record: null, pointer: true },
      grant: { visible: false, zone: "", give: true, user: "", password: "" },
      newZone: {
        visible: false,
        kind: "forward",
        zone: "",
        network: "",
        grant: true,
      },
      dropZone: { visible: false, zone: "", confirm: "" },
      admin: { user: "administrator", password: "" },
      loading: {
        zones: false,
        records: false,
        save: false,
        remove: false,
        grant: false,
        zone: false,
        compare: false,
        adopt: false,
      },
      error: {
        zones: "",
        records: "",
        save: "",
        name: "",
        value: "",
        ttl: "",
        remove: "",
        grant: "",
        zoneName: "",
        zoneAdmin: "",
        compare: "",
        adopt: "",
      },
    };
  },
  computed: {
    ...mapState(["instanceName", "core", "appName"]),
    currentZone() {
      return this.zones.find((z) => z.name === this.zone) || {};
    },
    editorTypes() {
      // a reverse zone holds pointers, a forward zone everything else
      return this.currentZone.reverse
        ? ["PTR", "CNAME", "TXT"]
        : TYPES.filter((t) => t !== "PTR");
    },
    compareRows() {
      if (!this.comparison) return [];
      return this.comparison.rows.filter(
        (r) => this.compareAll || r.status === "differs"
      );
    },
    shown() {
      const text = this.filter.text.toLowerCase();
      return this.records.filter(
        (r) =>
          (!this.filter.own || !r.locked) &&
          (!text ||
            r.name.includes(text) ||
            r.data.toLowerCase().includes(text) ||
            r.type.toLowerCase() === text)
      );
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
    this.listZones();
  },
  methods: {
    emptyEditor() {
      return {
        visible: false,
        replaces: null,
        name: "",
        type: "A",
        value: "",
        preference: 10,
        port: "",
        priority: 0,
        weight: 100,
        ttl: 3600,
        pointer: true,
      };
    },
    formatDate(iso) {
      if (!iso) return "-";
      const d = new Date(iso);
      return isNaN(d) ? iso : d.toLocaleString();
    },
    recordText(r) {
      return [r.name, r.type, r.data].filter(Boolean).join("  ");
    },
    errorText(err, fallback) {
      if (err.validation) {
        const code = err.validation[0].error;
        const key = "dns.error_" + code;
        return this.$te(key) ? this.$t(key) : code;
      }
      return this.$t(fallback);
    },
    async listZones() {
      this.loading.zones = true;
      this.error.zones = "";
      try {
        const res = await this.runModuleTask("list-dns-zones");
        this.zones = res.zones;
        this.log = res.log;
        if (!this.zones.some((z) => z.name === this.zone)) {
          const first = this.zones.find((z) => !z.ad_zone) || this.zones[0];
          this.zone = first ? first.name : "";
        }
        if (this.zone) this.listRecords();
      } catch (e) {
        this.error.zones = this.errorText(e, "dns.zones_failed");
      } finally {
        this.loading.zones = false;
      }
    },
    selectZone(name) {
      this.zone = name;
      this.records = [];
      this.comparison = null;
      this.error.compare = "";
      this.listRecords();
    },
    async listRecords() {
      this.loading.records = true;
      this.error.records = "";
      try {
        const res = await this.runModuleTask("list-dns-records", {
          zone: this.zone,
        });
        this.records = res.records;
        this.ttl = res.ttl;
      } catch (e) {
        this.error.records = this.errorText(e, "dns.records_failed");
      } finally {
        this.loading.records = false;
      }
    },
    compareCount(status) {
      return this.comparison.rows.filter((r) => r.status === status).length;
    },
    async compareZone() {
      this.loading.compare = true;
      this.error.compare = "";
      try {
        this.comparison = await this.runModuleTask(
          "compare-dns-zone",
          { zone: this.zone },
          {
            title: this.$t("dns.comparing", { zone: this.zone }),
            hidden: false,
          }
        );
      } catch (e) {
        this.comparison = null;
        this.error.compare = this.errorText(e, "dns.compare_failed");
      } finally {
        this.loading.compare = false;
      }
    },
    askAdopt(row, mode) {
      this.error.adopt = "";
      this.adopt = { visible: true, row, mode };
    },
    async adoptRecord() {
      const a = this.adopt;
      this.error.adopt = "";
      this.loading.adopt = true;
      try {
        await this.runModuleTask(
          "adopt-dns-record",
          { zone: this.zone, name: a.row.name, type: a.row.type, mode: a.mode },
          { title: this.$t("dns.saving", { name: a.row.name }), hidden: false }
        );
        this.adopt.visible = false;
        await this.listZones();
        this.compareZone();
      } catch (e) {
        this.error.adopt = this.errorText(e, "deployments.save_failed");
      } finally {
        this.loading.adopt = false;
      }
    },
    openEditor(r) {
      this.error.save = this.error.name = this.error.value = "";
      this.error.ttl = "";
      const e = this.emptyEditor();
      e.type = this.editorTypes[0];
      e.ttl = this.ttl.default;
      if (r) {
        e.replaces = { type: r.type, data: r.data };
        e.name = r.name;
        e.type = r.type;
        e.ttl = r.ttl;
        const parts = r.data.split(" ");
        if (r.type === "MX") {
          e.value = parts[0];
          e.preference = parts[1];
        } else if (r.type === "SRV") {
          [e.value, e.port, e.priority, e.weight] = parts;
        } else {
          e.value = r.data;
        }
      }
      e.visible = true;
      this.editor = e;
    },
    editorData() {
      const e = this.editor;
      if (e.type === "MX") return `${e.value} ${e.preference}`;
      if (e.type === "SRV")
        return `${e.value} ${e.port} ${e.priority} ${e.weight}`;
      return e.value;
    },
    async saveRecord() {
      const e = this.editor;
      this.error.save = this.error.name = this.error.value = "";
      this.error.ttl = "";
      const ttl = Number(e.ttl);
      if (!e.name) this.error.name = this.$t("common.required");
      if (!e.value) this.error.value = this.$t("common.required");
      if (!Number.isInteger(ttl) || ttl < this.ttl.min || ttl > this.ttl.max)
        this.error.ttl = this.$t("dns.error_invalid_ttl");
      if (this.error.name || this.error.value || this.error.ttl) return;
      const data = {
        zone: this.zone,
        name: e.name,
        type: e.type,
        data: this.editorData(),
        ttl,
        pointer: !!e.pointer && (e.type === "A" || e.type === "AAAA"),
      };
      if (e.replaces) data.replaces = e.replaces;
      this.loading.save = true;
      try {
        await this.runModuleTask("save-dns-record", data, {
          title: this.$t("dns.saving", { name: e.name }),
          hidden: false,
        });
        this.editor.visible = false;
        this.listZones();
      } catch (err) {
        this.error.save = this.errorText(err, "deployments.save_failed");
      } finally {
        this.loading.save = false;
      }
    },
    askRemove(r) {
      this.error.remove = "";
      this.remove = { visible: true, record: r, pointer: true };
    },
    async removeRecord() {
      const r = this.remove.record;
      this.error.remove = "";
      this.loading.remove = true;
      try {
        await this.runModuleTask(
          "remove-dns-record",
          {
            zone: this.zone,
            name: r.name,
            type: r.type,
            data: r.data,
            pointer:
              !!this.remove.pointer && (r.type === "A" || r.type === "AAAA"),
          },
          { title: this.$t("dns.removing", { name: r.name }), hidden: false }
        );
        this.remove.visible = false;
        this.listZones();
      } catch (err) {
        this.error.remove = this.errorText(err, "deployments.remove_failed");
      } finally {
        this.loading.remove = false;
      }
    },
    askCreateZone() {
      this.error.zoneName = this.error.zoneAdmin = "";
      this.admin.password = "";
      this.newZone = {
        visible: true,
        kind: "forward",
        zone: "",
        network: "",
        grant: true,
      };
    },
    askRemoveZone(z) {
      this.error.zoneName = this.error.zoneAdmin = "";
      this.admin.password = "";
      this.dropZone = { visible: true, zone: z.name, confirm: "" };
    },
    closeZoneDialogs() {
      // the admin password does not stay in the page
      this.newZone.visible = false;
      this.dropZone.visible = false;
      this.admin.password = "";
    },
    zoneError(err, fallback) {
      // show the message at the field it belongs to
      const text = this.errorText(err, fallback);
      const field = err.validation ? err.validation[0].field : "";
      if (field === "admin_password") this.error.zoneAdmin = text;
      else this.error.zoneName = text;
      this.admin.password = "";
    },
    async createZone() {
      const z = this.newZone;
      this.error.zoneName = this.error.zoneAdmin = "";
      const value = z.kind === "forward" ? z.zone : z.network;
      if (!value) this.error.zoneName = this.$t("common.required");
      if (!this.admin.user || !this.admin.password)
        this.error.zoneAdmin = this.$t("common.required");
      if (this.error.zoneName || this.error.zoneAdmin) return;
      const data = {
        grant: !!z.grant,
        admin_user: this.admin.user,
        admin_password: this.admin.password,
      };
      if (z.kind === "forward") data.zone = value;
      else data.network = value;
      this.loading.zone = true;
      try {
        const res = await this.runModuleTask("create-dns-zone", data, {
          title: this.$t("dns.zone_creating", { zone: value }),
          hidden: false,
        });
        this.closeZoneDialogs();
        this.zone = res.zone;
        this.records = [];
        this.listZones();
      } catch (err) {
        this.zoneError(err, "dns.zone_failed");
      } finally {
        this.loading.zone = false;
      }
    },
    async removeZone() {
      const z = this.dropZone;
      this.error.zoneName = this.error.zoneAdmin = "";
      if (z.confirm.toLowerCase() !== z.zone)
        this.error.zoneName = this.$t("dns.error_confirm_mismatch");
      if (!this.admin.user || !this.admin.password)
        this.error.zoneAdmin = this.$t("common.required");
      if (this.error.zoneName || this.error.zoneAdmin) return;
      this.loading.zone = true;
      try {
        await this.runModuleTask(
          "remove-dns-zone",
          {
            zone: z.zone,
            confirm: z.confirm,
            admin_user: this.admin.user,
            admin_password: this.admin.password,
          },
          {
            title: this.$t("dns.zone_removing", { zone: z.zone }),
            hidden: false,
          }
        );
        this.closeZoneDialogs();
        if (this.zone === z.zone) {
          this.zone = "";
          this.records = [];
        }
        this.listZones();
      } catch (err) {
        this.zoneError(err, "dns.zone_failed");
      } finally {
        this.loading.zone = false;
      }
    },
    askGrant(z) {
      this.error.grant = "";
      this.grant = {
        visible: true,
        zone: z.name,
        give: !z.writable,
        user: "administrator",
        password: "",
      };
    },
    closeGrant() {
      // the admin password does not stay in the page
      this.grant.visible = false;
      this.grant.password = "";
    },
    async grantZone() {
      this.error.grant = "";
      if (!this.grant.user || !this.grant.password) {
        this.error.grant = this.$t("common.required");
        return;
      }
      this.loading.grant = true;
      try {
        await this.runModuleTask(
          "grant-dns-zone",
          {
            zone: this.grant.zone,
            grant: this.grant.give,
            admin_user: this.grant.user,
            admin_password: this.grant.password,
          },
          {
            title: this.$t("dns.granting", { zone: this.grant.zone }),
            hidden: false,
          }
        );
        this.closeGrant();
        this.listZones();
      } catch (err) {
        this.error.grant = this.errorText(err, "dns.grant_failed");
        this.grant.password = "";
      } finally {
        this.loading.grant = false;
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
.zones {
  margin-bottom: $spacing-05;
  .toolbar {
    margin: $spacing-04 0;
  }
}
.toolbar {
  display: flex;
  flex-wrap: wrap;
  align-items: flex-end;
  gap: $spacing-05;
  margin: $spacing-05 0;
  .search {
    min-width: 14rem;
    max-width: 24rem;
    flex: 1;
  }
  .own {
    flex: 0 0 auto;
    margin-bottom: $spacing-03;
  }
}
table.list {
  width: 100%;
  border-collapse: collapse;
  th,
  td {
    text-align: left;
    vertical-align: top;
    padding: $spacing-03 $spacing-05;
    border-bottom: 1px solid $ui-03;
  }
  .name {
    font-weight: 600;
    overflow-wrap: break-word;
  }
  .actions {
    white-space: nowrap;
    text-align: right;
  }
  tr.selected td {
    background: $ui-01;
  }
}
table.records {
  .name {
    min-width: 12rem;
    max-width: 24rem;
  }
}
.data {
  font-family: monospace;
  font-size: 0.8125rem;
  overflow-wrap: anywhere;
}
.record {
  margin: $spacing-04 0;
}
.compare-bar {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: $spacing-05;
  margin-bottom: $spacing-05;
}
.comparison {
  margin-bottom: $spacing-06;
  padding: $spacing-05;
  background: $ui-01;
  h5 {
    margin-bottom: $spacing-03;
  }
}
.helper a {
  margin-left: $spacing-03;
  cursor: pointer;
}
.pairs {
  display: grid;
  grid-template-columns: max-content 1fr;
  gap: $spacing-03 $spacing-06;
  margin: $spacing-05 0;
  dt {
    font-weight: 600;
  }
}
.struck {
  text-decoration: line-through;
  color: $text-02;
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
.warn {
  color: #8e6a00;
}
.count {
  margin-top: $spacing-04;
}
.tag {
  display: inline-block;
  padding: 0 $spacing-03;
  border: 1px solid $ui-04;
  border-radius: 1rem;
  font-size: 0.75rem;
}
.fields {
  display: flex;
  flex-wrap: wrap;
  gap: $spacing-05;
}
.field {
  max-width: 12rem;
}
</style>
