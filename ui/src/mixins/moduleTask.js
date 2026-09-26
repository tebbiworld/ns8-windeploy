//
// Copyright (C) 2026 tebbi
// SPDX-License-Identifier: GPL-3.0-or-later
//

// Run a module action and wait for its end: resolves with the action
// output, rejects with {validation: [...]} on validation errors or with
// {aborted: true} when the action failed.
import { TaskService, UtilService } from "@nethserver/ns8-ui-lib";

export default {
  mixins: [TaskService, UtilService],
  methods: {
    runModuleTask(action, data = {}, { title, hidden = true } = {}) {
      return new Promise((resolve, reject) => {
        const eventId = this.getUuid();
        const root = this.core.$root;
        const cleanup = () => {
          root.$off(`${action}-completed-${eventId}`);
          root.$off(`${action}-aborted-${eventId}`);
          root.$off(`${action}-validation-failed-${eventId}`);
        };
        root.$once(`${action}-completed-${eventId}`, (ctx, result) => {
          cleanup();
          resolve(result.output);
        });
        root.$once(`${action}-aborted-${eventId}`, (result) => {
          cleanup();
          reject({ aborted: true, result });
        });
        root.$once(`${action}-validation-failed-${eventId}`, (errors) => {
          cleanup();
          reject({ validation: errors });
        });
        this.createModuleTaskForApp(this.instanceName, {
          action,
          data,
          extra: {
            title: title || this.$t("action." + action),
            isNotificationHidden: hidden,
            eventId,
          },
        }).catch((err) => {
          cleanup();
          reject({ aborted: true, error: this.getErrorMessage(err) });
        });
      });
    },
  },
};
