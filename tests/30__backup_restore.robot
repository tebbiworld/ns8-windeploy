*** Settings ***
Library     SSHLibrary
Resource    api.resource

*** Variables ***
# Every state file the backup must carry (imageroot/etc/state-include.conf),
# filled with recognisable content before the backup.
@{STATE_FILES}    deployments.json    policies.json    policy-log.jsonl    deployment-log.jsonl
...               logon.json    logon-log.jsonl    scripts.json    scripts-log.jsonl    dns-log.jsonl

*** Test Cases ***
Fill the state files
    [Documentation]    Valid content the actions can read, marked with the
    ...                file name; a logon rule without GPO shows up on the page.
    &{base} =    Create Dictionary
    ...    deployments.json=${{ {"deployments": []} }}
    ...    policies.json=${{ {"profiles": []} }}
    ...    scripts.json=${{ {"sets": []} }}
    ...    logon.json=${{ {"rules": [{"id": "0123456789ab", "name": "ci rule", "gpo_guid": "", "link_targets": [], "rights": {}}]} }}
    FOR    ${name}    IN    @{STATE_FILES}
        ${content} =    Evaluate    json.dumps(dict($base.get($name, {}), ci=$name))    modules=json
        ${b64} =    Evaluate    base64.b64encode($content.encode()).decode()    modules=base64
        Run on node    runagent -m ${module_id} bash -c 'echo ${b64} | base64 -d > "$AGENT_STATE_DIR/${name}"'
    END
    ${sums} =    State checksums    ${module_id}
    Set Global Variable    ${SUMS_ORIG}    ${sums}

Back up the module
    ${repo}    ${path} =    Back up the module to the cluster repository    ${module_id}
    Set Global Variable    ${BACKUP_REPO}    ${repo}
    Set Global Variable    ${BACKUP_PATH}    ${path}

Stop the original instance
    # Stopped, not removed: on Rocky 9 (systemd 252) a module removed and
    # re-created within seconds gets the same UID back and the user manager
    # is not started again. Only the units of the module are stopped.
    Run on node    runagent -m ${module_id} bash -c 'cd ~/.config/systemd/user && ls *.service *.timer 2>/dev/null | xargs -r systemctl --user disable --now'

Restore into a new instance while the DC is unreachable
    [Documentation]    restore-module stores the settings without the bind
    ...                test (skip_check): the DC of the CI never answers.
    ${rid} =    Restore the module from the cluster repository    ${BACKUP_REPO}    ${BACKUP_PATH}
    Set Global Variable    ${restored_id}    ${rid}
    Should Not Be Equal    ${restored_id}    ${module_id}

The restored instance has the settings, the secret and the state
    ${cfg} =    Run task    module/${restored_id}/get-configuration    {}
    Should Be Equal    ${cfg['realm']}    CI.TEST
    Should Be Equal    ${cfg['username']}    svc-ci
    Should Be True    ${cfg['password_set']}
    Should Be Equal As Integers    ${cfg['delete_grace_days']}    21
    Secrets are kept out of the module environment    ${restored_id}
    ${sums} =    State checksums    ${restored_id}
    Should Be Equal    ${sums}    ${SUMS_ORIG}
    ${res} =    Run task    module/${restored_id}/list-logon-rules    {}
    Should Be Equal    ${res['rules'][0]['name']}    ci rule
    Run on node    runagent -m ${restored_id} systemctl --user is-enabled windeploy-purge.timer

*** Keywords ***
State checksums
    [Arguments]    ${mid}
    ${out} =    Run on node    runagent -m ${mid} bash -c 'cd "$AGENT_STATE_DIR" && sha256sum ${STATE_FILES}[0] ${STATE_FILES}[1] ${STATE_FILES}[2] ${STATE_FILES}[3] ${STATE_FILES}[4] ${STATE_FILES}[5] ${STATE_FILES}[6] ${STATE_FILES}[7] ${STATE_FILES}[8]'
    RETURN    ${out}
