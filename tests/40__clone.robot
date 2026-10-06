*** Settings ***
Library     SSHLibrary
Resource    api.resource

*** Test Cases ***
Clone the module
    ${out} =    Run task    cluster/clone-module    {"module":"${restored_id}","replace":false,"node":1}
    Set Global Variable    ${clone_id}    ${out['module_id']}
    Should Not Be Equal    ${clone_id}    ${restored_id}

The clone has the settings and the secret but starts empty
    [Documentation]    A copy must not manage the GPOs of its source: the
    ...                deployments, profiles, rules, scripts and logs stay behind.
    ${cfg} =    Run task    module/${clone_id}/get-configuration    {}
    Should Be Equal    ${cfg['username']}    svc-ci
    Should Be Equal As Integers    ${cfg['delete_grace_days']}    21
    Should Be True    ${cfg['password_set']}
    Secrets are kept out of the module environment    ${clone_id}
    # create-module may have written an empty deployments.json again
    ${left} =    Run on node    runagent -m ${clone_id} bash -c 'cd "$AGENT_STATE_DIR" && ls policies.json logon.json scripts.json policy-log.jsonl deployment-log.jsonl logon-log.jsonl scripts-log.jsonl dns-log.jsonl 2>/dev/null | wc -l'
    Should Be Equal As Integers    ${left.strip()}    0
    ${res} =    Run task    module/${clone_id}/list-deployments    {}
    Should Be Empty    ${res['deployments']}
    ${res} =    Run task    module/${clone_id}/list-logon-rules    {}
    Should Be Empty    ${res['rules']}

Remove the clone
    Run on node    remove-module --no-preserve ${clone_id}
