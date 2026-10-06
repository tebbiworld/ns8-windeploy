*** Settings ***
Library     SSHLibrary
Resource    api.resource

*** Variables ***
# There is no domain controller in the CI: the settings are stored without
# the bind test, and the DC name points at the node itself, so every
# request to it is refused at once instead of waiting for a timeout.
${CONFIG}    {"domain":"","dc_host":"dc.ci.test","dc_ip":"127.0.0.1","realm":"CI.TEST","workgroup":"CI","username":"svc-ci","password":"Ci-Secret-1234","skip_check":true}

*** Test Cases ***
Install the module
    IF    '${SCENARIO}' == 'update'
        ${output}  ${rc} =    Execute Command    add-module ${UPDATE_FROM} 1    return_rc=True
    ELSE
        ${output}  ${rc} =    Execute Command    add-module ${IMAGE_URL} 1    return_rc=True
    END
    Should Be Equal As Integers    ${rc}  0
    &{output} =    Evaluate    ${output}
    Set Global Variable    ${module_id}    ${output.module_id}

Configure the module
    Run task    module/${module_id}/configure-module    ${CONFIG}    decode_json=${FALSE}

Update to the image under test
    Skip If    '${SCENARIO}' != 'update'    scenario is ${SCENARIO}
    Run on node    api-cli run update-module --data '{"force":true,"module_url":"${IMAGE_URL}","instances":["${module_id}"]}'

Configuration reads back
    ${cfg} =    Run task    module/${module_id}/get-configuration    {}
    Should Be Equal    ${cfg['realm']}    CI.TEST
    Should Be Equal    ${cfg['username']}    svc-ci
    Should Be True    ${cfg['password_set']}
    Should Be Equal As Integers    ${cfg['delete_grace_days']}    14

The waiting period can be changed
    ${config} =    Evaluate    dict(json.loads('${CONFIG}'), password="", delete_grace_days=21)    modules=json
    ${data} =    Evaluate    json.dumps($config)    modules=json
    Run task    module/${module_id}/configure-module    ${data}    decode_json=${FALSE}
    ${cfg} =    Run task    module/${module_id}/get-configuration    {}
    Should Be Equal As Integers    ${cfg['delete_grace_days']}    21
    # an empty password keeps the stored one
    Should Be True    ${cfg['password_set']}

Secrets are stored in passwords.env only
    Secrets are kept out of the module environment    ${module_id}

The timers are enabled
    Run on node    runagent -m ${module_id} systemctl --user is-enabled windeploy-index.timer
    Run on node    runagent -m ${module_id} systemctl --user is-enabled windeploy-purge.timer
