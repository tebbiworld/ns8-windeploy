*** Settings ***
Library     SSHLibrary
Resource    api.resource

*** Test Cases ***
The package index is downloaded and searchable
    Wait Until Keyword Succeeds    30 times    20 seconds    7-Zip is found    ${module_id}

The pages load without a domain controller
    ${res} =    Run task    module/${module_id}/list-deployments    {}
    Should Be Empty    ${res['deployments']}
    ${res} =    Run task    module/${module_id}/list-policies    {}
    Should Be Empty    ${res['profiles']}
    Should Be Equal    ${res['domain']}    ${None}
    ${res} =    Run task    module/${module_id}/list-logon-rules    {}
    Should Be Empty    ${res['rules']}
    Should Be Equal As Integers    ${res['grace_days']}    21
    ${res} =    Run task    module/${module_id}/list-scripts    {}
    Should Be Empty    ${res['sets']}

The administrators can never be denied the logon
    Run task expecting a validation error    module/${module_id}/save-logon-rule
    ...    {"name":"ci","rights":{"deny_interactive":[{"sid":"S-1-5-32-544"}]},"link_targets":[],"reason":"CI test"}
    ...    deny_admins
    Run task expecting a validation error    module/${module_id}/save-logon-rule
    ...    {"name":"ci","rights":{"deny_interactive":[{"sid":"S-1-5-21-1-2-3-512"}]},"link_targets":[],"reason":"CI test"}
    ...    deny_admins

A SID with extra text is refused
    Run task expecting a validation error    module/${module_id}/save-logon-rule
    ...    {"name":"ci","rights":{"interactive":[{"sid":"S-1-5-32-545,*S-1-1-0"}]},"link_targets":[],"reason":"CI test"}
    ...    rights_pattern

Removal steps need a reason and an existing item
    Run task expecting a validation error    module/${module_id}/remove-deployment
    ...    {"id":"0123456789ab","step":"start","reason":"x"}    reason_string_gte
    Run task expecting a validation error    module/${module_id}/remove-deployment
    ...    {"id":"0123456789ab","step":"start","reason":"CI test"}    deployment_not_found
    Run task expecting a validation error    module/${module_id}/remove-scripts
    ...    {"id":"0123456789ab","step":"cancel","reason":"CI test"}    set_not_found

A refused login is one plain line in the task log
    [Documentation]    The DC name points at the node: the request fails, the
    ...                UI gets one neutral error key, the log no traceback.
    ${stdout}    ${stderr}    ${rc} =    Execute Command
    ...    api-cli run module/${module_id}/search-principals --data '{"query":"ci"}'    return_stdout=True    return_stderr=True    return_rc=True    timeout=5 min
    Should Not Be Equal As Integers    ${rc}    0
    Should Not Contain    ${stderr}    Ci-Secret-1234

*** Keywords ***
7-Zip is found
    [Arguments]    ${mid}
    ${res} =    Run task    module/${mid}/search-packages    {"query":"7zip"}
    ${ids} =    Evaluate    [p['id'] for p in $res['packages']]
    Should Contain    ${ids}    7zip.7zip
