"""Regression tests for the email composer's additionalDetails parser.

Anchors the fix in ce25966 — concatenated PIM / Entra ID exports put
every additionalDetails field on a single line with no separator:

    additionalDetails :key : ipaddrvalue : 89.104.236.4

The pre-fix parser only handled the multi-line shape and missed every
field on concatenated logs.
"""

from __future__ import annotations


# A real PIM "Add member to role" alert (verbatim shape from the
# product, just with the identifying tenant data scrubbed).
PIM_CONCATENATED_LOG = """\
additionalDetails :key : RequestIdvalue : 1be29bfe-889d-44f1-aa63-b5db3c1d479c

additionalDetails :key : acctvalue : member

additionalDetails :key : ipaddrvalue : 89.104.236.4

additionalDetails :key : ActionTypevalue : Grant

additionalDetails :key : UserAgentvalue : Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/149.0.0.0

additionalDetails :key : Justificationvalue : Rewst Integration without this permissions can't assign entra groups with roles to users.
"""


def test_concatenated_pim_extracts_ipaddr():
    from intel.email_composer import _extract_additional_detail_value
    out = _extract_additional_detail_value(
        PIM_CONCATENATED_LOG.splitlines(), "ipaddr",
    )
    assert out == "89.104.236.4"


def test_concatenated_pim_extracts_request_id():
    from intel.email_composer import _extract_additional_detail_value
    out = _extract_additional_detail_value(
        PIM_CONCATENATED_LOG.splitlines(), "RequestId",
    )
    assert out == "1be29bfe-889d-44f1-aa63-b5db3c1d479c"


def test_concatenated_pim_extracts_action_type():
    from intel.email_composer import _extract_additional_detail_value
    out = _extract_additional_detail_value(
        PIM_CONCATENATED_LOG.splitlines(), "ActionType",
    )
    assert out == "Grant"


def test_concatenated_pim_extracts_multiword_value():
    """User-Agent contains spaces, parens, semicolons — must capture
    the whole string until end-of-line, not stop at the first space."""
    from intel.email_composer import _extract_additional_detail_value
    out = _extract_additional_detail_value(
        PIM_CONCATENATED_LOG.splitlines(), "UserAgent",
    )
    assert "Mozilla/5.0" in out
    assert "Chrome/149.0.0.0" in out


def test_concatenated_pim_extracts_punctuated_value():
    """Justification has periods, apostrophes, commas — confirm the
    capture stops at end-of-line, not at the first period."""
    from intel.email_composer import _extract_additional_detail_value
    out = _extract_additional_detail_value(
        PIM_CONCATENATED_LOG.splitlines(), "Justification",
    )
    assert "Rewst Integration" in out
    assert "users" in out


def test_multiline_pim_still_works():
    """The original multi-line shape must keep working — analysts pasting
    out of PowerShell's pretty-printer get nicely formatted blocks."""
    log = """\
additionalDetails :
key : ipaddr
value : 10.20.30.40
key : Justification
value : Adding the new tenant admin
"""
    from intel.email_composer import _extract_additional_detail_value
    assert _extract_additional_detail_value(log.splitlines(), "ipaddr") == "10.20.30.40"
    assert _extract_additional_detail_value(log.splitlines(), "Justification") == "Adding the new tenant admin"


def test_missing_key_returns_empty():
    from intel.email_composer import _extract_additional_detail_value
    assert _extract_additional_detail_value(
        PIM_CONCATENATED_LOG.splitlines(), "NotInTheLog",
    ) == ""


def test_empty_input_returns_empty():
    from intel.email_composer import _extract_additional_detail_value
    assert _extract_additional_detail_value([], "ipaddr") == ""
    assert _extract_additional_detail_value([""], "ipaddr") == ""


# ─── targetResources (concatenated) ───────────────────────────────────
# Real PIM "Add member to role" lines — 5 fields per resource, all
# concatenated. The walker has to pick out the User-typed resource and
# return its UPN / displayName.
PIM_TARGET_RESOURCES_LINE = (
    "targetResources :id : 00000000-0000-0000-0000-000000000001"
    "displayName : -type : OtheruserPrincipalName : -groupType : -\n"
    "targetResources :id : 7ea39fcc-63ba-4a91-894f-b41a20b45a98"
    "displayName : -type : RequestuserPrincipalName : -groupType : -\n"
    "targetResources :id : 96dde296-d788-42b8-8f79-996e72fe00de"
    "displayName : Rewst Integrationtype : UseruserPrincipalName : "
    "rewst@itsalto.comgroupType : -\n"
    "targetResources :id : e8611ab8-c189-46e8-94e1-60213ab1f814"
    "displayName : Privileged Role Administratortype : RoleuserPrincipalName : "
    "-groupType : -\n"
)


def test_concatenated_target_resource_extracts_user_display_name():
    """The most important field on a PIM alert: WHO got the role."""
    from intel.email_composer import _extract_target_resource_display_name
    out = _extract_target_resource_display_name(
        PIM_TARGET_RESOURCES_LINE.splitlines(),
    )
    assert out == "Rewst Integration"


def test_concatenated_target_resource_extracts_user_upn():
    from intel.email_composer import _extract_target_resource_upn
    out = _extract_target_resource_upn(
        PIM_TARGET_RESOURCES_LINE.splitlines(),
    )
    assert out == "rewst@itsalto.com"


def test_concatenated_target_resource_extracts_role_display_name():
    """The second most important field: WHAT role got granted."""
    from intel.email_composer import _extract_role_target_resource_display_name
    out = _extract_role_target_resource_display_name(
        PIM_TARGET_RESOURCES_LINE.splitlines(),
    )
    assert out == "Privileged Role Administrator"


# ─── modifiedProperties (concatenated) ────────────────────────────────
PIM_MODIFIED_PROPERTIES_LINE = (
    'modifiedProperties :displayName : RoleDefinitionOriginIdoldValue : ""'
    'newValue : "e8611ab8-c189-46e8-94e1-60213ab1f814"'
    'modifiedProperties :displayName : RoleDefinitionOriginTypeoldValue : ""'
    'newValue : "BuiltInRole"'
    'modifiedProperties :displayName : TemplateIdoldValue : ""'
    'newValue : "e8611ab8-c189-46e8-94e1-60213ab1f814"'
)


def test_concatenated_modified_property_extracts_new_value():
    """Each modifiedProperty triple should resolve to its newValue."""
    from intel.email_composer import _extract_modified_property_new_value
    lines = [PIM_MODIFIED_PROPERTIES_LINE]
    assert _extract_modified_property_new_value(
        lines, "RoleDefinitionOriginType") == "BuiltInRole"
    assert _extract_modified_property_new_value(
        lines, "RoleDefinitionOriginId") == "e8611ab8-c189-46e8-94e1-60213ab1f814"
    assert _extract_modified_property_new_value(
        lines, "TemplateId") == "e8611ab8-c189-46e8-94e1-60213ab1f814"


def test_concatenated_modified_property_unknown_key_returns_empty():
    from intel.email_composer import _extract_modified_property_new_value
    lines = [PIM_MODIFIED_PROPERTIES_LINE]
    assert _extract_modified_property_new_value(lines, "NotAField") == ""
