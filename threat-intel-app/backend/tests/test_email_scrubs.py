"""Email composer post-processor tests.

The compose_ai prompt forbids greetings, team self-references, closing
courtesy lines, and bulleted lists — but LLMs occasionally produce them
anyway. These tests pin the regex safety-nets in email_composer.py.
"""

from __future__ import annotations

from intel.email_composer import _strip_list_markers, _strip_filler_phrases


# ─── greeting strip ──────────────────────────────────────────────────────────
def test_hi_team_greeting_stripped():
    body = "Hi team,\n\nThe account login failed because the account is disabled."
    assert "Hi team" not in _strip_filler_phrases(body)


def test_hello_greeting_stripped():
    body = "Hello,\n\nThe endpoint connected to a suspicious host."
    assert "Hello" not in _strip_filler_phrases(body)


def test_greetings_greeting_stripped():
    body = "Greetings,\n\nA new alert was triaged."
    assert "Greetings" not in _strip_filler_phrases(body)


def test_dear_name_greeting_stripped():
    body = "Dear John,\n\nThe sign-in attempt was blocked."
    out = _strip_filler_phrases(body)
    assert "Dear John" not in out
    assert "The sign" in out


def test_clean_body_without_greeting_unchanged():
    """A body that's already greeting-free must not be mutated."""
    body = ("The account login attempt for user@example.com failed at 14:02 UTC "
            "because the account is disabled.")
    assert _strip_filler_phrases(body) == body


# ─── team-reference rewrite ──────────────────────────────────────────────────
def test_our_mdr_team_rewritten_to_passive():
    """The exact failing case the user pasted."""
    body = ("In response to this alert, our MDR team has cleared the notification "
            "after confirming that the failure was due to the account being disabled.")
    out = _strip_filler_phrases(body)
    assert "MDR team" not in out
    assert "In response to this alert" not in out
    assert "The notification was cleared" in out


def test_our_team_with_plural_verb_rewritten():
    body = "Our team confirmed the alert and dismissed the notification."
    out = _strip_filler_phrases(body)
    assert "team" not in out.lower()
    assert "was confirmed" in out.lower()


def test_orphan_auxiliary_sentences_dropped():
    """The team-strip fallback can leave 'The team is monitoring' as bare
    ' is monitoring' — that orphan sentence must be dropped."""
    body = ("The endpoint was isolated. The team is monitoring for further "
            "activity. Sign-in logs were captured.")
    out = _strip_filler_phrases(body)
    assert "team" not in out.lower()
    assert "is monitoring" not in out.lower()
    assert "Sign-in logs were captured" in out


# ─── closing courtesy line strip ─────────────────────────────────────────────
def test_please_reach_out_stripped():
    body = "The alert is closed. Please reach out if you need anything further from us."
    out = _strip_filler_phrases(body)
    assert "Please reach out" not in out
    assert "The alert is closed" in out


def test_let_us_know_stripped():
    body = "The endpoint is back online. Let us know if you have any questions."
    out = _strip_filler_phrases(body)
    assert "Let us know" not in out
    assert "The endpoint is back online" in out


def test_do_not_hesitate_stripped():
    body = "The session was revoked. Please do not hesitate to contact us."
    out = _strip_filler_phrases(body)
    assert "hesitate" not in out


def test_feel_free_to_contact_stripped():
    body = "The investigation is complete. Feel free to contact us with questions."
    out = _strip_filler_phrases(body)
    assert "Feel free" not in out


# ─── filler opener strip ─────────────────────────────────────────────────────
def test_i_am_writing_to_inform_stripped():
    body = "I am writing to inform you that the alert was triaged as benign."
    out = _strip_filler_phrases(body)
    assert "I am writing" not in out
    assert "The alert was triaged as benign" in out


def test_please_be_advised_stripped():
    body = "Please be advised that the user account has been disabled."
    out = _strip_filler_phrases(body)
    assert "Please be advised" not in out


def test_at_this_time_stripped():
    body = "At this time we have no evidence of compromise."
    out = _strip_filler_phrases(body)
    assert "At this time" not in out


# ─── bullet stripping ────────────────────────────────────────────────────────
def test_dash_bullets_become_prose():
    body = ("The next steps to take:\n"
            "- Reset the password\n"
            "- Revoke active sessions\n"
            "- Re-enroll MFA")
    out = _strip_list_markers(body)
    assert "- Reset" not in out
    assert "Reset the password" in out
    # Adjacent bullet lines collapse into one paragraph joined by ". ".
    assert "Reset the password. Revoke active sessions" in out


def test_numbered_lists_become_prose():
    body = "Steps:\n1. Isolate the host\n2. Capture forensic image\n3. Re-image"
    out = _strip_list_markers(body)
    assert "1. Isolate" not in out
    assert "Isolate the host" in out


def test_bullet_glyph_stripped():
    body = "Watch for:\n• PowerShell EncodedCommand\n• Cobalt Strike beacon URL"
    out = _strip_list_markers(body)
    assert "•" not in out
    assert "PowerShell EncodedCommand" in out


# ─── capitalisation after sentence-level rewrites ────────────────────────────
def test_capitalisation_after_team_rewrite():
    """The verb-rewrite produces lowercase 'the notification was cleared' —
    when that sits at sentence start it must be capitalised."""
    body = "Our MDR team cleared the notification."
    out = _strip_filler_phrases(body)
    assert out.startswith("The notification was cleared")
