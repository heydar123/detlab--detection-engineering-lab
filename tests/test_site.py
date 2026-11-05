"""The read-only copy of the web page: what is embedded, what the page may do, and what happens when the template changes."""

import json
import re
from html.parser import HTMLParser

import pytest

from detlab import site
from detlab.app import WEB_DIR
from detlab.cli import main

TEMPLATE = (WEB_DIR / "index.html").read_text(encoding="utf-8")


# ------------------------------------------------------------------ embedding data inside a script block

def test_json_inside_the_page_never_contains_a_raw_angle_bracket_or_ampersand():
    text = site.embed_json({"a": "</script><script>alert(1)</script>", "b": "x & y", "c": ["<!--", "-->"]})
    assert "<" not in text and ">" not in text and "&" not in text
    assert json.loads(text) == {"a": "</script><script>alert(1)</script>", "b": "x & y", "c": ["<!--", "-->"]}


def test_json_inside_the_page_is_plain_ascii_and_keeps_every_character():
    obj = {"name": "Ünïcode   line separator \U0001f600", "tab": "a\tb", "nested": [{"k": "é"}]}
    text = site.embed_json(obj)
    assert text.isascii() and "\n" not in text
    assert json.loads(text) == obj


def test_text_that_looks_like_the_end_of_a_script_cannot_end_the_script():
    """Parse the finished page the way a browser does: the snapshot must be one single script element."""
    snapshot = {"payload": {"rules": [], "attacks": []}, "evil": "</script><img src=x onerror=alert(1)>"}
    page = site.render_page(snapshot, page=TEMPLATE)

    class Scripts(HTMLParser):
        def __init__(self):
            super().__init__()
            self.stack, self.scripts, self.tags = [], [], []

        def handle_starttag(self, tag, attrs):
            self.tags.append(tag)
            if tag == "script":
                self.scripts.append({"attrs": dict(attrs), "text": ""})
                self.stack.append(tag)

        def handle_endtag(self, tag):
            if tag == "script" and self.stack:
                self.stack.pop()

        def handle_data(self, data):
            if self.stack:
                self.scripts[-1]["text"] += data

    parser = Scripts()
    parser.feed(page)
    data = [s for s in parser.scripts if s["attrs"].get("id") == "lab-snapshot"]
    assert len(data) == 1 and data[0]["attrs"]["type"] == "application/json"
    assert json.loads(data[0]["text"])["evil"] == "</script><img src=x onerror=alert(1)>"
    assert "img" not in parser.tags, "the text inside the data never became an element"


# ------------------------------------------------------------------ the finished page

@pytest.fixture(scope="module")
def page(lab):
    return site.render_page(lab.snapshot())


def test_the_page_has_one_snapshot_one_token_and_a_policy_that_allows_no_network(page):
    assert page.count('id="lab-snapshot"') == 1
    assert page.count('<meta name="lab-token" content="static">') == 1 and "__LAB_TOKEN__" not in page
    assert page.count('http-equiv="Content-Security-Policy"') == 1
    policy = re.search(r'http-equiv="Content-Security-Policy" content="([^"]+)"', page).group(1)
    assert policy == site.CSP
    assert "default-src 'none'" in policy and "connect-src 'none'" in policy and "form-action 'none'" in policy
    assert "base-uri 'none'" in policy and "img-src data:" in policy
    assert "http://" not in policy and "https://" not in policy and "*" not in policy
    assert '<meta name="referrer" content="no-referrer">' in page


def test_the_snapshot_comes_before_the_program_and_the_page_says_what_it_is(page):
    assert page.index('id="lab-snapshot"') < page.index(site.SCRIPT_START)
    description = re.search(r'<meta name="description" content="([^"]+)"', page).group(1)
    assert description.startswith("Detection engineering lab (read-only copy): 32 detection rules as code, "
                                  "tested on made-up logs with 13 planted attacks, 26 public attack recordings, "
                                  "a red-team set and an ATT&CK coverage map.")
    assert description.endswith("A lab, not production experience.")


def test_the_page_makes_no_requests_to_any_other_site(page):
    """No script, stylesheet, image, font or link may point at the network: the policy would block it, and the page has none."""
    assert not re.search(r"""(src|href|action)\s*=\s*["']?\s*(https?:)?//""", page, re.I)
    assert not re.search(r"@import|url\(\s*['\"]?https?:", page, re.I)
    assert "fetch(" in page and "SNAP" in page, "the same page still contains the code for the local server"


def test_the_embedded_snapshot_holds_every_answer_the_server_would_give(lab, page):
    raw = re.search(r'<script type="application/json" id="lab-snapshot">(.*?)</script>', page, re.S).group(1)
    snap = json.loads(raw)
    assert set(snap) == {"payload", "alerts", "cases", "reports"}
    assert len(snap["payload"]["rules"]) == 32 and len(snap["payload"]["attacks"]) == 13
    assert set(snap["alerts"]) == set(lab.alert_index) and set(snap["cases"]) == {c.case_id for c in lab.cases}
    assert {"detection_report.md", "evasion_report.md"} <= set(snap["reports"])
    assert all(f"{cid}.md" in snap["reports"] for cid in snap["cases"])
    assert all(len(a["events"]) <= 25 for a in snap["alerts"].values()), "evidence is capped so the page stays small"


def test_the_copy_is_the_same_page_as_the_local_app_with_nothing_else_changed(page):
    stripped = re.sub(r'<script type="application/json" id="lab-snapshot">.*?</script>\n', "", page, flags=re.S)
    stripped = re.sub(r'<meta http-equiv="Content-Security-Policy".*?<meta name="description" content="[^"]*">\n', "", stripped, flags=re.S)
    assert stripped.replace('content="static"', 'content="__LAB_TOKEN__"') == TEMPLATE


def test_the_page_turns_off_everything_that_needs_the_lab_to_be_running():
    """In the copy, a request that would change something (a POST body) is refused with a plain explanation."""
    assert "This is a read-only copy of the lab." in TEMPLATE
    assert "if (body !== undefined) throw new Error('This is a read-only copy of the lab." in TEMPLATE
    assert "this is the read-only copy, so testing is switched off" in TEMPLATE.lower()
    assert "It makes no network requests." in TEMPLATE


def test_a_missing_item_is_reported_in_words_and_never_guessed():
    assert "That item is not in this copy." in TEMPLATE
    assert "Object.prototype.hasOwnProperty.call(obj, key)" in TEMPLATE, "an id like __proto__ must not match"


# ------------------------------------------------------------------ the template guard

@pytest.mark.parametrize("needle", [site.TOKEN_META, site.SCRIPT_START, "</head>"])
def test_a_template_that_lost_a_marker_is_refused(needle):
    with pytest.raises(ValueError, match="The page template changed"):
        site.render_page({"payload": {"rules": [], "attacks": []}}, page=TEMPLATE.replace(needle, "", 1))


@pytest.mark.parametrize("needle", [site.TOKEN_META, site.SCRIPT_START, "</head>"])
def test_a_template_with_a_marker_twice_is_refused(needle):
    with pytest.raises(ValueError, match="The page template changed"):
        site.render_page({"payload": {"rules": [], "attacks": []}}, page=TEMPLATE.replace(needle, needle + needle, 1))


def test_a_snapshot_without_replay_still_gets_a_description():
    page = site.render_page({"payload": {"rules": [1, 2], "attacks": [1]}}, page=TEMPLATE)
    description = re.search(r'<meta name="description" content="([^"]+)"', page).group(1)
    assert "2 detection rules as code, tested on made-up logs with 1 planted attacks, a red-team set" in description
    assert "public attack recordings" not in description


def test_a_quote_in_the_description_cannot_break_out_of_the_attribute():
    template = TEMPLATE
    page = site.render_page({"payload": {"rules": [], "attacks": [], "replay": {"summary": {"datasets": '" onload="x'}}}},
                            page=template)
    description = re.search(r'<meta name="description" content="(.*?)">\n', page).group(1)
    assert '"' not in description and "&quot;" in description


# ------------------------------------------------------------------ writing the files

def test_the_site_is_written_as_one_file_with_a_marker_for_github_pages(lab, tmp_path):
    info = site.build_site(lab, tmp_path / "out")
    assert info["files"] == ["index.html", ".nojekyll"] and info["directory"] == str(tmp_path / "out")
    assert sorted(p.name for p in (tmp_path / "out").iterdir()) == [".nojekyll", "index.html"]
    assert (tmp_path / "out" / ".nojekyll").read_text(encoding="utf-8") == ""
    html = (tmp_path / "out" / "index.html").read_text(encoding="utf-8")
    assert info["bytes"] == len(html.encode("utf-8")) and 500_000 < info["bytes"] < 3_000_000


def test_the_export_site_command_writes_the_site(tmp_path, capsys):
    assert main(["export-site", "--out", str(tmp_path / "pages")]) == 0
    out = capsys.readouterr().out
    assert "Wrote" in out and "index.html" in out and "GitHub Pages" in out
    assert (tmp_path / "pages" / "index.html").stat().st_size > 500_000


def test_the_export_site_command_fails_clearly(tmp_path, capsys):
    assert main(["export-site", "--rules", str(tmp_path / "nothing"), "--out", str(tmp_path / "x")]) == 1
    assert "I cannot find the rules folder" in capsys.readouterr().out
    blocked = tmp_path / "file"
    blocked.write_text("not a folder", encoding="utf-8")
    assert main(["export-site", "--out", str(blocked / "inside")]) == 1
    assert "Could not write the site" in capsys.readouterr().out
