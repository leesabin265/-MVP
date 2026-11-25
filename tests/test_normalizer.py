import pytest

from mpg.detection import Location, Normalizer

N = Normalizer()


def test_double_url_encoding_scenario_a():
    r = N.normalize("admin%2527%20OR%201%3D1--", Location.QUERY)
    assert r.text == "admin' or 1=1--"
    assert r.url_rounds == 2
    assert "multi_encoding" in r.signals


def test_single_encoding_is_not_a_signal():
    r = N.normalize("hello%20world", Location.QUERY)
    assert r.text == "hello world"
    assert r.signals == set()


def test_plus_is_space_only_for_query_and_form():
    assert N.normalize("a+b", Location.QUERY).text == "a b"
    assert N.normalize("a+b", Location.FORM).text == "a b"
    assert N.normalize("a+b", Location.JSON).text == "a+b"


def test_excessive_encoding():
    r = N.normalize("%2525252527", Location.QUERY)
    assert "excessive_encoding" in r.signals


def test_html_entity_and_fullwidth():
    r = N.normalize("&lt;script&gt;", Location.JSON)
    assert r.text == "<script>"
    assert "html_entity" in r.signals
    r = N.normalize("＜ｓｃｒｉｐｔ＞", Location.JSON)
    assert r.text == "<script>"
    assert "fullwidth" in r.signals


def test_fullwidth_parentheses_in_korean_are_not_a_signal():
    r = N.normalize("（주）예시상사", Location.JSON)
    assert r.text == "(주)예시상사"
    assert "fullwidth" not in r.signals


def test_inline_and_versioned_comments():
    r = N.normalize("UNION/**/SELECT", Location.JSON)
    assert r.text == "union select"
    assert "comment_obfuscation" in r.signals
    r = N.normalize("/*!50000UNION*/ SELECT", Location.JSON)
    assert r.text == "union select"


def test_mixed_case_signal():
    assert "mixed_case" in N.normalize("SeLeCt", Location.JSON).signals
    for s in ("select", "SELECT", "Select"):
        assert "mixed_case" not in N.normalize(s, Location.JSON).signals


def test_control_chars_removed():
    r = N.normalize("sel\x00ect", Location.JSON)
    assert r.text == "select"
    assert "control_char" in r.signals


def test_js_escape_decoded():
    r = N.normalize(r"\x61\x6c\x65\x72\x74\x28\x31\x29", Location.JSON)
    assert r.text == "alert(1)"
    assert "js_escape" in r.signals


def test_steps_are_recorded_for_console():
    r = N.normalize("admin%2527", Location.QUERY)
    names = [s[0] for s in r.steps]
    assert names[0] == "raw"
    assert names[1].startswith("url_decode")


@pytest.mark.parametrize("value", ["/*" * 50_000, "%" * 100_000, "&" * 100_000, "\\x" * 50_000])
def test_pathological_inputs_finish(value):
    N.normalize(value, Location.JSON)
