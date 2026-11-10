from html.parser import HTMLParser

import pytest

from app import app


class Elements(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.tags = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))


@pytest.mark.parametrize("route", ["/lookup", "/mx", "/dmarc", "/whois"])
def test_result_actions_keep_accessible_text_on_mobile(route):
    response = app.test_client().get(route)
    assert response.status_code == 200
    elements = Elements(response.get_data(as_text=True)).tags
    assert any("result-toolbar" in attrs.get("class", "") for _, attrs in elements)
    assert any("result-actions" in attrs.get("class", "") for _, attrs in elements)
    assert sum("action-label" in attrs.get("class", "") for _, attrs in elements) >= 2
    export = next(
        attrs for tag, attrs in elements
        if tag == "button" and attrs.get("@click") == "exportResults"
    )
    assert export["title"] == "Export results"


def test_mobile_navigation_has_named_controls_and_focus_management():
    elements = Elements(app.test_client().get("/").get_data(as_text=True)).tags
    sidebar = next(attrs for tag, attrs in elements if tag == "aside")
    assert sidebar[":inert"] == "!desktopMenu && !mobileMenuOpen"
    assert "@keydown.tab" in sidebar
    toggle = next(
        attrs for tag, attrs in elements
        if tag == "button" and attrs.get("aria-controls") == sidebar["id"]
    )
    assert toggle["aria-label"] == "Open navigation"
    assert toggle[":aria-expanded"] == "mobileMenuOpen"
    assert "$refs.menuClose.focus()" in toggle["@click"]
    main = next(attrs for tag, attrs in elements if tag == "main")
    assert main[":inert"] == "mobileMenuOpen"
    settings = next(
        attrs for tag, attrs in elements
        if tag == "button" and attrs.get("aria-label") == "Settings"
    )
    assert "mobileMenuOpen = false" in settings["@click"]
    assert "getElementById('settings-close').focus()" in settings["@click"]


def test_library_icon_pagination_controls_have_names():
    elements = Elements(app.test_client().get("/resources").get_data(as_text=True)).tags
    for action, label in [
        ("goToFirstPage()", "First page"),
        ("previousPage()", "Previous page"),
        ("nextPage()", "Next page"),
        ("goToLastPage()", "Last page"),
    ]:
        button = next(
            attrs for tag, attrs in elements
            if tag == "button" and attrs.get("@click") == action
        )
        assert button["aria-label"] == label


@pytest.mark.parametrize("route", ["/", "/lookup", "/mx", "/dmarc", "/whois", "/headers", "/history", "/resources", "/intel", "/tools"])
def test_shared_mobile_foundations_are_present(route):
    html = app.test_client().get(route).get_data(as_text=True)
    elements = Elements(html).tags
    viewport = next(attrs for tag, attrs in elements if tag == "meta" and attrs.get("name") == "viewport")
    assert "user-scalable=no" not in viewport["content"]
    assert "maximum-scale" not in viewport["content"]
    assert "textarea,select{font-size:16px" in html
    assert "--bg-canvas:" in html
    assert "prefers-reduced-motion:reduce" in html
    assert "DOMContentLoaded" in html


@pytest.mark.parametrize("route", ["/lookup", "/mx", "/dmarc", "/whois"])
def test_async_results_have_loading_feedback(route):
    elements = Elements(app.test_client().get(route).get_data(as_text=True)).tags
    assert any(attrs.get("role") == "status" and attrs.get("aria-live") == "polite" for _, attrs in elements)
    assert any("loading-skeleton" in attrs.get("class", "") for _, attrs in elements)


@pytest.mark.parametrize("route", ["/mx", "/dmarc"])
def test_compare_switch_and_domain_input_are_labelled(route):
    elements = Elements(app.test_client().get(route).get_data(as_text=True)).tags
    switch = next(attrs for tag, attrs in elements if tag == "input" and attrs.get("x-model") == "compareMode")
    assert switch["aria-label"] == "Compare DNS providers"
    domain = next(attrs for tag, attrs in elements if tag == "input" and attrs.get("x-model") == "domain")
    assert any(tag == "label" and attrs.get("for") == domain["id"] for tag, attrs in elements)


@pytest.mark.parametrize("route,action", [
    ("/", "showSessionModal = true"),
    ("/history", "showPreview(item)"),
    ("/resources", "showConcept(item.title)"),
    ("/intel", "showConcept(concept)"),
])
def test_interactive_cards_support_keyboard(route, action):
    elements = Elements(app.test_client().get(route).get_data(as_text=True)).tags
    card = next(attrs for _, attrs in elements if attrs.get("@click") == action)
    assert card["role"] == "button"
    assert card["tabindex"] == "0"
    assert any(key.startswith("@keydown.enter") for key in card)
    assert any(key.startswith("@keydown.space") for key in card)
