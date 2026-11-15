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


def test_intelligence_pagination_is_not_repeated_per_concept():
    class PaginationParser(HTMLParser):
        def __init__(self):
            super().__init__()
            self.template_depth = 0
            self.next_page_depths = []

        def handle_starttag(self, tag, attrs):
            attrs = dict(attrs)
            if tag == "template":
                self.template_depth += 1
            if tag == "button" and attrs.get("aria-label") == "Next page":
                self.next_page_depths.append(self.template_depth)

        def handle_endtag(self, tag):
            if tag == "template":
                self.template_depth -= 1

    parser = PaginationParser()
    parser.feed(app.test_client().get("/intel").get_data(as_text=True))
    assert parser.next_page_depths == [0]
