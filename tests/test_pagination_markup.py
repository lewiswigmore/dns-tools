from html.parser import HTMLParser

import pytest

from app import app


class PaginationParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.template_depth = 0
        self.pagination_inside_loop = False
        self.pagination_count = 0

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "template":
            if self.template_depth:
                self.template_depth += 1
            elif any(
                collection in attrs.get("x-for", "")
                for collection in ("paginatedConcepts", "paginatedHistory")
            ):
                self.template_depth = 1
        if attrs.get("aria-label") == "Pagination":
            self.pagination_count += 1
            if self.template_depth:
                self.pagination_inside_loop = True

    def handle_endtag(self, tag):
        if tag == "template" and self.template_depth:
            self.template_depth -= 1


@pytest.mark.parametrize("route", ["/intel", "/history"])
def test_pagination_is_outside_repeated_entries(route):
    response = app.test_client().get(route)
    parser = PaginationParser()
    parser.feed(response.get_data(as_text=True))
    assert parser.pagination_count == 1
    assert not parser.pagination_inside_loop
