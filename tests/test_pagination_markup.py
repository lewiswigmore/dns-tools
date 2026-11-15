from html.parser import HTMLParser

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
            elif attrs.get("x-for", "").startswith("concept in "):
                self.template_depth = 1
        if attrs.get("aria-label") == "Pagination":
            self.pagination_count += 1
            if self.template_depth:
                self.pagination_inside_loop = True

    def handle_endtag(self, tag):
        if tag == "template" and self.template_depth:
            self.template_depth -= 1


def test_intelligence_pagination_is_outside_concept_cards():
    response = app.test_client().get("/intel")
    parser = PaginationParser()
    parser.feed(response.get_data(as_text=True))
    assert parser.pagination_count == 1
    assert not parser.pagination_inside_loop
