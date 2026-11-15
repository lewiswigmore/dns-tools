from html.parser import HTMLParser

import pytest

from app import app


class DialogMarkupParser(HTMLParser):
    void_tags = {
        "area", "base", "br", "col", "embed", "hr", "img", "input",
        "link", "meta", "param", "source", "track", "wbr",
    }

    def __init__(self):
        super().__init__()
        self.stack = []
        self.errors = []

    def handle_starttag(self, tag, attrs):
        if tag not in self.void_tags:
            self.stack.append(tag)

    def handle_endtag(self, tag):
        if tag in self.void_tags:
            return
        if tag.startswith("ui-dialog") and (not self.stack or self.stack[-1] != tag):
            self.errors.append((tag, self.stack[-1] if self.stack else None))
        if tag in self.stack:
            self.stack = self.stack[:len(self.stack) - 1 - self.stack[::-1].index(tag)]


@pytest.mark.parametrize("path", ["/", "/history", "/intel", "/resources"])
def test_dialog_content_is_not_nested_under_unclosed_elements(path):
    response = app.test_client().get(path)
    assert response.status_code == 200
    parser = DialogMarkupParser()
    parser.feed(response.get_data(as_text=True))
    assert not parser.errors
