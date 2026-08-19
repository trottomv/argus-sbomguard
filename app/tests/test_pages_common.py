from api.pages.common import dep_name


class TestDepName:
    def test_with_name_and_version(self):
        assert dep_name("lodash", "4.17.20", "pkg:npm/lodash@4.17.20") == "lodash 4.17.20"

    def test_with_name_no_version(self):
        assert dep_name("lodash", None, None) == "lodash"

    def test_purl_with_version(self):
        assert dep_name(None, None, "pkg:npm/lodash@4.17.20") == "lodash 4.17.20"

    def test_purl_without_version(self):
        assert dep_name(None, None, "pkg:npm/lodash") == "lodash"

    def test_purl_single_segment(self):
        assert dep_name(None, None, "lodash") == "lodash"

    def test_purl_query_string(self):
        assert dep_name(None, None, "pkg:npm/lodash?x=y") == "lodash"

    def test_empty_all(self):
        assert dep_name(None, None, None) == "-"
