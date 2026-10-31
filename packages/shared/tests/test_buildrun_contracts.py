import pytest
from pydantic import ValidationError

from routes_shared.buildrun import BuildRunOptions, PatchRejected, TestPlan, validate_patch

GOOD = """diff --git a/app/api/products/route.js b/app/api/products/route.js
index 64a1d2f..d380e64 100644
--- a/app/api/products/route.js
+++ b/app/api/products/route.js
@@ -1,3 +1,3 @@
 a
--- a SQL comment line that was removed
+-- ../../etc/passwd (just text inside a hunk)
 c
"""


def test_valid_patch_lists_changed_files_and_ignores_hunk_content():
    assert validate_patch(GOOD) == ["app/api/products/route.js"]


def test_new_and_deleted_files():
    patch = "--- /dev/null\n+++ b/lib/new.js\n@@ -0,0 +1 @@\n+x\n--- a/old.js\n+++ /dev/null\n@@ -1 +0,0 @@\n-y\n"
    assert validate_patch(patch) == ["lib/new.js", "old.js"]


@pytest.mark.parametrize("patch, message", [
    ("", "empty"),
    ("--- a/../x\n+++ b/../x\n@@ -1 +1 @@\n-a\n+b\n", "unsafe path"),
    ("--- /etc/passwd\n+++ /etc/passwd\n@@ -1 +1 @@\n-a\n+b\n", "unsafe path"),
    ("--- a/.git/hooks/pre-commit\n+++ b/.git/hooks/pre-commit\n@@ -1 +1 @@\n-a\n+b\n", "unsafe path"),
    ("--- a/C:\\x\n+++ b/C:\\x\n@@ -1 +1 @@\n-a\n+b\n", "unsafe path"),
    ("diff --git a/link b/link\nnew file mode 120000\n--- /dev/null\n+++ b/link\n@@ -0,0 +1 @@\n+/etc\n", "symbolic"),
    ("diff --git a/sub b/sub\nnew file mode 160000\n", "symbolic"),
    ("diff --git a/x.png b/x.png\nGIT binary patch\nliteral 0\n", "Binary"),
    ("diff --git a/x b/x\nBinary files a/x and b/x differ\n", "Binary"),
    ("--- a/x\n+++ b/x\n@@ -1,2 +1,2 @@\n-a\n", "truncated"),
    ("diff --git a/x b/y\nrename from x\nrename to ../../y\n", "unsafe path"),
    ("--- a/x\n+++ b/x\n" + "@@ -1 +1 @@\n-a\n+" + "b" * (1024 * 1024) + "\n", "larger than 1 MB"),
])
def test_dangerous_or_malformed_patches_are_rejected(patch, message):
    with pytest.raises(PatchRejected, match=message):
        validate_patch(patch)


def _plan(path="/api", **request):
    return {"tests": [{"id": "t1", "name": "x", "request": {"path": path, **request}, "expect": {}}]}


@pytest.mark.parametrize("path", ["http://169.254.169.254/", "//evil.example/x", "api", "/a b", "/x\r\nHost: y"])
def test_test_plan_only_addresses_the_application(path):
    with pytest.raises(ValidationError):
        TestPlan.model_validate(_plan(path))


def test_test_plan_rejects_header_smuggling_and_duplicate_ids():
    with pytest.raises(ValidationError):
        TestPlan.model_validate(_plan(headers={"Host": "evil"}))
    with pytest.raises(ValidationError):
        TestPlan.model_validate(_plan(headers={"X-A": "1\r\nX-B: 2"}))
    dup = {"tests": [{"id": "a", "name": "x", "request": {"path": "/"}, "expect": {}}] * 2}
    with pytest.raises(ValidationError):
        TestPlan.model_validate(dup)
    with pytest.raises(ValidationError):
        TestPlan.model_validate({"tests": [], "unexpected": True})


def test_options_validate_timeouts_and_package_names():
    assert BuildRunOptions(timeouts={"build": 60}, approved_scripts=["sharp", "@prisma/engines", "<root>"])
    for bad in ({"timeouts": {"build": 1}}, {"timeouts": {"forever": 60}}, {"approved_scripts": ["x; rm -rf /"]}):
        with pytest.raises(ValidationError):
            BuildRunOptions(**bad)
