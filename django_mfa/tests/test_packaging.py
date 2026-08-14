"""Guard the built distribution, not the source tree.

Every other test in this suite runs from a source checkout, where every
subpackage is present on disk no matter what the packaging metadata says.
That is exactly why the packaging bug these tests exist to prevent survived
21 implementation tasks, two code reviews, and a real-browser validation
pass: the old setup.py hardcoded

    packages=["django_mfa", "django_mfa.templatetags", "django_mfa.migrations"]

which predated django_mfa/adapters/ and django_mfa/views/. The built wheel
contained neither, so `pip install django-mfa` produced a package that raised
ImportError from DjangoMfaAppConfig.ready() before a host project could serve
a single request -- while this suite stayed green.

These tests build a real wheel and inspect it. They are skipped (never
failed) when the build backend isn't available, so a contributor without
`build` installed doesn't get a spurious failure.
"""

import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def _build_wheel(outdir):
    """Build a wheel into ``outdir``; return its path, or None if unbuildable."""
    try:
        subprocess.run(
            [sys.executable, "-m", "build", "--wheel", "--outdir", str(outdir),
             str(REPO_ROOT)],
            check=True, capture_output=True, timeout=600,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired,
            FileNotFoundError):
        return None
    wheels = list(Path(outdir).glob("*.whl"))
    return wheels[0] if wheels else None


def _on_disk_packages():
    """Every importable package under django_mfa/, as dotted names."""
    packages = set()
    for init in (REPO_ROOT / "django_mfa").rglob("__init__.py"):
        packages.add(".".join(init.parent.relative_to(REPO_ROOT).parts))
    return packages


@unittest.skipUnless(
    __import__("importlib.util", fromlist=["util"]).find_spec("build"),
    "the `build` package is not installed",
)
class WheelContentsTests(unittest.TestCase):
    """Build the wheel once for the whole class -- it is the slow part."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._tmp = tempfile.TemporaryDirectory()
        cls.wheel = _build_wheel(cls._tmp.name)
        if cls.wheel is None:
            cls._tmp.cleanup()
            raise unittest.SkipTest("wheel build failed in this environment")
        cls.names = zipfile.ZipFile(cls.wheel).namelist()

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()
        super().tearDownClass()

    def test_every_package_on_disk_ships_in_the_wheel(self):
        """The regression guard. A new subpackage added under django_mfa/ is
        shipped automatically by hatchling's `packages = ["django_mfa"]`; if
        someone reintroduces an explicit per-package list and forgets one,
        this fails naming the missing package.
        """
        shipped = {
            ".".join(Path(n).parent.parts)
            for n in self.names if n.endswith("/__init__.py")
        }
        missing = _on_disk_packages() - shipped
        self.assertEqual(
            missing, set(),
            f"these packages exist on disk but are NOT in the built wheel: "
            f"{sorted(missing)} -- a host project installing from PyPI would "
            f"get an ImportError, exactly as it did when setup.py's hardcoded "
            f"packages=[...] list omitted adapters/ and views/")

    def test_templates_and_static_files_ship(self):
        """These live inside the package but are not .py files, so they ride
        on the build backend's file inclusion rather than package discovery.
        MANIFEST.in used to declare them; hatchling includes them because they
        sit under the package root.
        """
        for needle in ("django_mfa/templates/django_mfa/security.html",
                       "django_mfa/static/django_mfa/webauthn.js",
                       "django_mfa/static/django_mfa/style.css"):
            self.assertIn(needle, self.names, f"{needle} missing from the wheel")

    def test_translation_catalogs_ship(self):
        """Catalogs ride on file inclusion too, and their absence is silent.

        Django looks for <app>/locale/<lang>/LC_MESSAGES/ inside the
        *installed* package. A wheel without it doesn't error -- gettext
        simply finds no catalog and every string falls back to the English
        source, so a fully translated install looks untranslated with
        nothing in the logs to say why.

        The .mo files are the load-bearing half: gettext reads only those,
        so a wheel carrying every .po and no .mo is a wheel with no
        translations in it whatsoever, and looks complete in a file listing.
        They are also the half most easily lost, being the only binary
        artifact here and the natural thing for an ignore rule to sweep up
        (which .gitignore's blanket `*.mo` did, until the negation in it).
        """
        self.assertIn("django_mfa/locale/django.pot", self.names)
        locale = REPO_ROOT / "django_mfa" / "locale"
        for suffix in (".po", ".mo"):
            in_wheel = sorted(
                n for n in self.names
                if n.startswith("django_mfa/locale/")
                and n.endswith(f"/LC_MESSAGES/django{suffix}"))
            on_disk = sorted(
                p.relative_to(REPO_ROOT).as_posix()
                for p in locale.glob(f"*/LC_MESSAGES/django{suffix}"))
            with self.subTest(suffix=suffix):
                self.assertTrue(on_disk, f"no django{suffix} files on disk")
                self.assertEqual(
                    in_wheel, on_disk,
                    f"the django{suffix} catalogs on disk and in the wheel "
                    f"disagree")

    def test_migrations_ship(self):
        """A Django app whose migrations don't ship leaves `migrate` with
        nothing to apply and no error -- the tables simply never exist.
        """
        migrations = [n for n in self.names
                      if n.startswith("django_mfa/migrations/") and n.endswith(".py")]
        self.assertGreaterEqual(len(migrations), 8)  # 0001..0007 + __init__
