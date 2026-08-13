# Contributing

Feel free to create a new Pull request if you want to propose a new feature or fix a bug.

## Development setup

This project uses [uv](https://docs.astral.sh/uv/). There is no `requirements.txt` or `setup.py` -- `pyproject.toml` is the only packaging file, and `uv run` creates and syncs the environment for you, so there is no virtualenv to activate:

    uv run python test_runner.py          # the whole suite
    uv run ruff check .                   # lint
    uv run ruff check . --fix             # and fix what's auto-fixable

To run a single test, pass a label -- `test_runner.py` falls back to the whole suite only when given none:

    uv run python test_runner.py django_mfa.tests.test_conf

To check one Python/Django combination locally (CI runs the full grid of Python 3.10-3.13 against Django 4.2 and 5.2):

    uv run --python 3.12 --with "django~=4.2.0" python test_runner.py

## Documentation

The docs are Markdown, read by Sphinx through [MyST](https://myst-parser.readthedocs.io/), and live in `docs/`:

    cd docs && make html          # build into docs/_build/html
    cd docs && make linkcheck     # verify external links still resolve

`-W` is on by default, so a warning fails the build here exactly as it does in CI and on Read the Docs.

Two things that build output alone will *not* catch, both pinned by `django_mfa/tests/test_docs.py` instead:

- With MyST's `colon_fence` extension off, `:::{warning}` is not an error -- it renders the literal text `:::{warning}` into the published page and the build still reports success.
- A page missing from `index.md`'s toctree builds fine and simply never gets linked.

When you add a setting to `django_mfa/conf.py`, document it in `docs/settings.md` in the same change; a test asserts every key in `DEFAULTS` appears there.

## Releasing

Releases publish themselves. There is no API token to hold, and nobody runs
`twine upload` by hand: PyPI is configured to trust `.github/workflows/publish.yml`
in this repository via OpenID Connect, and mints a short-lived, project-scoped
upload token for that workflow alone.

To cut a release, in full:

1.  Bump `version` in `pyproject.toml` and add that version's section to
    `CHANGELOG.md`, in the same PR. Merge it to `master`.

There is no step 2. You never create a tag and you never create a GitHub
Release -- `.github/workflows/tag-release.yml` sees the version change, creates
tag `v<version>` on the commit that carried it, publishes a GitHub Release
(marked pre-release if PEP 440 says the version is one), and starts
`publish.yml` against that tag.

`pyproject.toml` is the only place a version string is written anywhere in this
project: `django_mfa.__version__` and `docs/conf.py` both read it back from the
installed package metadata. Deriving the tag from it too means there is nothing
left that can disagree with anything else.

`publish.yml` then tests the oldest and newest supported Python/Django
combinations, builds the sdist and wheel, checks the README renders on PyPI,
installs the wheel into a clean environment and starts Django against it, and
only then uploads.

Two guards survive from when tags were typed by hand, because the cost of
getting a version wrong is unbounded -- PyPI does not allow re-uploading one:

- The tag must match `pyproject.toml`'s `version`. Nothing in the build
  connects them: hatchling never looks at the tag, so a release tagged `v4.0.0`
  cut from a tree still saying `4.0.0a1` would publish `4.0.0a1` and report
  success. That is not hypothetical -- it happened on 2026-08-13, and this
  guard is what stopped it.
- The publish job must run on a tag ref. The `pypi` deployment environment only
  accepts tags matching `v*`, and the guard fails loudly rather than skipping
  when handed a branch.

To release a version already sitting on `master` -- or the first time, when the
version predates all of this -- run **Tag release** from the Actions tab
manually. Re-running it is harmless: if `v<version>` already exists it does
nothing.

:::{warning}
Renaming `publish.yml`, or the `pypi` environment, breaks publishing --
both names are part of what PyPI trusts, and a mismatch is rejected at upload
time with an authentication error that does not mention the rename. Change it on
[PyPI](https://pypi.org/manage/project/django-mfa/settings/publishing/) first.

`tag-release.yml` reaches `publish.yml` through `workflow_dispatch`, not through
the Release it just created, and that is not incidental. GitHub suppresses
workflow runs caused by its own `GITHUB_TOKEN` so workflows cannot loop, with
`workflow_dispatch` and `repository_dispatch` as the only exceptions. Chaining
on `release: published` instead fails *silently*: the Release appears, nothing
publishes, and no workflow run exists anywhere to explain why.
:::

## Sending pull requests

1.  Fork the repo:

        https://github.com/MicroPyramid/django-mfa

2.  Create a branch for your specific changes:

        $ git checkout master
        $ git pull
        $ git checkout -b feature

    To simplify things, please, make one branch per issue (pull request). It's also important to make sure your branch is up-to-date with upstream master, so that maintainers can merge changes easily.

3.  Commit changes. Please update docs, if relevant.

4.  Don't forget to run the tests (and `ruff`) to check that nothing breaks.

5.  Ideally, write your own tests for new feature/bug fix.

6.  Submit a [pull request](https://help.github.com/articles/using-pull-requests).
