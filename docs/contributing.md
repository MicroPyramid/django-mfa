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
