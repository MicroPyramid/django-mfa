# Minimal Sphinx makefile.
#
# Replaces a 190-line sphinx-quickstart dump that carried ~20 targets nobody
# ran (qthelp, devhelp, applehelp, texinfo, latexpdfja, pseudoxml...) and set
# BUILDDIR = build, while conf.py excludes `_build` and both CI and Read the
# Docs build into `_build`. The stale target was the one people actually hit.
#
# You do not need Sphinx on your PATH: `uv run` provides it from the `docs`
# dependency group.
#
#   make html        build into _build/html
#   make linkcheck   verify every external link still resolves
#   make clean       remove _build

SPHINXBUILD ?= uv run --group docs sphinx-build
SOURCEDIR   = .
BUILDDIR    = _build

# -W turns warnings into errors, matching CI and .readthedocs.yaml, so a dead
# cross-reference fails here rather than shipping.
SPHINXOPTS ?= -W

.PHONY: help html linkcheck clean

help:
	@echo "make html        build the HTML docs into $(BUILDDIR)/html"
	@echo "make linkcheck   check external links"
	@echo "make clean       remove $(BUILDDIR)"

html:
	$(SPHINXBUILD) $(SPHINXOPTS) -b html $(SOURCEDIR) $(BUILDDIR)/html
	@echo
	@echo "Done. Open $(BUILDDIR)/html/index.html"

linkcheck:
	$(SPHINXBUILD) -b linkcheck $(SOURCEDIR) $(BUILDDIR)/linkcheck

clean:
	rm -rf $(BUILDDIR)
