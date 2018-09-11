SPHINXOPTS    =
SPHINXBUILD   = python -msphinx
SPHINXPROJ    = ida-minsc
SOURCEDIR     = ./source
BUILDDIR      = _build
RSTGENERATE   = python dummyparse.py

MAKEDIR := $(dir $(firstword $(MAKEFILE_LIST)))
ROOTDIR := $(realpath $(MAKEDIR)..)
STATICDIR := ./static

# Various targets used for auto-generation of documentation
base_targets = database enumeration function instruction segment structure
misc_targets = ui tools
custom_targets = tags tagfix
static_targets = $(wildcard $(STATICDIR)/*.rst)

# Put it first so that "make" without argument is like "make help".
help:
	@$(SPHINXBUILD) -M help "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)

.PHONY: help all

## macros for doing stuff

# forwarding things to a sphinx target
define sphinx_target
$(1): source
	@$$(SPHINXBUILD) -M $$@ "$$(SOURCEDIR)" "$$(BUILDDIR)" $$(SPHINXOPTS) $$(O)
endef

define copy_target
$(1): $(2)
	$$(info [*] Copying file from $(2) to $(1))
	cp '$(2)' '$(1)'
endef

# generate documentation from a module
define make_docs
$(1): $(2)
	$$(info [*] Writing documentation for $(2) to $(1))
	$$(RSTGENERATE) -o '$$@' '$$<' $(3)
endef

## default sphinxbuild targets
_sphinx_targets  = html dirhtml singlehtml pickle json htmlhelp qthelp devhelp
_sphinx_targets += epub latex latexpdf latexpdfja text man textinfo info
_sphinx_targets += gettext changes xml pseudoxml linkcheck doctest coverage

$(foreach target,$(_sphinx_targets),$(eval $(call sphinx_target,$(target))))

all: configuration source | html

configuration: $(SOURCEDIR)/conf.py
	$(info [*] Duplicated configuration into $<)

## targets for auto-generating docs

# base modules
$(foreach target,$(base_targets),$(eval $(call make_docs,$(SOURCEDIR)/$(target).rst,$(ROOTDIR)/base/$(target).py)))

# miscellaneous modules
$(foreach target,$(misc_targets),$(eval $(call make_docs,$(SOURCEDIR)/$(target).rst,$(ROOTDIR)/misc/$(target).py)))

# custom modules
$(foreach target,$(custom_targets),$(eval $(call make_docs,$(SOURCEDIR)/$(target).rst,$(ROOTDIR)/custom/$(target).py)))

# static targets
$(foreach target,$(static_targets),$(eval $(call copy_target,$(SOURCEDIR)/$(notdir $(target)),$(target))))

# auto-generation of all modules
_source_targets = $(foreach target,$(base_targets) $(misc_targets) $(custom_targets),source/$(target).rst)
_static_targets = $(foreach target,$(static_targets),$(SOURCEDIR)/$(notdir $(target)))
source: $(_source_targets) $(_static_targets)
	$(info [!] Completed generation of documentation)

# configuration file
$(eval $(call copy_target,$(SOURCEDIR)/conf.py,$(MAKEDIR)conf.py))
