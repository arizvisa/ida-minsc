SPHINXOPTS    =
SPHINXBUILD   = python -msphinx
SPHINXPROJ    = ida-minsc
SOURCEDIR     = _source
BUILDDIR      = _build
RSTGENERATE   = python docparse.py

MAKEDIR := $(dir $(firstword $(MAKEFILE_LIST)))
ROOTDIR := $(realpath $(MAKEDIR)..)
MODULEDIR := modules
STATICDIR := static
IMAGEDIR := images

# Various targets used for auto-generation of documentation
base_targets = database enumeration function instruction segment structure
misc_targets = ui tools
custom_targets = tags tagfix

image_path = _images
static_path = _static

# Put it first so that "make" without argument is like "make help".
help:
	@$(SPHINXBUILD) -M help "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)

.PHONY: help all configuration source

## macros for doing stuff

# forwarding things to a sphinx target
define sphinx_target
$(1): source
	@$$(SPHINXBUILD) -M $$@ "$$(SOURCEDIR)" "$$(BUILDDIR)" $$(SPHINXOPTS) $$(O)
endef

define copy_target
$(1): $(2) | $$(dir $(1))
	$$(info [*] Copying file from $(2) to $(1))
	cp '$(2)' '$(1)'
endef

define require_directory
$(1):
	$$(info [*] Creating required directory for source in $(1))
	@mkdir -p $(1)
endef

# generate documentation from a module
define make_docs
$(1): $(2) | $$(dir $(1))
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
	$(info [*] Successfuly copied configuration into $<)

source: $(SOURCEDIR)
	$(info [*] Successfuly build source in $<)

## targets for auto-building documentation
_source_targets = $(foreach target,$(base_targets),$(SOURCEDIR)/$(MODULEDIR)/$(target).rst)
_source_targets+= $(foreach target,$(misc_targets),$(SOURCEDIR)/$(MODULEDIR)/misc-$(target).rst)
_source_targets+= $(foreach target,$(custom_targets),$(SOURCEDIR)/$(MODULEDIR)/custom-$(target).rst)
_static_targets = $(foreach target,$(wildcard $(STATICDIR)/*.rst),$(SOURCEDIR)/$(notdir $(target)))
_image_targets = $(foreach image,$(wildcard $(IMAGEDIR)/*),$(SOURCEDIR)/$(image_path)/$(notdir $(image)))
$(SOURCEDIR): $(SOURCEDIR)/index.rst $(_source_targets) $(_static_targets) $(_image_targets) | $(SOURCEDIR)/
	$(info [!] Completed building of documentation)

# base modules (module/$source.rst)
sources = $(foreach module,$(base_targets),base/$(module))
$(foreach source,$(sources),$(eval $(call make_docs,$(SOURCEDIR)/$(MODULEDIR)/$(notdir $(source)).rst,$(ROOTDIR)/$(source).py)))

# miscellaneous modules (module/misc-$source.rst)
sources = $(foreach module,$(misc_targets),misc/$(module))
$(foreach source,$(sources),$(eval $(call make_docs,$(SOURCEDIR)/$(MODULEDIR)/misc-$(notdir $(source)).rst,$(ROOTDIR)/$(source).py)))

# custom modules (module/custom-$source.rst)
sources = $(foreach module,$(custom_targets),custom/$(module))
$(foreach source,$(sources),$(eval $(call make_docs,$(SOURCEDIR)/$(MODULEDIR)/custom-$(notdir $(source)).rst,$(ROOTDIR)/$(source).py)))

## targets for shuffling files around
$(eval $(call require_directory,$(SOURCEDIR)/))
$(eval $(call require_directory,$(SOURCEDIR)/$(MODULEDIR)/))
$(eval $(call require_directory,$(SOURCEDIR)/$(image_path)/))
$(eval $(call require_directory,$(SOURCEDIR)/$(static_path)/))

# static targets ($source.rst)
$(foreach source,$(wildcard $(STATICDIR)/*.rst),$(eval $(call copy_target,$(SOURCEDIR)/$(notdir $(source)),$(source))))

# image files
$(foreach image,$(wildcard $(IMAGEDIR)/*),$(eval $(call copy_target,$(SOURCEDIR)/_images/$(notdir $(image)),$(image))))

# configuration file
$(eval $(call copy_target,$(SOURCEDIR)/conf.py,$(MAKEDIR)conf.py))

# index file
$(eval $(call copy_target,$(SOURCEDIR)/index.rst,$(MAKEDIR)index.rst))
