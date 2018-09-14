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
TEMPLATEDIR := templates
HTMLDIR := html

# Various targets used for auto-generation of documentation
base_targets = database enumeration function instruction segment structure
misc_targets = ui tools
custom_targets = tags tagfix

image_path = _images
static_path = _static
template_path = _templates

# Save the current branch state
cwd := $(realpath .)
branch := $(shell git symbolic-ref --short HEAD)
revision := $(shell git rev-parse HEAD)

# Put it first so that "make" without argument is like "make help".
help:
	@$(SPHINXBUILD) -M help "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)

.PHONY: help build configuration source gh-pages

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

all: build

build: configuration source | html
	$(info [*] Successfully built html documentation)

configuration: $(SOURCEDIR)/conf.py
	$(info [*] Successfuly copied configuration into $<)

source: $(SOURCEDIR)
	$(info [*] Successfuly built source in $<)

gh-pages: build
	$(info [*] Checking out branch: $@)
	@git -C '$(ROOTDIR)' checkout -f '$@' 2>/dev/null
	@git status --porcelain | grep ^A | tr ' ' ':' | cut -d: -f3 | xargs git -C '$(ROOTDIR)' reset
	$(info [*] Moving documentation to target directory: $(ROOTDIR))
	@tar -C '$(BUILDDIR)/html' -cf- . | tar -xvf- -C '$(ROOTDIR)'
	$(info [*] Creating commit from recent build of documentation)
	@tar -C '$(BUILDDIR)/html' -cf- . | tar -tf- | xargs git -C '$(ROOTDIR)' add
	-git commit -m 'gh-pages: built documents from commit $(revision). '
	$(info [*] Successfully committed documentation to branch: $@)
	@git -C '$(ROOTDIR)' checkout -f '$(branch)' 2>/dev/null
	$(info [*] Restored previous branch: $(branch))

## targets for auto-building documentation
_source_targets = $(foreach target,$(base_targets),$(SOURCEDIR)/$(MODULEDIR)/$(target).rst)
_source_targets+= $(foreach target,$(misc_targets),$(SOURCEDIR)/$(MODULEDIR)/misc-$(target).rst)
_source_targets+= $(foreach target,$(custom_targets),$(SOURCEDIR)/$(MODULEDIR)/custom-$(target).rst)
_static_targets = $(foreach target,$(wildcard $(STATICDIR)/*.rst),$(SOURCEDIR)/$(notdir $(target)))
_image_targets = $(foreach image,$(wildcard $(IMAGEDIR)/*),$(SOURCEDIR)/$(image_path)/$(notdir $(image)))
_template_targets = $(foreach target,$(wildcard $(TEMPLATEDIR)/*),$(SOURCEDIR)/$(template_path)/$(notdir $(target)))
_html_targets = $(foreach target,$(wildcard $(HTMLDIR)/*),$(SOURCEDIR)/$(static_path)/$(notdir $(target)))

$(SOURCEDIR): $(SOURCEDIR)/index.rst $(_source_targets) $(_static_targets) $(_image_targets) $(_template_targets) $(_html_targets) | $(SOURCEDIR)/
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
$(eval $(call require_directory,$(SOURCEDIR)/$(template_path)/))

# static targets ($source.rst)
$(foreach source,$(wildcard $(STATICDIR)/*.rst),$(eval $(call copy_target,$(SOURCEDIR)/$(notdir $(source)),$(source))))

# templates (_templates/$source)
$(foreach source,$(wildcard $(TEMPLATEDIR)/*),$(eval $(call copy_target,$(SOURCEDIR)/$(template_path)/$(notdir $(source)),$(source))))

# image files (_images/$image)
$(foreach image,$(wildcard $(IMAGEDIR)/*),$(eval $(call copy_target,$(SOURCEDIR)/$(image_path)/$(notdir $(image)),$(image))))

# html static files (_static/$image)
$(foreach source,$(wildcard $(HTMLDIR)/*),$(eval $(call copy_target,$(SOURCEDIR)/$(static_path)/$(notdir $(source)),$(source))))

# configuration file (conf.py)
$(eval $(call copy_target,$(SOURCEDIR)/conf.py,$(MAKEDIR)conf.py))

# index file
$(eval $(call copy_target,$(SOURCEDIR)/index.rst,$(MAKEDIR)index.rst))
