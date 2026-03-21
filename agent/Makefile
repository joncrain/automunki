# AutoMunki macOS client — Swift postflight (sources in src/, universal binary in build/).
#
# Targets:
#   build / sign / install — binary pipeline; install = copy signed binaries into payload/
#   pkg              — unsigned installer: build → payload → pkgbuild → build/$(PKG_NAME).unsigned.pkg
#   package          — signed installer: install → pkgbuild → productsign → build/$(PKG_NAME).pkg
#   all              — release: build sign install package (needs signing identities)
#   install-local    — unsigned binary straight to /usr/local/munki
#
NAME := automunki-client
VERSION := 1.0
INSTALL_DIRECTORY := /usr/local/munki

SCRIPT_DIR := $(shell pwd)
INSTALL_DIR := $(SCRIPT_DIR)/payload$(INSTALL_DIRECTORY)
BUILD_DIR := $(SCRIPT_DIR)/build
SRC_DIR := $(SCRIPT_DIR)/src
TARGET := 11

ifneq ($(wildcard $(SCRIPT_DIR)/../.env),)
    $(foreach line,$(shell awk '!/^#/ && !/^[[:space:]]*$$/ {print $$0}' $(SCRIPT_DIR)/../.env | sed 's/^\([^=]*\)=["'\'']\(.*\)["'\'']$$/\1=\2/'),$(eval export $(line)))
endif

CODESIGN_ID ?= $(DEV_CODESIGN_ID)
PKG_SIGN_ID ?= $(DEV_PKG_SIGN_ID)

CODESIGN_ID_SHA1 := $(shell /usr/bin/security find-identity -v -p codesigning \
	| /usr/bin/grep "$(CODESIGN_ID)" \
	| /usr/bin/head -n 1 \
	| /usr/bin/awk '{print $$2}')

PKG_PREFIX ?= com.automunki.pkg
PKG_ID := $(PKG_PREFIX).$(NAME)
PKG_NAME := $(NAME)-$(VERSION)

SWIFT_SOURCES := $(wildcard $(SRC_DIR)/*.swift)
SWIFT_BINS := $(basename $(notdir $(SWIFT_SOURCES)))
ALL_BINS := $(SWIFT_BINS)

.PHONY: all clean build sign install package pkg stage-payload-unsigned install-local clean-all

all: build sign install package

$(BUILD_DIR):
	@git lfs pull 2>/dev/null || true
	/bin/mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%_x86_64: $(SRC_DIR)/%.swift | $(BUILD_DIR)
	/usr/bin/xcrun -sdk macosx swiftc -O -target x86_64-apple-macos$(TARGET) $< -o $@

$(BUILD_DIR)/%_arm64: $(SRC_DIR)/%.swift | $(BUILD_DIR)
	/usr/bin/xcrun -sdk macosx swiftc -O -target arm64-apple-macos$(TARGET) $< -o $@

define make-universal-swift
$(BUILD_DIR)/$(1): $(BUILD_DIR)/$(1)_x86_64 $(BUILD_DIR)/$(1)_arm64
	/usr/bin/lipo -create $$^ -output $$@
	/bin/rm $$^
	/bin/chmod +x $$@
endef

$(foreach bin,$(SWIFT_BINS),$(eval $(call make-universal-swift,$(bin))))

build: $(addprefix $(BUILD_DIR)/,$(ALL_BINS))

sign: build
	@for binary in $(ALL_BINS); do \
		echo "Signing $$binary..."; \
		/usr/bin/codesign -s $(CODESIGN_ID_SHA1) $(BUILD_DIR)/$$binary || { echo "ERROR: Failed to sign $$binary"; exit 1; }; \
		echo "Successfully signed $$binary"; \
	done

install: sign
	@echo "Staging signed binaries to $(INSTALL_DIR)"
	@/bin/mkdir -p $(INSTALL_DIR)
	@for binary in $(ALL_BINS); do \
		/bin/cp $(BUILD_DIR)/$$binary $(INSTALL_DIR)/$$binary; \
		echo "Staged $$binary"; \
	done

# Unsigned binary into payload/ (for make pkg without codesigning)
stage-payload-unsigned: build
	@echo "Staging unsigned binaries to $(INSTALL_DIR)"
	@/bin/mkdir -p $(INSTALL_DIR)
	@for binary in $(ALL_BINS); do \
		/bin/cp $(BUILD_DIR)/$$binary $(INSTALL_DIR)/$$binary; \
		echo "Staged $$binary"; \
	done

pkg: stage-payload-unsigned
	@echo "Building unsigned component package $(PKG_NAME)..."
	@/bin/mkdir -p $(BUILD_DIR)
	@if [ -d "$(SCRIPT_DIR)/scripts" ]; then \
		/usr/bin/pkgbuild --root $(SCRIPT_DIR)/payload \
			--identifier $(PKG_ID) --version $(VERSION) --install-location / \
			--scripts $(SCRIPT_DIR)/scripts --ownership recommended \
			$(BUILD_DIR)/$(PKG_NAME).unsigned.pkg; \
	else \
		/usr/bin/pkgbuild --root $(SCRIPT_DIR)/payload \
			--identifier $(PKG_ID) --version $(VERSION) --install-location / \
			--ownership recommended \
			$(BUILD_DIR)/$(PKG_NAME).unsigned.pkg; \
	fi
	@echo "Unsigned package: $(BUILD_DIR)/$(PKG_NAME).unsigned.pkg"
	@echo "Install: sudo installer -pkg $(BUILD_DIR)/$(PKG_NAME).unsigned.pkg -target /"

package: install
	@echo "Building package $(PKG_NAME)..."
ifeq ($(PRODUCT_ARCHIVE),True)
	@if [ -z "$(PKG_SIGN_ID)" ]; then \
		echo "ERROR: Set PKG_SIGN_ID or DEV_PKG_SIGN_ID for product archive signing."; \
		echo "For an unsigned .pkg, run: make pkg"; \
		exit 1; \
	fi
	@if [ -d "$(SCRIPT_DIR)/scripts" ]; then \
		/usr/bin/pkgbuild --root $(SCRIPT_DIR)/payload \
			--identifier $(PKG_ID) --version $(VERSION) --install-location / \
			--scripts $(SCRIPT_DIR)/scripts --ownership recommended \
			$(BUILD_DIR)/$(PKG_NAME).component.pkg; \
	else \
		/usr/bin/pkgbuild --root $(SCRIPT_DIR)/payload \
			--identifier $(PKG_ID) --version $(VERSION) --install-location / \
			--ownership recommended $(BUILD_DIR)/$(PKG_NAME).component.pkg; \
	fi
	@if [ ! -f "$(SCRIPT_DIR)/distribution.xml" ]; then \
		/usr/bin/productbuild --synthesize \
			--package $(BUILD_DIR)/$(PKG_NAME).component.pkg $(BUILD_DIR)/distribution.xml; \
	else \
		cp $(SCRIPT_DIR)/distribution.xml $(BUILD_DIR)/distribution.xml; \
	fi
	@/usr/bin/productbuild --distribution $(BUILD_DIR)/distribution.xml \
		--package-path $(BUILD_DIR) --sign "$(PKG_SIGN_ID)" $(BUILD_DIR)/$(PKG_NAME).pkg
	@/bin/rm $(BUILD_DIR)/$(PKG_NAME).component.pkg $(BUILD_DIR)/distribution.xml
else
	@if [ -z "$(PKG_SIGN_ID)" ]; then \
		echo "ERROR: Set PKG_SIGN_ID or DEV_PKG_SIGN_ID (Developer ID Installer) for signed packages."; \
		echo "For an unsigned .pkg, run: make pkg"; \
		exit 1; \
	fi
	@if [ -d "$(SCRIPT_DIR)/scripts" ]; then \
		/usr/bin/pkgbuild --root $(SCRIPT_DIR)/payload \
			--identifier $(PKG_ID) --version $(VERSION) --install-location / \
			--scripts $(SCRIPT_DIR)/scripts --ownership recommended \
			$(BUILD_DIR)/$(PKG_NAME).unsigned.pkg; \
	else \
		/usr/bin/pkgbuild --root $(SCRIPT_DIR)/payload \
			--identifier $(PKG_ID) --version $(VERSION) --install-location / \
			--ownership recommended $(BUILD_DIR)/$(PKG_NAME).unsigned.pkg; \
	fi
	@/usr/bin/productsign --sign "$(PKG_SIGN_ID)" \
		$(BUILD_DIR)/$(PKG_NAME).unsigned.pkg $(BUILD_DIR)/$(PKG_NAME).pkg
	@/bin/rm $(BUILD_DIR)/$(PKG_NAME).unsigned.pkg
endif
	@echo "Package: $(BUILD_DIR)/$(PKG_NAME).pkg"

clean:
	/bin/rm -rf $(BUILD_DIR)
	@echo "Cleaned build directory"

install-local: build
	@echo "Installing unsigned postflight to /usr/local/munki (requires sudo)"
	sudo /bin/cp $(BUILD_DIR)/postflight /usr/local/munki/postflight
	sudo /bin/chmod +x /usr/local/munki/postflight

clean-all: clean
	/bin/rm -rf $(SCRIPT_DIR)/payload
	@echo "Removed payload/"
