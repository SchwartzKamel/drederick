# drederick — contributor Makefile
#
# Quick start for a fresh contributor:
#   make quickstart      # detect+install deps, build, publish, install binary globally
#   drederick --help     # verify it's on your PATH
#
# For the full target list:
#   make help

# ---------- Configuration (override via `make VAR=value`) ----------

PROJECT        := src/Drederick/Drederick.csproj
SOLUTION       := Drederick.slnx
BIN_NAME       := drederick
CONFIGURATION  := Release
TFM            := net10.0

# Install location. Default is userspace (no sudo). Override with PREFIX=/usr/local/bin for system-wide.
PREFIX         ?= $(HOME)/.local/bin
ARTIFACTS_DIR  := artifacts

# Runtime identifier — auto-detected, override with RID=linux-arm64 etc.
UNAME_S        := $(shell uname -s 2>/dev/null || echo Unknown)
UNAME_M        := $(shell uname -m 2>/dev/null || echo Unknown)
ifeq ($(UNAME_S),Linux)
  ifeq ($(UNAME_M),x86_64)
    RID ?= linux-x64
  else ifeq ($(UNAME_M),aarch64)
    RID ?= linux-arm64
  else
    RID ?= linux-x64
  endif
else ifeq ($(UNAME_S),Darwin)
  ifeq ($(UNAME_M),arm64)
    RID ?= osx-arm64
  else
    RID ?= osx-x64
  endif
else
  RID ?= linux-x64
endif

PUBLISH_DIR    := $(ARTIFACTS_DIR)/$(RID)
PUBLISHED_BIN  := $(PUBLISH_DIR)/$(BIN_NAME)
INSTALLED_BIN  := $(PREFIX)/$(BIN_NAME)

# ANSI colors (disabled if NO_COLOR is set or not a TTY)
ifdef NO_COLOR
  C_BOLD :=
  C_CYAN :=
  C_YELL :=
  C_GREEN :=
  C_RESET :=
else
  C_BOLD  := \033[1m
  C_CYAN  := \033[36m
  C_YELL  := \033[33m
  C_GREEN := \033[32m
  C_RESET := \033[0m
endif

.DEFAULT_GOAL := help

# ---------- Dynamic help ----------
# Targets tagged with `## Description` show up in `make help`.
# Group headers use `##@ Group Name`.

.PHONY: help
help: ## Show this help message
	@printf "$(C_BOLD)drederick$(C_RESET) — recon harness for authorized engagements\n\n"
	@printf "$(C_BOLD)Usage:$(C_RESET) make $(C_CYAN)<target>$(C_RESET) [VAR=value ...]\n\n"
	@awk 'BEGIN {FS = ":.*?## "} \
	     /^##@ / { printf "\n$(C_BOLD)%s$(C_RESET)\n", substr($$0, 5); next } \
	     /^[a-zA-Z_-]+:.*?## / { printf "  $(C_CYAN)%-18s$(C_RESET) %s\n", $$1, $$2 }' \
	     $(MAKEFILE_LIST)
	@printf "\n$(C_BOLD)Key variables$(C_RESET) (override with VAR=value):\n"
	@printf "  $(C_YELL)PREFIX$(C_RESET)        install dir   (current: $(PREFIX))\n"
	@printf "  $(C_YELL)RID$(C_RESET)           runtime id    (current: $(RID))\n"
	@printf "  $(C_YELL)CONFIGURATION$(C_RESET) dotnet config (current: $(CONFIGURATION))\n\n"
	@printf "$(C_BOLD)First-time contributor path:$(C_RESET)\n"
	@printf "  1. make quickstart    # deps + build + publish + install\n"
	@printf "  2. drederick doctor   # verify your pentest toolchain\n"
	@printf "  3. drederick --help   # explore\n\n"

##@ Setup

.PHONY: check-dotnet
check-dotnet: ## Verify .NET 10 SDK is present
	@command -v dotnet >/dev/null 2>&1 || { \
	    printf "$(C_YELL)error:$(C_RESET) dotnet SDK not found.\n"; \
	    printf "Install from https://dotnet.microsoft.com/download or run: make bootstrap\n"; \
	    exit 1; }
	@ver=$$(dotnet --list-sdks | awk '{print $$1}' | grep -E '^10\.' | head -1); \
	 if [ -z "$$ver" ]; then \
	    printf "$(C_YELL)error:$(C_RESET) .NET 10 SDK not found. Installed SDKs:\n"; \
	    dotnet --list-sdks | sed 's/^/    /'; \
	    exit 1; \
	 fi; \
	 printf "$(C_GREEN)ok$(C_RESET) .NET 10 SDK: $$ver\n"

.PHONY: bootstrap
bootstrap: ## Install system prerequisites (Debian/Kali: runs scripts/bootstrap.sh)
	@if [ ! -x scripts/bootstrap.sh ]; then \
	    printf "$(C_YELL)error:$(C_RESET) scripts/bootstrap.sh not found or not executable\n"; exit 1; \
	 fi
	@printf "Running bootstrap script (may prompt for sudo)...\n"
	@./scripts/bootstrap.sh

.PHONY: restore
restore: check-dotnet ## Restore NuGet dependencies
	@dotnet restore $(SOLUTION)

.PHONY: doctor
doctor: build ## Run drederick doctor (detect-only, no install)
	@dotnet run --project $(PROJECT) -c $(CONFIGURATION) --no-build -- doctor

.PHONY: doctor-install
doctor-install: build ## Run drederick doctor --install (install missing tools on consent)
	@dotnet run --project $(PROJECT) -c $(CONFIGURATION) --no-build -- doctor --install

##@ Development

.PHONY: build
build: check-dotnet ## Build the solution (Release)
	@dotnet build $(SOLUTION) -c $(CONFIGURATION) --nologo

.PHONY: build-debug
build-debug: check-dotnet ## Build the solution (Debug)
	@dotnet build $(SOLUTION) -c Debug --nologo

.PHONY: test
test: check-dotnet ## Run the test suite
	@dotnet test $(SOLUTION) -c $(CONFIGURATION) --nologo

.PHONY: test-live
test-live: check-dotnet ## Run the full suite including DREDERICK_INTEGRATION=1 live smoke
	@DREDERICK_INTEGRATION=1 dotnet test $(SOLUTION) -c $(CONFIGURATION) --nologo

.PHONY: format
format: check-dotnet ## Apply dotnet format to the solution
	@dotnet format $(SOLUTION)

.PHONY: format-check
format-check: check-dotnet ## Verify formatting without changes (CI gate)
	@dotnet format $(SOLUTION) --verify-no-changes

.PHONY: watch
watch: check-dotnet ## Run dotnet watch test for TDD
	@dotnet watch --project tests/Drederick.Tests test

##@ Release

.PHONY: publish
publish: check-dotnet ## Publish a self-contained single-file binary to artifacts/$RID
	@mkdir -p $(PUBLISH_DIR)
	@dotnet publish $(PROJECT) \
	    -c $(CONFIGURATION) \
	    -r $(RID) \
	    --self-contained true \
	    -p:PublishSingleFile=true \
	    -p:IncludeNativeLibrariesForSelfExtract=true \
	    -o $(PUBLISH_DIR) \
	    --nologo
	@printf "$(C_GREEN)published$(C_RESET) → $(PUBLISHED_BIN)\n"

.PHONY: install
install: publish ## Install the binary to $(PREFIX) (default: ~/.local/bin)
	@if [ ! -f "$(PUBLISHED_BIN)" ]; then \
	    printf "$(C_YELL)error:$(C_RESET) no published binary at $(PUBLISHED_BIN)\n"; exit 1; \
	 fi
	@mkdir -p $(PREFIX) || { printf "$(C_YELL)error:$(C_RESET) cannot create $(PREFIX). Try: sudo make install PREFIX=/usr/local/bin\n"; exit 1; }
	@if ! touch $(PREFIX)/.drederick.write-test 2>/dev/null; then \
	    printf "$(C_YELL)error:$(C_RESET) $(PREFIX) is not writable. Try one of:\n"; \
	    printf "    make install                          # defaults to ~/.local/bin (userspace)\n"; \
	    printf "    sudo make install PREFIX=/usr/local/bin  # system-wide\n"; \
	    exit 1; \
	 fi
	@rm -f $(PREFIX)/.drederick.write-test
	@install -m 755 $(PUBLISHED_BIN) $(INSTALLED_BIN)
	@printf "$(C_GREEN)installed$(C_RESET) → $(INSTALLED_BIN)\n"
	@case ":$$PATH:" in \
	    *":$(PREFIX):"*) printf "$(C_GREEN)ok$(C_RESET) $(PREFIX) is on your PATH\n" ;; \
	    *) printf "$(C_YELL)warn$(C_RESET) $(PREFIX) is NOT on your PATH. Add to your shell rc:\n"; \
	       printf "    export PATH=\"$(PREFIX):\$$PATH\"\n" ;; \
	 esac
	@printf "verify: $(C_CYAN)$(BIN_NAME) --help$(C_RESET)\n"

.PHONY: install-symlink
install-symlink: publish ## Symlink the published binary into $(PREFIX) (for active development)
	@mkdir -p $(PREFIX)
	@ln -sf "$$(pwd)/$(PUBLISHED_BIN)" $(INSTALLED_BIN)
	@printf "$(C_GREEN)symlinked$(C_RESET) $(INSTALLED_BIN) → $$(pwd)/$(PUBLISHED_BIN)\n"

.PHONY: install-from-release
install-from-release: ## Download + install the latest signed release binary (no build)
	@if [ ! -x scripts/install.sh ]; then \
	    printf "$(C_YELL)error:$(C_RESET) scripts/install.sh not found or not executable\n"; exit 1; \
	 fi
	@PREFIX=$(PREFIX) ./scripts/install.sh

.PHONY: uninstall
uninstall: ## Remove the installed binary from $(PREFIX)
	@if [ -e $(INSTALLED_BIN) ] || [ -L $(INSTALLED_BIN) ]; then \
	    rm -f $(INSTALLED_BIN); \
	    printf "$(C_GREEN)removed$(C_RESET) $(INSTALLED_BIN)\n"; \
	 else \
	    printf "nothing to remove at $(INSTALLED_BIN)\n"; \
	 fi

.PHONY: quickstart
quickstart: bootstrap-optional doctor-install publish install ## One-shot: deps + build + publish + install globally
	@printf "\n$(C_GREEN)done$(C_RESET) — try: $(C_CYAN)$(BIN_NAME) --help$(C_RESET) and $(C_CYAN)$(BIN_NAME) doctor$(C_RESET)\n"

# Opportunistic bootstrap: skip silently if not on a supported distro / script missing.
.PHONY: bootstrap-optional
bootstrap-optional:
	@if [ -x scripts/bootstrap.sh ] && command -v apt-get >/dev/null 2>&1; then \
	    ./scripts/bootstrap.sh; \
	 else \
	    printf "$(C_YELL)skip$(C_RESET) bootstrap (not on apt-based distro or script missing — drederick doctor will handle deps)\n"; \
	 fi

##@ Run

.PHONY: run
run: build ## Run drederick in-place (pass args via ARGS="--scope ...")
	@dotnet run --project $(PROJECT) -c $(CONFIGURATION) --no-build -- $(ARGS)

.PHONY: serve
serve: build ## Launch the Datasette web UI (auto-bootstraps datasette if missing)
	@dotnet run --project $(PROJECT) -c $(CONFIGURATION) --no-build -- serve

##@ Housekeeping

.PHONY: clean
clean: ## Remove build artifacts and published binaries
	@dotnet clean $(SOLUTION) --nologo >/dev/null 2>&1 || true
	@find . -type d \( -name bin -o -name obj \) -not -path './.git/*' -exec rm -rf {} + 2>/dev/null || true
	@rm -rf $(ARTIFACTS_DIR)
	@printf "$(C_GREEN)clean$(C_RESET) bin/ obj/ $(ARTIFACTS_DIR)/ removed\n"

.PHONY: clean-output
clean-output: ## Remove scan output (out/) and cross-run memory (memory/, ~/.drederick/)
	@rm -rf out memory
	@printf "$(C_YELL)note$(C_RESET) keeping ~/.drederick/ (run 'rm -rf ~/.drederick' manually if you want a true clean slate)\n"
	@printf "$(C_GREEN)clean$(C_RESET) out/ and memory/ removed\n"

.PHONY: version
version: ## Print version info for the local workspace
	@printf "$(C_BOLD)drederick$(C_RESET)\n"
	@printf "  commit:      %s\n" "$$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
	@printf "  branch:      %s\n" "$$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
	@printf "  dotnet SDK:  %s\n" "$$(dotnet --version 2>/dev/null || echo missing)"
	@printf "  target:      $(TFM) / $(RID)\n"
	@printf "  install:     $(INSTALLED_BIN)\n"
	@if [ -x "$(INSTALLED_BIN)" ]; then \
	    printf "  installed:   $(C_GREEN)yes$(C_RESET)\n"; \
	 else \
	    printf "  installed:   $(C_YELL)no$(C_RESET) (run 'make install')\n"; \
	 fi

# --- web targets ---
.PHONY: web-install web-dev web-build
web-install: ## Install SPA dependencies (pnpm)
	@cd web && pnpm install

web-dev: ## Run the SPA dev server (http://localhost:5173)
	@cd web && pnpm dev

web-build: ## Build the SPA into src/Drederick.Web/wwwroot
	@cd web && pnpm build
