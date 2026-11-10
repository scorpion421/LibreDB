# LibreDB POSIX / Linux / macOS source build and Antigravity plugin installer
# Zero external library dependencies (SQLite is bundled in source via rusqlite; LZ4 is pure Rust).
# Prerequisites: Rust toolchain (cargo + rustc) and a standard C compiler (cc / gcc / clang).

CARGO ?= cargo
SH ?= sh
BINARY := target/release/libredb

.PHONY: all build build-native test python install install-personal install-mcp-only install-migrate-legacy bench uninstall guardrail clean check-deps help

all: build

## Verify that cargo and a C compiler (required only for bundled sqlite3.c) are present
check-deps:
	@command -v $(CARGO) >/dev/null 2>&1 || { \
		echo "Error: 'cargo' not found in PATH. Install Rust via: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"; \
		exit 1; \
	}
	@command -v cc >/dev/null 2>&1 || command -v gcc >/dev/null 2>&1 || command -v clang >/dev/null 2>&1 || { \
		echo "Error: C compiler ('cc', 'gcc', or 'clang') not found. Install build-essential (Debian/Ubuntu), gcc (Fedora/RHEL), or base-devel (Arch)."; \
		exit 1; \
	}

## Build optimized release CLI & MCP server binary (target/release/libredb)
build: check-deps
	$(CARGO) build --release

## Build with host CPU instruction tuning (-C target-cpu=native)
build-native: check-deps
	RUSTFLAGS="-C target-cpu=native" $(CARGO) build --release

## Run all core, cognitive, bridge, CLI, and 10,000 power-loss crash simulation tests
test: check-deps
	$(CARGO) test --release

## Build optional PyO3 abi3 shared library (crates/libredb-py -> liblibredb_py.so / .dylib)
python: check-deps
	PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1 $(CARGO) build --release -p libredb-py

## Build and install enterprise-neutral LibreDB CLI + Antigravity plugin into ~/.gemini and ~/.local/bin
install: build
	$(SH) ./scripts/deploy_plugin.sh

## Build and install LibreDB with the author's personal rules profile (--personal-rules)
install-personal: build
	$(SH) ./scripts/deploy_plugin.sh --personal-rules

## Build and install LibreDB MCP server + CLI with lifecycle hooks disabled (--no-hooks)
install-mcp-only: build
	$(SH) ./scripts/deploy_plugin.sh --no-hooks

## Build and install enterprise-neutral LibreDB while migrating an existing ~/.gemini/database/customizations.db
install-migrate-legacy: build
	$(SH) ./scripts/deploy_plugin.sh --migrate-legacy

## Run reproducible storage, graph, and recall throughput benchmark
bench: build
	./$(BINARY) bench --nodes 2000 --threads 8

## Run strict workspace guardrail audit using the compiled release binary
guardrail: build
	./$(BINARY) guardrail check --path . --strict

## Remove installed Antigravity plugin and PATH binary while preserving ~/.gemini/libredb/*.ldb data
uninstall:
	rm -rf "$$HOME/.gemini/config/plugins/libredb"
	rm -f "$$HOME/.gemini/antigravity/bin/libredb" "$$HOME/.local/bin/libredb"
	@echo "[OK] Removed LibreDB plugin and PATH shims (preserved user databases in $$HOME/.gemini/libredb)."

## Clean Cargo build artifacts
clean:
	$(CARGO) clean

## Show available Makefile targets
help:
	@echo "LibreDB source build targets:"
	@echo "  make              Compile optimized release binary (target/release/libredb)"
	@echo "  make build-native Compile with -C target-cpu=native for maximum local performance"
	@echo "  make test         Run full release test suite + 10,000 crash simulations"
	@echo "  make install                Build and deploy enterprise-neutral LibreDB CLI + MCP plugin"
	@echo "  make install-mcp-only       Deploy MCP server + CLI with hooks disabled (--no-hooks)"
	@echo "  make install-migrate-legacy Deploy neutral plugin and migrate legacy customizations.db"
	@echo "  make install-personal       Deploy with personal workflow rules (--personal-rules)"
	@echo "  make bench                  Run storage, recall, and concurrency throughput benchmark"
	@echo "  make python       Build optional PyO3 Python extension (libredb-py)"
	@echo "  make guardrail    Run strict LibreDB guardrail check on workspace"
	@echo "  make uninstall    Remove plugin files while keeping ~/.gemini/libredb databases"
	@echo "  make clean        Remove target/ build artifacts"
