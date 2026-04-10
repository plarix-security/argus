.PHONY: build test lint check install clean benchmark help

# Default target
all: build

## Build the project
build:
	npm run build

## Run tests
test:
	npm test

## Run linter
lint:
	npm run lint

## Run wyscan on itself (self-check)
check:
	node dist/cli/index.js check

## Install globally (requires npm link permissions)
install: build
	npm link

## Clean build artifacts
clean:
	rm -rf dist
	rm -rf node_modules/.cache

## Deep clean (includes node_modules)
clean-all: clean
	rm -rf node_modules

## Run benchmark evaluation
benchmark:
	python3 benchmark/scripts/evaluate.py

## Run a specific benchmark by number
benchmark-%:
	node dist/cli/index.js scan benchmark/$*-*/

## Type check without emitting
typecheck:
	npx tsc --noEmit

## Watch mode for development
watch:
	npx tsc --watch

## Show help
help:
	@echo "Available targets:"
	@echo "  build       - Build the TypeScript project"
	@echo "  test        - Run tests"
	@echo "  lint        - Run linter"
	@echo "  check       - Run wyscan on itself"
	@echo "  install     - Install globally via npm link"
	@echo "  clean       - Remove build artifacts"
	@echo "  clean-all   - Remove build artifacts and node_modules"
	@echo "  benchmark   - Run all benchmark evaluations"
	@echo "  benchmark-N - Run specific benchmark (e.g., make benchmark-15)"
	@echo "  typecheck   - Type check without emitting"
	@echo "  watch       - Watch mode for development"
	@echo "  help        - Show this help message"
