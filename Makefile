SHELL=/usr/bin/bash

MKDOCS_IMAGE := aquasec/mkdocs-material:tracee
MKDOCS_PORT := 8000

.PHONY: test
test:
	which gotestsum || (pushd /tmp && go install gotest.tools/gotestsum@latest && popd)
	gotestsum -- --mod=vendor -bench=^$$ -race ./...

.PHONY: fmt
fmt:
	go fmt ./...

.PHONY: sanity
sanity: test
	go run ./cmd/cfsec  ./example > /dev/null

.PHONY: pr-ready
pr-ready: quality sanity lint-pr-checks typos

.PHONY: lint-pr-checks
lint-pr-checks:
	@go run ./cmd/cfsec-pr-lint

.PHONY: cyclo
cyclo:
	which gocyclo || go install github.com/fzipp/gocyclo/cmd/gocyclo@latest
	gocyclo -over 15 -ignore 'vendor/' .

.PHONY: vet
vet:
	go vet ./...

.PHONY: typos
typos:
	which codespell || pip install codespell
	codespell -S vendor,funcs,.terraform,.git --ignore-words .codespellignore -f

.PHONY: quality
quality: cyclo vet

.PHONY: fix-typos
fix-typos:
	which codespell || pip install codespell
	codespell -S vendor --ignore-words .codespellignore -f -w -i1

.PHONY: tagger
tagger:
	@git checkout master
	@git fetch --tags
	@echo "the most recent tag was `git describe --tags --abbrev=0`"
	@echo ""
	read -p "Tag number: " TAG; \
	 git tag -a "$${TAG}" -m "$${TAG}"; \
	 git push origin "$${TAG}"

.PHONY: publish-docs
publish-docs: generate-docs
	@python3 ./scripts/build_checks_nav.py

# Runs MkDocs dev server to preview the docs page before it is published.
.PHONY: mkdocs-serve
mkdocs-serve:
	docker build -t $(MKDOCS_IMAGE) -f docs/Dockerfile docs
	docker  run --name mkdocs-serve --rm -v $(PWD):/docs -p $(MKDOCS_PORT):8000 $(MKDOCS_IMAGE)