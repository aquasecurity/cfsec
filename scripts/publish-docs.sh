#!/bin/bash

set -ex

DEPLOY_REPO="https://${DOCS_GITHUB_TOKEN}@github.com/cfsec/cfsec.github.io.git"
MESSAGE=$(git log -1 HEAD --pretty=format:%s)

function clone_site {
	echo "getting latest site"
	git clone --depth 1 "${DEPLOY_REPO}" _site
}

function deploy {
	echo "deploying changes"
	pushd _site
	git config --global user.name "GitHub Actions Build"
	git config --global user.email github-actions@cfsec.dev
	git add -A
	git remote set-url origin "${DEPLOY_REPO}"
	git commit -m "GitHub Actions Build: ${GITHUB_RUN_ID}. ${MESSAGE}" || true
	git push --set-upstream origin master || true
	popd
}

clone_site
go run ./cmd/cfsec-docs
cp -r checkdocs/docs/* ./_site/_docs/
cp -r checkdocs/data/* ./_site/_data/
deploy

rm -rf checkdocs
