.PHONY: test
test:
	which gotestsum || (pushd /tmp && go install gotest.tools/gotestsum@latest && popd)
	gotestsum -- --mod=vendor -bench=^$$ -race ./...

.PHONY: fmt
fmt:
	go fmt ./...