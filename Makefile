.PHONY: test tests base-image lint tests-asan runtime torture-unit clean

DOCKER ?= docker
BASE_IMAGE ?= ngx-unzstd-tests-base
NGINX_VERSION ?= 1.30.4
NGINX_TESTS_REF ?= 5432676478e4422db94c4249fd117cb87d89b33b

base-image:
	$(DOCKER) build \
		--build-arg NGINX_TESTS_REF=$(NGINX_TESTS_REF) \
		-f Dockerfile.tests-base \
		-t $(BASE_IMAGE):$(NGINX_VERSION) .

tests: base-image
	$(DOCKER) run --rm \
		--user $$(id -u):$$(id -g) \
		-e NGINX_VERSION=$(NGINX_VERSION) \
		-v $(PWD):/work -w /work \
		$(BASE_IMAGE):$(NGINX_VERSION) \
		/work/docker-run-tests.sh $(T)

test: tests

lint: base-image
	$(DOCKER) run --rm \
		--user $$(id -u):$$(id -g) \
		-v $(PWD):/work -w /work \
		$(BASE_IMAGE):$(NGINX_VERSION) \
		cppcheck --enable=warning,portability,performance \
		  --check-level=exhaustive --error-exitcode=1 \
		  --suppressions-list=.cppcheck-suppressions \
		  --suppress=missingIncludeSystem --std=c11 \
		  -DZSTD_STATIC_LINKING_ONLY \
		  ngx_http_unzstd_filter_module.c

tests-asan: base-image
	$(DOCKER) run --rm \
		--user $$(id -u):$$(id -g) \
		-e ASAN=1 -e NGINX_VERSION=$(NGINX_VERSION) \
		-v $(PWD):/work -w /work \
		$(BASE_IMAGE):$(NGINX_VERSION) \
		/work/docker-run-tests.sh $(T)

torture-unit:
	python3 tools/test_torture_lab.py

runtime: base-image torture-unit
	$(DOCKER) run --rm \
		--user $$(id -u):$$(id -g) \
		-e NGINX_VERSION=$(NGINX_VERSION) \
		-v $(PWD):/work -w /work \
		$(BASE_IMAGE):$(NGINX_VERSION) \
		bash -lc 'bash tools/ci-build.sh nginx "$$NGINX_VERSION" dynamic && \
		  python3 tools/test_runtime.py \
		    --nginx-binary "/work/.build/nginx-$$NGINX_VERSION/objs/nginx" \
		    --module "/work/.build/nginx-$$NGINX_VERSION/objs/ngx_http_unzstd_filter_module.so" \
		    --directives-json /work/tools/verified-directives.json \
		    --evidence-path /work/torture-lab-evidence.json'

clean:
	$(DOCKER) image rm $(BASE_IMAGE):$(NGINX_VERSION) 2>/dev/null || true
