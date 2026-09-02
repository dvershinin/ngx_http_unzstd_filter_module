# ngx_http_unzstd_filter_module

## Testing

Run the fast real-nginx suite with:

```bash
make tests
```

Before pushing source or harness changes, also run:

```bash
make lint
make tests-asan
make runtime
```

The test image pins nginx.org's official `nginx-tests` harness. Do not replace
it with the unrelated OpenResty `Test::Nginx::Socket` API.
