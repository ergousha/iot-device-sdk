# NVS fixtures

Made by Espressif's own encoder, `nvs_partition_gen.py` (the
`esp-idf-nvs-partition-gen` package, 0.1.9, as shipped with ESP-IDF v5.5.3),
so the parser is checked against the format real tooling writes. Every PEM in
them is fake (`FAKE` lines); `the_fixtures_hold_no_real_key_material` checks
that. Never put a real key, certificate or password here, and never commit a
real device dump (`*.nvs.bin` and `dumps/` are git-ignored).

| File | From | Contents |
|---|---|---|
| `vaktus.bin` | `vaktus.csv` | secure-element layout: `cloud` (`thing`, `cert`, `pubkey`), `ota_job/pending` (blob, `ota_pending.json`), `wifi/ssid`, `fixture/large_blob` (9000 B, `large.bin`, split over 3 pages) |
| `gateway.bin` | `gateway.csv` | soft-key layout: `device_id` (`cert`, `key`, `thing`), `platform` (`boot_cnt` u32, `boot_fw`) |
| `types_v2.bin` | `types.csv` | every integer type, a string and a blob, format version 2 |
| `types_v1.bin` | `types.csv` | the same, format version 1 (single-page blob, type `0x41`) |

`large.bin` is `bytes(i % 251 for i in range(9000))`.

## Regenerating

From this directory (the CSVs name `ota_pending.json` and `large.bin`
relative to it), with the Python environment ESP-IDF installs (it has the
generator and `cryptography`, which the generator imports even when not
encrypting):

```sh
# esp-idf-sys builds keep it in the product repo; a classic install in ~/.espressif
PY=<product-repo>/.embuild/espressif/python_env/idf5.5_py3.14_env/bin/python
$PY -m esp_idf_nvs_partition_gen generate vaktus.csv vaktus.bin 0x6000
$PY -m esp_idf_nvs_partition_gen generate gateway.csv gateway.bin 0x3000
$PY -m esp_idf_nvs_partition_gen generate types.csv types_v2.bin 0x3000
$PY -m esp_idf_nvs_partition_gen generate --version 1 types.csv types_v1.bin 0x3000
```

Without ESP-IDF: `python3 -m venv /tmp/nvsgen && /tmp/nvsgen/bin/pip install
esp-idf-nvs-partition-gen==0.1.9` and use `PY=/tmp/nvsgen/bin/python`.
`$IDF_PATH/components/nvs_flash/nvs_partition_generator/nvs_partition_gen.py
generate ...` is the same tool (a wrapper that runs the module).

The output is deterministic: regenerating with the same version gives
byte-identical files.
