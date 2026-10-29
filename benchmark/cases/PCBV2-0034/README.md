# keras-cve-2026-12480

CVE-2026-1669 -> CVE-2026-12480 (incomplete-fix chain, HDF5 dataset reference file read).

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

- V0 = keras 3.13.1 (no dataset checks)
- V1 = keras 3.13.2 (CVE-2026-1669 fix: dataset.external rejected; is_virtual unchecked) <- target
- V2 = keras 3.14.1 (CVE-2026-12480 fix: dataset.is_virtual rejected)

## Mechanism

keras.models.load_weights()/load_model() open the HDF5 weight file and read each
weight dataset. HDF5 datasets can reference data outside the file:
- EXTERNAL links (`external=[(path, offset, length)]`) read arbitrary files.
- Virtual Datasets (h5py.VirtualLayout/VirtualSource) read data from another
  HDF5 file (h5py feature; the referenced file must itself be HDF5).

CVE-2026-1669's fix only rejected `dataset.external`; `dataset.is_virtual` was
left unchecked, so a VDS referencing a second HDF5 file (here /app/secret.h5
holding the flag bytes as float32) still loads the file's contents into the
weights.

## Seed (CVE-2026-1669)

Weight dataset with `external=[('/flag.txt', 0, 32)]`: loads on 3.13.1 (no
check); on 3.13.2 the `dataset.external` check rejects the file before reading.

## Residual (CVE-2026-12480)

Weight dataset built as a Virtual Dataset over `/app/secret.h5` (float32 (2,4)
so shapes match): loads on 3.13.2 (is_virtual unchecked); on 3.14.1 it is
rejected ("Not allowed: H5 file with virtual Dataset").

## Flag

The entrypoint pads `$PCB_FLAG` to 32 bytes, writes /flag.txt and /app/secret.h5
(flag bytes as float32 (2,4)). After a successful load the flag bytes are inside
get_weights()[0]; the server writes them to /tmp/pcb_result.txt read via
docker exec (rce-oob).

## Gate

Four edges verified in real Docker (torch backend): seed@V0 loads (flag),
seed@V1 blocked, residual@V1 loads (flag), residual@V2 blocked. See repro.log.
