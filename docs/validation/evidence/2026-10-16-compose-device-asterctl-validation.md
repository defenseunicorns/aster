# Compose and device `asterctl` validation — 2026-10-16

## Claim

This is a bounded operator-workflow observation for PR #95. One amd64 Docker
Compose node and one arm64 Debian-package node exchanged authenticated Event
and Blob data over a private overlay path. The observation covers artifact-only
Compose setup, packaged `asterctl`, durable and finite Blob behavior, restart
access, expected failures, and one small transfer measurement. It is not a
production authorization, a performance threshold, or a large-file
qualification.

No credential, mission identifier, peer identifier, token, private endpoint,
or generated bundle is retained here.

## Artifacts

- PR head: `e75923ead4879b036dc4cb20aeb03dd5d3b9bcb0`, signed commit.
- Compose workflow: run `38921113951`, successful for amd64 and arm64.
- Workflow source revision: synthetic merge
  `c05ebd97b4c307b8b3b9f6d10f178fcf5b890dc9`; its second parent is the PR
  head above.
- The downloaded amd64 artifact passed every entry in its `SHA256SUMS` file.
- Agent image manifest digest:
  `sha256:cb3d76a245bfe50fd5daf2387705d3f99a7b0174d0c40aeb7b13999aaaf49848`.
- Admin image manifest digest:
  `sha256:1e1979f888c2afa382f48bb2d0a4240778881289269699aeef840ffbb223f245`.
- Device package workflow: run `38897169705`, branch head
  `d2454f458646fdbf36e23c883f79437798a554df`; package SHA-256
  `db8e4d9129ab232e711bf0f671742b85fc4b604f9804bc575db299ba3ac33dcb`.
  That earlier packaged CLI already contains the Blob API used on the device;
  the later Compose-only output-finalization correction is exercised by the
  exact amd64 admin image.

The artifact-supplied validator, Compose preflight, packaged verifier, health
check, architecture check, and exact image-ID binding passed before data
operations. The Docker UDP port was bound only to the selected private-overlay
address. The disposable mission came from the documented evaluation-only
`playground-init` flow and authorized only its generated selector.

## Results

| Check | Observation |
| --- | --- |
| Authenticated contact | Both nodes reported active authorization and completed authenticated contacts. |
| Event transfer | Fresh publications transferred in both directions after the matching durable receiver subscriptions were created. An Event published before the receiver subscription did not transfer. |
| Durable Blob, Docker to device | 98,304 bytes read on the device; source and destination SHA-256 matched. |
| Durable Blob, device to Docker | 98,304 bytes read through the exact CI admin image into the Docker Desktop bind mount; SHA-256 matched and the output mode was `0600`. This is the case that rejected `O_TMPFILE` before the named-sibling correction. |
| Docker replacement | The agent container was replaced with the exact CI image while retaining its state directory. A pre-replacement durable Blob remained readable and byte-identical. |
| Finite TTL | A 32,768-byte Blob with a 20,000 ms TTL was readable and byte-identical before expiry. After expiry, read returned the typed `expired or retired` result and created no output path. |
| Missing source | Publish failed locally with `cannot open source file`, produced no receipt, and did not contact the mutation path. |
| Unauthorized selector | Publish returned `permission_denied` and produced no receipt. |
| Output safety | The requested destination stayed absent on failure. Successful bind-mounted output used mode `0600`; an existing destination was not part of the write path. |

## Bounded performance observation

A fresh 1 MiB durable Blob was published on Docker and read on the device:

- size: 1,048,576 bytes;
- publication-to-verified-read elapsed time: 36,382 ms;
- effective throughput: 0.03 MiB/s;
- unavailable read retries before promotion: 8;
- sampled Docker-agent peak RSS during the interval: 37,932 KiB;
- device-agent process high-water RSS after the interval: 25,600 KiB;
- output SHA-256: exact match.

This one overlay-path observation includes CLI/container and retry overhead and
does not establish a supported rate, latency, or memory ceiling.

## Qualification gap observed

A separate 16 MiB durable device-to-Docker attempt did not complete. During
the bounded observation, the Docker agent emitted one runtime fatal transition
and restarted once; Docker reported no OOM kill. After restart the node was
healthy, retained active peer authorization, and reported 21 authenticated
contacts. `ReadBlob` returned the typed `missing Blob` result, no partial
destination was left, and the observed receiver state accounted for only about
7 MiB of staged data; this run did not establish complete chunk arrival. The
configured payload and depot limits were each 64 MiB or greater.

This evidence therefore makes no large-file interoperability or performance
claim. The 16 MiB runtime transition requires separate diagnosis; the passing
1 MiB result must not be used to dismiss it.

## Operator corrections derived from execution

- Create the durable Event subscription on the receiver before publishing a
  cross-node Event, then allow an authenticated contact to refresh routing.
- Blob output uses an owner-controlled destination directory, a mode-`0600`
  named sibling, file synchronization, atomic no-replace rename, and directory
  synchronization. Cleanup is best-effort, and a post-publication directory
  synchronization error requires verifying the destination before retrying.

## Restoration

The evaluation used disposable mission material and isolated state. After the
run, the device's original configuration, credential directories, state,
package files, and inactive/disabled service baseline were restored. The first
renamed-state restore exposed a `mesh.redb` mismatch, so the state directory was
replaced from the immutable pre-test archive while the service remained
stopped. The final metadata-and-SHA-256 manifest matched the pre-test manifest
exactly. Four man pages present only in the newer test package and all explicitly
named disposable lab/rollback paths were removed. The local pre-test archives
remain available for recovery.
