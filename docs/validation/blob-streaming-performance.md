## Selected-contact measurement fields

Semantic-v9/profile-5 contacts emit bounded measurements in their `CONTACT`
receipt. `blob_stream_sent_bytes` and `blob_stream_received_bytes` are the
canonical pack bytes carried in the current attempt; `blob_stream_resumed_bytes`
is the durable prefix skipped across local send and receive directions.
`blob_stream_checkpoints` and `blob_stream_partitions` count checkpoint
settlement and receiver pipeline completion. `blob_stream_resumed_bytes` is
cumulative across the contact's Profile-5 exchanges: an exact already-present
retry may add the complete wire length while adding zero sent/received bytes.

`blob_stream_pipeline` is a semicolon-delimited value. Its capacity prefix is
`workers`, `peak_items`, `peak_bytes`, and `peak_reorder`. Each subsequent stage
has the form `name:items:bytes:queue_wait_ns:service_ns:output_blocked_ns` for
`admission`, `map`, `reorder`, and `sink`. These cumulative, bounded counters
make a CM4 run attributable without retaining per-partition histories or Blob
identifiers. A sender-only direction has no receiver pipeline samples.
