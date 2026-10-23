//! Device benchmark for the production Profile-5 completed-pack data path.
//!
//! Publication builds the same independently authenticated one-MiB records as
//! the selected Blob API. Timed transfer reads that completed pack directly;
//! receive uses the shared bounded map/reorder/durable-pack pipeline. Synthetic
//! serial DATA modes are deliberately absent so their CPU cost cannot be
//! mistaken for selected-runtime throughput.

use aster_iroh::{CarrierSecurityProfile, Endpoint, EndpointConfig, ExpectedPeer, SecretKey};
use aster_mesh::{
    BlobMetadata, BlobPublicationStreamId, BlobStreamOpen, BlobStreamSegmentOpener,
    BlobStreamSegmentSealer, Priority, Scope, Topic, VersionVector,
};
use aster_node::{
    application::blob_stream::publish_blob_stream,
    stream_pipeline::PipelineLimits,
    stream_validation::{self, BlobNetworkReport},
};
use std::{
    collections::BTreeSet,
    error::Error,
    io::{Read, Write as _},
    net::SocketAddr,
    path::PathBuf,
    time::{Duration, Instant},
};

type AnyError = Box<dyn Error + Send + Sync>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    PackReceive {
        bind: SocketAddr,
        bytes: u64,
    },
    PackSend {
        bind: SocketAddr,
        peer: SocketAddr,
        bytes: u64,
    },
}

fn parse_args<I, S>(args: I) -> Result<Mode, AnyError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let args = args
        .into_iter()
        .map(|arg| arg.as_ref().to_owned())
        .collect::<Vec<_>>();
    match args.as_slice() {
        [role, bind, bytes] if role == "pack-receive" => Ok(Mode::PackReceive {
            bind: bind.parse()?,
            bytes: bytes.parse()?,
        }),
        [role, bind, peer, bytes] if role == "pack-send" => Ok(Mode::PackSend {
            bind: bind.parse()?,
            peer: peer.parse()?,
            bytes: bytes.parse()?,
        }),
        _ => Err("usage: blob_stream_transport_benchmark pack-receive BIND PLAINTEXT_BYTES | pack-send BIND PEER PLAINTEXT_BYTES".into()),
    }
}

fn config(bind: SocketAddr, connect_timeout: Duration) -> EndpointConfig {
    EndpointConfig {
        bind,
        connect_timeout,
        exchange_timeout: Duration::from_secs(60),
        max_exchange_bytes: 2 * 1024 * 1024,
    }
}

fn receiver_config(bind: SocketAddr) -> EndpointConfig {
    // The one-shot device harness may listen while a slower CM4 builds a full
    // authenticated pack. Production nodes use a node-lifetime listener.
    config(bind, Duration::from_secs(5 * 60))
}

fn sender_config(bind: SocketAddr) -> EndpointConfig {
    config(bind, Duration::from_secs(30))
}

struct TempPack(PathBuf);

impl TempPack {
    fn new(role: &str) -> std::io::Result<Self> {
        let mut random = [0; 8];
        getrandom::fill(&mut random).map_err(std::io::Error::other)?;
        let root = std::env::temp_dir().join(format!(
            "aster-stream-pack-{role}-{}-{}",
            std::process::id(),
            u64::from_be_bytes(random)
        ));
        std::fs::create_dir(&root)?;
        Ok(Self(root))
    }
}

impl Drop for TempPack {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct PatternReader {
    offset: u64,
    total: u64,
}

impl Read for PatternReader {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        let len = usize::try_from((self.total - self.offset).min(output.len() as u64))
            .expect("bounded read length");
        for (relative, byte) in output[..len].iter_mut().enumerate() {
            *byte = ((self.offset + relative as u64) % 251) as u8;
        }
        self.offset += len as u64;
        Ok(len)
    }
}

fn blob_open(total_len: u64) -> BlobStreamOpen {
    BlobStreamOpen::new(
        BlobPublicationStreamId::from_bytes([0x12; 32]).expect("stream ID"),
        [0x22; 32],
        b"device-network-pipeline".to_vec(),
        [0x32; 32],
        1,
        VersionVector::default(),
        Topic::new("imagery").expect("topic"),
        Scope::new("mission/validation").expect("scope"),
        BlobMetadata::new(Some("application/octet-stream".into()), Vec::new()).expect("metadata"),
        Priority::Immediate,
        None,
        None,
        total_len,
        1,
        1,
        [0x42; 32],
        [0x52; 32],
    )
    .expect("Blob open")
}

fn pack_limits() -> PipelineLimits {
    PipelineLimits::new(4, 8, 16 * 1024 * 1024, 8).expect("pipeline limits")
}

fn print_pack_report(
    role: &str,
    report: &BlobNetworkReport,
    elapsed: Duration,
    path: &aster_iroh::PathWitness,
) {
    let roots = [report.roots.0, report.roots.1]
        .into_iter()
        .map(|root| {
            root.into_iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        })
        .collect::<Vec<_>>();
    let mib_s = report.attempt_bytes as f64 / (1024.0 * 1024.0) / elapsed.as_secs_f64();
    let completed = report
        .pipeline
        .as_ref()
        .map_or(0, |pipeline| pipeline.completed_items());
    println!(
        "ASTER_BLOB_NETWORK {{\"role\":\"{role}\",\"wire_bytes\":{},\"resumed_from\":{},\"attempt_bytes\":{},\"elapsed_ns\":{},\"mib_s\":{mib_s:.3},\"checkpoints\":{},\"segments\":{completed},\"plaintext_root\":\"{}\",\"ciphertext_root\":\"{}\",\"path\":\"{:?}\"}}",
        report.wire_bytes,
        report.resumed_from,
        report.attempt_bytes,
        elapsed.as_nanos(),
        report.checkpoints,
        roots[0],
        roots[1],
        path.selected,
    );
}

async fn pack_receive(bind: SocketAddr, plaintext_len: u64) -> Result<(), AnyError> {
    let root = TempPack::new("receive")?;
    let open = blob_open(plaintext_len);
    let wire_len =
        stream_validation::expected_pack_wire_len(plaintext_len).map_err(std::io::Error::other)?;
    let endpoint = Endpoint::bind_with_security_profile(
        SecretKey::from_bytes(&[0x71; 32]),
        receiver_config(bind),
        CarrierSecurityProfile::IrohQuicV1,
    )
    .await?;
    println!(
        "ASTER_STREAM_LISTEN {{\"id\":\"{}\",\"bind\":\"{}\"}}",
        endpoint.id(),
        bind
    );
    let connection = endpoint
        .accept(&BTreeSet::from([
            SecretKey::from_bytes(&[0x72; 32]).public()
        ]))
        .await?;
    let path = connection.path_witness();
    let started = Instant::now();
    let report = stream_validation::receive_completed_pack(
        connection.clone(),
        &open,
        BlobStreamSegmentOpener::from_test_key(
            *open.stream_id().as_bytes(),
            open.digest(),
            open.content_epoch(),
            [0x62; 32],
            [0x72; 12],
        ),
        &root.0,
        wire_len,
        pack_limits(),
    )
    .await
    .map_err(std::io::Error::other)?;
    print_pack_report("receive", &report, started.elapsed(), &path);
    connection.close();
    endpoint.close().await;
    Ok(())
}

async fn pack_send(bind: SocketAddr, peer: SocketAddr, plaintext_len: u64) -> Result<(), AnyError> {
    let root = TempPack::new("send")?;
    let open = blob_open(plaintext_len);
    let published = publish_blob_stream(
        PatternReader {
            offset: 0,
            total: plaintext_len,
        },
        &open,
        BlobStreamSegmentSealer::from_test_key(
            *open.stream_id().as_bytes(),
            open.digest(),
            open.content_epoch(),
            [0x62; 32],
            [0x72; 12],
        ),
        &root.0,
        pack_limits(),
    )
    .await?;
    let roots = (published.plaintext_root, published.ciphertext_root);
    println!(
        "ASTER_BLOB_PACK_READY {{\"plaintext_bytes\":{plaintext_len},\"segments\":{}}}",
        published.segment_count
    );
    std::io::stdout().flush()?;
    let endpoint = Endpoint::bind_with_security_profile(
        SecretKey::from_bytes(&[0x72; 32]),
        sender_config(bind),
        CarrierSecurityProfile::IrohQuicV1,
    )
    .await?;
    let connection = endpoint
        .connect(ExpectedPeer {
            id: SecretKey::from_bytes(&[0x71; 32]).public(),
            address: peer,
        })
        .await?;
    let path = connection.path_witness();
    let started = Instant::now();
    let report = stream_validation::send_completed_pack(connection.clone(), &open, &root.0, roots)
        .await
        .map_err(std::io::Error::other)?;
    print_pack_report("send", &report, started.elapsed(), &path);
    connection.close();
    endpoint.close().await;
    Ok(())
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), AnyError> {
    let mode = parse_args(std::env::args().skip(1))?;
    match mode {
        Mode::PackReceive { bind, bytes } => pack_receive(bind, bytes).await,
        Mode::PackSend { bind, peer, bytes } => pack_send(bind, peer, bytes).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_exposes_only_completed_pack_device_modes() {
        assert!(matches!(
            parse_args(["pack-receive", "192.168.60.79:18293", "67108864"]),
            Ok(Mode::PackReceive {
                bytes: 67_108_864,
                ..
            })
        ));
        assert!(matches!(
            parse_args([
                "pack-send",
                "192.168.60.80:0",
                "192.168.60.79:18293",
                "67108864"
            ]),
            Ok(Mode::PackSend {
                bytes: 67_108_864,
                ..
            })
        ));
        assert!(parse_args(["send", "127.0.0.1:0", "127.0.0.1:1", "1024"]).is_err());
        assert!(parse_args(["loopback", "1024"]).is_err());
    }

    #[test]
    fn one_shot_receiver_outlives_cm4_full_pack_preparation() {
        let bind = "127.0.0.1:0".parse().expect("loopback bind");

        assert!(receiver_config(bind).connect_timeout >= Duration::from_secs(180));
        assert_eq!(sender_config(bind).connect_timeout, Duration::from_secs(30));
    }
}
