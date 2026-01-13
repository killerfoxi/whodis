use clap::{Parser, ValueEnum};
use color_eyre::eyre::{Context, Result, eyre};
use futures::StreamExt;
use hickory_client::client::Client;
use hickory_client::proto::dnssec::rdata::KEY;
use hickory_client::proto::dnssec::{SigSigner, SigningKey};
use hickory_client::proto::op::{Message, OpCode, Query, ResponseCode, UpdateMessage};
use hickory_client::proto::rr::{DNSClass, Name, RData, Record, RecordType, rdata};
use hickory_client::proto::runtime::TokioRuntimeProvider;
use hickory_client::proto::tcp::TcpClientStream;
use hickory_client::proto::xfer::DnsHandle;
use local_ip_address::{local_ip, local_ipv6};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, instrument};

mod key_validator;

const KEY_BYTES: &[u8] = include_bytes!("../dns_update.key");

#[derive(ValueEnum, Clone, Debug, Default)]
enum IpMode {
    #[default]
    Both,
    V4Only,
    V6Only,
}

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// The zone to update in (e.g. `dyn.lan`).
    #[arg(short, long)]
    zone: String,

    /// FQDN of the hostname entry (e.g. `laptop.dyn.lan`).
    #[arg(short = 'n', long)]
    hostname: String,

    /// The DNS server to send the update to. Example: `192.168.1.53:53`.
    #[arg(short, long)]
    server: SocketAddr,

    /// Restrict update to a specific protocol. Defaults to 'both'.
    #[arg(value_enum, short = 'm', long, default_value_t = IpMode::Both)]
    mode: IpMode,

    /// Explicit IP address(es) to set. Can be specified multiple times.
    /// If provided, auto-detection is skipped.
    #[arg(long)]
    ip: Vec<IpAddr>,
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "whodis=info".into()),
        )
        .init();

    let args = Args::parse();

    if let Err(e) = run_update_workflow(args).await {
        tracing::error!("DNS Update failed: {:?}", e);
        return Err(e);
    }
    Ok(())
}

#[instrument(skip(args))]
async fn run_update_workflow(args: Args) -> Result<()> {
    let ips = determine_ips(&args.mode, args.ip)?;

    if ips.is_empty() {
        // This likely means we are in 'Both' mode but found NO IPs at all,
        // or the user requested v6-only on a v4-only machine.
        return Err(eyre!("No applicable IP addresses found to update."));
    }

    info!(hostname = %args.hostname, ips = ?ips, mode = ?args.mode, "Resolved update targets");

    let zone_name = Name::from_str(&args.zone).context("Invalid zone name format")?;
    let host_name = Name::from_str(&args.hostname).context("Invalid hostname format")?;

    debug!(server = ?args.server, "Establishing authenticated connection");
    let mut updater = DnsUpdater::connect(args.server, zone_name.clone(), KEY_BYTES).await?;

    info!("Dispatching DNS update request");
    updater.apply_update(host_name, ips).await?;

    info!("DNS Update completed successfully");
    Ok(())
}

/// Determines which IPs to register based on the selected Mode.
fn determine_ips(mode: &IpMode, explicit: Vec<IpAddr>) -> Result<Vec<IpAddr>> {
    // Helper: Returns true if the IP matches the requested mode logic
    let is_compatible = |ip: &IpAddr| match mode {
        IpMode::V4Only => ip.is_ipv4(),
        IpMode::V6Only => ip.is_ipv6(),
        IpMode::Both => true,
    };

    // Handle provided ips first.
    if !explicit.is_empty() {
        let filtered: Vec<IpAddr> = explicit.into_iter().filter(is_compatible).collect();
        if filtered.is_empty() {
            return Err(eyre!(
                "Explicit IPs provided, but none matched the selected mode ({:?})",
                mode
            ));
        }
        return Ok(filtered);
    }

    // Gather ips
    let mut detected = Vec::new();

    if matches!(mode, IpMode::V4Only | IpMode::Both) {
        match local_ip() {
            Ok(ip) => detected.push(ip),
            Err(e) => {
                if let IpMode::V4Only = mode {
                    return Err(eyre!("Failed to detect local IPv4: {}", e));
                }
                debug!("No IPv4 address detected (skipping v4 update)");
            }
        }
    }

    if matches!(mode, IpMode::V6Only | IpMode::Both) {
        match local_ipv6() {
            Ok(ip) => detected.push(ip),
            Err(e) => {
                if let IpMode::V6Only = mode {
                    return Err(eyre!("Failed to detect local IPv6: {}", e));
                }
                debug!("No IPv6 address detected (skipping v6 update)");
            }
        }
    }

    Ok(detected)
}

struct DnsUpdater {
    client: Client,
    zone: Name,
}

impl DnsUpdater {
    async fn connect(server: SocketAddr, zone: Name, key_material: &[u8]) -> Result<Self> {
        let signing_key = key_validator::load_and_validate(key_material)?;
        let public_key = signing_key.to_public_key().context("Deriving public key")?;

        let signer = SigSigner::sig0(
            KEY::new_sig0key(&public_key),
            Box::new(signing_key),
            zone.clone(),
        );

        let (stream, sender) = TcpClientStream::new(
            server,
            None,
            Some(Duration::from_secs(5)),
            TokioRuntimeProvider::new(),
        );
        let (client, bg) = Client::new(stream, sender, Some(Arc::new(signer)))
            .await
            .context("DNS Handshake")?;

        tokio::spawn(bg);
        Ok(Self { client, zone })
    }

    #[instrument(skip(self), fields(zone = %self.zone))]
    async fn apply_update(&mut self, host: Name, ips: Vec<IpAddr>) -> Result<()> {
        let msg = self.construct_packet(host, ips);

        let mut response_stream = self.client.send(msg);
        match response_stream.next().await {
            Some(Ok(resp)) => match resp.response_code() {
                ResponseCode::NoError => Ok(()),
                code => Err(eyre!("Server refused update: {}", code)),
            },
            Some(Err(e)) => Err(e).context("Network error during update"),
            None => Err(eyre!("Connection closed unexpectedly")),
        }
    }

    fn construct_packet(&self, host: Name, ips: Vec<IpAddr>) -> Message {
        let mut msg = Message::new();
        msg.set_op_code(OpCode::Update);
        msg.set_id(rand::random());

        let mut zone_section = Query::new();
        zone_section.set_name(self.zone.clone());
        zone_section.set_query_type(RecordType::SOA);
        msg.add_zone(zone_section);

        for ip in ips {
            let (rdata, rtype) = match ip {
                IpAddr::V4(addr) => (RData::A(rdata::A(addr)), RecordType::A),
                IpAddr::V6(addr) => (RData::AAAA(rdata::AAAA(addr)), RecordType::AAAA),
            };

            // Class ANY + Specific Type = Delete that RRSet.
            let mut delete_op = Record::update0(host.clone(), 0, rtype);
            delete_op.set_dns_class(DNSClass::ANY);
            msg.add_update(delete_op.into_record_of_rdata());

            let mut add_op = Record::from_rdata(host.clone(), 300, rdata.clone());
            add_op.set_dns_class(DNSClass::IN);
            add_op.set_data(rdata);
            msg.add_update(add_op);
        }

        msg
    }
}
