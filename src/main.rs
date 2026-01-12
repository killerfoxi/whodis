use clap::Parser;
use color_eyre::Section;
use color_eyre::eyre::{Context, Result, eyre};

use futures::StreamExt;
use hickory_client::client::Client;
use hickory_client::proto::dnssec::crypto::RsaSigningKey;
use hickory_client::proto::dnssec::rdata::KEY;
use hickory_client::proto::op::{Message, OpCode, Query, UpdateMessage};
use hickory_client::proto::runtime::TokioRuntimeProvider;
// Helper for async IO
use hickory_client::proto::dnssec::{Algorithm, SigSigner, SigningKey};
use hickory_client::proto::rr::{DNSClass, Name, RData, Record, RecordType, rdata};
use hickory_client::proto::tcp::TcpClientStream;
use hickory_client::proto::xfer::DnsHandle;
use local_ip_address::local_ip;
use rustls_pki_types::PrivateKeyDer;
use rustls_pki_types::pem::PemObject;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, instrument};

const KEY_BYTES: &[u8] = include_bytes!("../dns_update.key");

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    #[arg(short, long)]
    zone: String,

    #[arg(short = 'n', long)]
    hostname: String,

    #[arg(short, long)]
    server: SocketAddr,

    #[arg(long)]
    ip: Option<IpAddr>,
}

#[tokio::main]
#[instrument]
async fn main() -> Result<()> {
    color_eyre::install()?;

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "whodis=info".into()),
        )
        .init();

    let args = Args::parse();

    let ip = match args.ip {
        Some(ip) => ip,
        None => local_ip().context("Failed to determine local IP address")?,
    };

    info!(hostname = %args.hostname, ip = ?ip, "Resolved update target");

    debug!("Constructing DNS Update packet");
    let zone_name = Name::from_str(&args.zone).context("Invalid zone name")?;
    let hostname_rr = Name::from_str(&args.hostname).context("Invalid hostname")?;

    let mut msg = Message::new();
    msg.set_op_code(OpCode::Update);
    msg.set_id(rand::random());

    let mut zone = Query::new();
    zone.set_name(zone_name.clone());
    zone.set_query_type(RecordType::SOA);
    msg.add_zone(zone);

    // Delete old records (ANY class = delete all RRsets for this name)
    let mut delete_record = Record::update0(hostname_rr.clone(), 0, RecordType::ANY);
    delete_record.set_dns_class(DNSClass::ANY);
    msg.add_update(delete_record.into_record_of_rdata());

    let data = match ip {
        IpAddr::V4(ipv4) => RData::A(rdata::A(ipv4)),
        IpAddr::V6(_) => return Err(eyre!("IPv6 not implemented yet")),
    };
    // Add new record
    let mut add_record = Record::from_rdata(hostname_rr, 300, data.clone());
    add_record.set_dns_class(DNSClass::IN);
    add_record.set_data(data);
    msg.add_update(add_record);

    debug!("Loading embedded key");
    let key_der = PrivateKeyDer::from_pem_slice(KEY_BYTES).context("Parsing embedded key")?;
    let signing_key = Box::new(
        RsaSigningKey::from_key_der(&key_der, Algorithm::RSASHA256)
            .context("Constructing signing key.")
            .suggestion("Wrong algorithm?")?,
    );
    let pubkey = signing_key
        .to_public_key()
        .context("Extracting public key")?;
    let signer = SigSigner::sig0(KEY::new_sig0key(&pubkey), signing_key, zone_name);

    debug!(server = ?args.server, "Connecting to DNS server via TCP...");

    let (stream, sender) = TcpClientStream::new(
        args.server,
        None,
        Some(Duration::from_secs(5)),
        TokioRuntimeProvider::new(),
    );

    let (client, bg) = Client::new(stream, sender, Some(Arc::new(signer)))
        .await
        .context("Failed to establish DNS connection")?;

    tokio::spawn(bg);

    info!(server = ?args.server, "Sending authenticated update");

    while let Some(resp) = client.send(msg).next().await {
        match resp
            .context("Error during response handling")?
            .response_code()
        {
            hickory_client::proto::op::ResponseCode::NoError => {
                info!("DNS Update successful");
                return Ok(());
            }
            code => {
                return Err(eyre!("Update failed"))
                    .with_context(|| format!("Response Code: {code}"));
            }
        }
    }
    Err(eyre!("No answers?"))
}
