use anyhow::Context;
use axum::{routing::get, Router};
use aya::{
    maps::HashMap,
    maps::{perf::AsyncPerfEventArray, MapRefMut},
    programs::{Xdp, XdpFlags},
    util::online_cpus,
    Bpf,
};
use clap::Parser;
use metrics::register_counter;
use metrics_exporter_prometheus::PrometheusBuilder;
use std::{
    fs,
    future::ready,
    net::{IpAddr, SocketAddr},
};
use tokio::{signal, sync::mpsc::UnboundedSender, task};
use tokio::sync::{mpsc, mpsc::UnboundedReceiver};
use tracing::{error, info};
use tracker_common::{Connection, ConnectionV6};
mod tracker;
mod events;
use tracker::{Syn, Tracker};
use events::*;

/// Program to track and block port scanners
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Path to the ebpf program
    #[clap(short, long)]
    path: String,

    /// Interface to load program into
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "tracker=info".into()))
        .init();

    let args = Args::parse();

    let data = fs::read(args.path)?;
    let mut bpf = Bpf::load(&data)?;

    let probe: &mut Xdp = bpf.program_mut("xdp").unwrap().try_into()?;
    probe.load()?;
    probe.attach(&args.iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    let blocklist: HashMap<_, u32, u32> = HashMap::try_from(bpf.map_mut("BLOCKLIST")?)?;
    let blocklist_v6: HashMap<_, u128, u32> = HashMap::try_from(bpf.map_mut("BLOCKLISTV6")?)?;
    let mut perf_array = AsyncPerfEventArray::try_from(bpf.map_mut("EVENTS")?)?;
    let mut perf_array_v6 = AsyncPerfEventArray::try_from(bpf.map_mut("EVENTSV6")?)?;

    // setup metrics server
    info!("Starting metrics server on :9090");
    setup_metrics_server().await;

    let (tx, rx): (UnboundedSender<Syn>, UnboundedReceiver<Syn>) = mpsc::unbounded_channel();
    let (block_tx, block_rx): (UnboundedSender<IpAddr>, UnboundedReceiver<IpAddr>) =
        mpsc::unbounded_channel();

    info!("starting blocker loop");
    start_block_loop(block_rx, blocklist, blocklist_v6).await;

    info!("starting event loops");
    for cpu_id in online_cpus()? {
        let buf_v4 = perf_array.open(cpu_id, None)?;
        let buf_v6 = perf_array_v6.open(cpu_id, None)?;
        event_loop::<Connection>(tx.clone(), buf_v4).await;
        event_loop::<ConnectionV6>(tx.clone(), buf_v6).await;
    }

    info!("starting blocker");
    let tracker = Tracker::new(rx, block_tx);
    task::spawn(async move {
        tracker.run().await;
    });
    info!("waiting for ctrl-c");
    signal::ctrl_c().await.expect("failed to listen for event");
    Ok::<_, anyhow::Error>(())
}

async fn setup_metrics_server() {
    let builder = PrometheusBuilder::new();
    let recorder = builder.install_recorder().unwrap();
    register_counter!("connection_attempts");

    let app = Router::new().route("/metrics", get(move || ready(recorder.render())));

    let addr = SocketAddr::from(([0, 0, 0, 0], 9090));
    task::spawn(async move {
        axum::Server::bind(&addr)
            .serve(app.into_make_service())
            .await
            .unwrap()
    });
}

async fn start_block_loop(
    mut rx: UnboundedReceiver<IpAddr>,
    mut blocklist_v4: HashMap<MapRefMut, u32, u32>,
    mut blocklist_v6: HashMap<MapRefMut, u128, u32>,
) {
    task::spawn(async move {
        loop {
            if let Some(ip) = rx.recv().await {
                match ip {
                    IpAddr::V4(v4) => blocklist_v4
                        .insert(v4.into(), 0, 0)
                        .unwrap_or_else(|_| error!("failed to insert IP into blocklist: {}", v4)),
                    IpAddr::V6(v6) => blocklist_v6
                        .insert(v6.into(), 0, 0)
                        .unwrap_or_else(|_| error!("failed to insert IP into blocklist: {}", v6)),
                }
            }
        }
    });
}

