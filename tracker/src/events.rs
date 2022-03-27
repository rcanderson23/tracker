use std::net::IpAddr;

use aya::maps::{perf::AsyncPerfEventArrayBuffer, MapRefMut};
use bytes::BytesMut;
use metrics::increment_counter;
use tokio::{sync::mpsc::UnboundedSender, task, time::Instant};
use tracing::{info, error};
use tracker_common::{Connection, ConnectionV6};

use crate::tracker::Syn;

pub trait ConnExt {
    fn source_ip(&self) -> IpAddr;
    fn dest_ip(&self) -> IpAddr;
    fn source_port(&self) -> u16;
    fn dest_port(&self) -> u16;
}

impl ConnExt for Connection {
    fn source_ip(&self) -> IpAddr {
        IpAddr::V4(self.source_ip.into())
    }

    fn dest_ip(&self) -> IpAddr {
        IpAddr::V4(self.dest_ip.into())
    }

    fn source_port(&self) -> u16 {
        self.source_port
    }

    fn dest_port(&self) -> u16 {
        self.dest_port
    }
}

impl ConnExt for ConnectionV6 {
    fn source_ip(&self) -> IpAddr {
        IpAddr::V6(self.source_ip.into())
    }

    fn dest_ip(&self) -> IpAddr {
        IpAddr::V6(self.dest_ip.into())
    }

    fn source_port(&self) -> u16 {
        self.source_port
    }

    fn dest_port(&self) -> u16 {
        self.dest_port
    }
}

pub async fn event_loop<T: ConnExt>(
    tx: UnboundedSender<Syn>,
    mut buf: AsyncPerfEventArrayBuffer<MapRefMut>,
) {
    task::spawn(async move {
        let mut buffers = (0..10)
            .map(|_| BytesMut::with_capacity(65536))
            .collect::<Vec<_>>();

        loop {
            if let Ok(events) = buf.read_events(&mut buffers).await {
                for event in buffers.iter_mut().take(events.read) {
                    increment_counter!("connection_attempts");
                    let ptr = event.as_ptr() as *const T;
                    let data = unsafe { ptr.read_unaligned() };
                    let source_ip = data.source_ip();
                    let source_port = data.source_port();
                    let dest_ip = data.dest_ip();
                    let dest_port = data.dest_port();
                    info!("{}:{} -> {}:{}", source_ip, source_port, dest_ip, dest_port);
                    tx.send(Syn {
                        source_ip,
                        dest_port,
                        observation: Instant::now(),
                    })
                    .unwrap();
                }
            } else {
                error!("failed to read events from ebpf array")
            }
        }
    });
}
