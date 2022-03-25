use std::{collections::HashMap as StdHashMap, net::IpAddr};
use tokio::{
    sync::mpsc::{UnboundedReceiver, UnboundedSender},
    time::{Duration, Instant},
};
use tracing::{debug, warn};

/// Syn contains the necessary information for tracking connections for blocking purposes
#[derive(Clone, Copy, Debug)]
pub struct Syn {
    pub source_ip: IpAddr,
    pub dest_port: u16,
    pub observation: Instant,
}

pub struct Tracker {
    ports: StdHashMap<IpAddr, StdHashMap<u16, Instant>>,
    rx: UnboundedReceiver<Syn>,
    tx: UnboundedSender<IpAddr>,
}

impl Tracker {
    pub fn new(rx: UnboundedReceiver<Syn>, tx: UnboundedSender<IpAddr>) -> Self {
        Tracker {
            ports: StdHashMap::new(),
            rx,
            tx,
        }
    }

    pub async fn run(mut self) {
        while let Some(msg) = self.rx.recv().await {
            debug!(
                "Received Syn: Source: {}, Port: {}",
                msg.source_ip, msg.dest_port
            );
            if let Some(syn) = self.ports.get_mut(&msg.source_ip) {
                if should_block(syn, msg.dest_port, Instant::now()) {
                    let p: String = syn
                        .keys()
                        .map(|p| p.to_string())
                        .collect::<Vec<String>>()
                        .join(", ");
                    warn!("Port scanning detected: {}", p);
                    self.tx.send(msg.source_ip).unwrap();
                    warn!("IP {} has been blocked.", msg.source_ip);
                    self.ports.remove(&msg.source_ip);
                }
            } else {
                let mut port = StdHashMap::with_capacity(4);
                port.insert(msg.dest_port, msg.observation);
                self.ports.insert(msg.source_ip, port);
            }
        }
    }
}

fn should_block(tracked_ports: &mut StdHashMap<u16, Instant>, port: u16, now: Instant) -> bool {
    tracked_ports.retain(|_, created| now.duration_since(*created) < Duration::new(60, 0));
    let update = tracked_ports.insert(port, now);
    if update.is_none() && tracked_ports.len() > 3 {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn block() {
        let mut ports = StdHashMap::with_capacity(4);
        let now = Instant::now();

        assert_eq!(should_block(&mut ports, 8000, now), false);
        assert_eq!(
            should_block(
                &mut ports,
                8001,
                now.checked_add(Duration::new(1, 0)).unwrap()
            ),
            false
        );
        assert_eq!(
            should_block(
                &mut ports,
                8002,
                now.checked_add(Duration::new(1, 0)).unwrap()
            ),
            false
        );
        assert_eq!(
            should_block(
                &mut ports,
                8003,
                now.checked_add(Duration::new(1, 0)).unwrap()
            ),
            true
        );
    }
}
