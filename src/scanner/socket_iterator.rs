//! 迭代 IP 和端口组合的 Socket 迭代器。
use itertools::{iproduct, Product};
use std::net::{IpAddr, SocketAddr};

pub struct SocketIterator<'s> {
    product_it:
        Product<Box<std::slice::Iter<'s, u16>>, Box<std::slice::Iter<'s, std::net::IpAddr>>>,
}

impl<'s> SocketIterator<'s> {
    pub fn new(ips: &'s [IpAddr], ports: &'s [u16]) -> Self {
        let ports_it = Box::new(ports.iter());
        let ips_it = Box::new(ips.iter());
        Self {
            product_it: iproduct!(ports_it, ips_it),
        }
    }
}

#[allow(clippy::doc_link_with_quotes)]
impl Iterator for SocketIterator<'_> {
    type Item = SocketAddr;

    /// 基于提供的 IP 和端口之一的组合返回一个 socket，
    /// 或者当这些组合用尽时返回 None。
    /// 每个 IP 将具有相同的端口，直到端口递增。
    ///
    /// let it = SocketIterator::new(&["127.0.0.1", "192.168.0.1"], &[80, 443]);
    /// it.next(); // 127.0.0.1:80
    /// it.next(); // 192.168.0.1:80
    /// it.next(); // 127.0.0.1:443
    /// it.next(); // 192.168.0.1:443
    /// it.next(); // None
    fn next(&mut self) -> Option<Self::Item> {
        self.product_it
            .next()
            .map(|(port, ip)| SocketAddr::new(*ip, *port))
    }
}

#[cfg(test)]
mod tests {
    use super::SocketIterator;
    use std::net::{IpAddr, SocketAddr};

    #[test]
    fn goes_through_every_ip_port_combination() {
        let addrs = vec![
            "127.0.0.1".parse::<IpAddr>().unwrap(),
            "192.168.0.1".parse::<IpAddr>().unwrap(),
        ];
        let ports: Vec<u16> = vec![22, 80, 443];
        let mut it = SocketIterator::new(&addrs, &ports);

        assert_eq!(Some(SocketAddr::new(addrs[0], ports[0])), it.next());
        assert_eq!(Some(SocketAddr::new(addrs[1], ports[0])), it.next());
        assert_eq!(Some(SocketAddr::new(addrs[0], ports[1])), it.next());
        assert_eq!(Some(SocketAddr::new(addrs[1], ports[1])), it.next());
        assert_eq!(Some(SocketAddr::new(addrs[0], ports[2])), it.next());
        assert_eq!(Some(SocketAddr::new(addrs[1], ports[2])), it.next());
        assert_eq!(None, it.next());
    }
}
