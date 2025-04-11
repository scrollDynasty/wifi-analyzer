use anyhow::Result;
use pcap::Packet;
use pnet::util::MacAddr;

/// Структура для представления заголовка 802.11
#[derive(Debug)]
pub struct WifiHeader {
    pub frame_control: u16,
    pub duration: u16,
    pub address1: MacAddr,
    pub address2: MacAddr,
    pub address3: MacAddr,
    pub sequence_control: u16,
}

/// Типы фреймов 802.11
#[derive(Debug, PartialEq)]
pub enum FrameType {
    Management,
    Control,
    Data,
    Unknown,
}

/// Подтипы управляющих фреймов
#[derive(Debug)]
pub enum ManagementSubtype {
    Beacon,
    ProbeRequest,
    ProbeResponse,
    AssociationRequest,
    AssociationResponse,
    ReassociationRequest,
    ReassociationResponse,
    Disassociation,
    Authentication,
    Deauthentication,
    Unknown,
}

impl WifiHeader {
    /// Парсинг заголовка WiFi пакета
    pub fn parse(packet: &Packet) -> Result<Self> {
        let data = packet.data;
        
        // Проверяем минимальную длину пакета
        if data.len() < 24 {
            return Err(anyhow::anyhow!("Пакет слишком короткий для заголовка 802.11"));
        }
        
        Ok(WifiHeader {
            frame_control: u16::from_le_bytes([data[0], data[1]]),
            duration: u16::from_le_bytes([data[2], data[3]]),
            address1: MacAddr::new(data[4], data[5], data[6], data[7], data[8], data[9]),
            address2: MacAddr::new(data[10], data[11], data[12], data[13], data[14], data[15]),
            address3: MacAddr::new(data[16], data[17], data[18], data[19], data[20], data[21]),
            sequence_control: u16::from_le_bytes([data[22], data[23]]),
        })
    }
    
    /// Получение типа фрейма
    pub fn frame_type(&self) -> FrameType {
        match (self.frame_control & 0x0C) >> 2 {
            0 => FrameType::Management,
            1 => FrameType::Control,
            2 => FrameType::Data,
            _ => FrameType::Unknown,
        }
    }
    
    /// Получение подтипа управляющего фрейма
    pub fn management_subtype(&self) -> ManagementSubtype {
        if self.frame_type() != FrameType::Management {
            return ManagementSubtype::Unknown;
        }
        
        match (self.frame_control & 0xF0) >> 4 {
            0x08 => ManagementSubtype::Beacon,
            0x04 => ManagementSubtype::ProbeRequest,
            0x05 => ManagementSubtype::ProbeResponse,
            0x00 => ManagementSubtype::AssociationRequest,
            0x01 => ManagementSubtype::AssociationResponse,
            0x02 => ManagementSubtype::ReassociationRequest,
            0x03 => ManagementSubtype::ReassociationResponse,
            0x0A => ManagementSubtype::Disassociation,
            0x0B => ManagementSubtype::Authentication,
            0x0C => ManagementSubtype::Deauthentication,
            _ => ManagementSubtype::Unknown,
        }
    }
}

/// Извлечение SSID из Beacon фрейма
pub fn extract_ssid(packet: &Packet) -> Option<String> {
    let data = packet.data;
    if data.len() < 38 {
        return None;
    }
    
    // Ищем поле SSID в Beacon фрейме
    let mut offset = 36;
    while offset < data.len() {
        let element_id = data[offset];
        let length = data[offset + 1] as usize;
        
        if element_id == 0 && length > 0 {
            let ssid_bytes = &data[offset + 2..offset + 2 + length];
            return Some(String::from_utf8_lossy(ssid_bytes).into_owned());
        }
        
        offset += 2 + length;
    }
    
    None
}

/// Извлечение уровня сигнала из пакета
pub fn extract_signal_strength(_packet: &Packet) -> i8 {
    // В реальном приложении здесь нужно использовать radiotap заголовок
    // или другую информацию о радио-параметрах
    0
}

/// Извлечение канала из Beacon фрейма
pub fn extract_channel(packet: &Packet) -> Option<u8> {
    let data = packet.data;
    if data.len() < 38 {
        return None;
    }
    
    // Ищем поле Channel в Beacon фрейме
    let mut offset = 36;
    while offset < data.len() {
        let element_id = data[offset];
        let length = data[offset + 1] as usize;
        
        if element_id == 3 && length >= 1 {
            return Some(data[offset + 2]);
        }
        
        offset += 2 + length;
    }
    
    None
}

/// Функция для парсинга MAC-адреса из строки
pub fn parse_mac_addr(mac_str: &str) -> Result<MacAddr> {
    let parts: Vec<&str> = mac_str.split(':').collect();
    if parts.len() != 6 {
        return Err(anyhow::anyhow!("Неверный формат MAC-адреса"));
    }
    
    let bytes: Result<Vec<u8>, _> = parts
        .iter()
        .map(|&s| u8::from_str_radix(s, 16))
        .collect();
    
    let bytes = bytes?;
    Ok(MacAddr::new(bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]))
} 