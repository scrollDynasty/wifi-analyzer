use anyhow::{Context, Result};
use clap::Parser;
use colored::*;
use log::{error, info, warn};
use pcap::{Active, Capture, Device};
use std::collections::HashMap;
use std::process::Command;
use std::net::MacAddr;

mod packet;
mod deauth;
use packet::{WifiHeader, extract_ssid, extract_signal_strength, extract_channel};
use deauth::{send_deauth, deauth_all_clients};

/// Структура для хранения информации о точке доступа
#[derive(Debug, Clone)]
struct AccessPoint {
    bssid: String,
    ssid: String,
    channel: u8,
    signal_strength: i8,
    clients: Vec<String>,
}

/// Аргументы командной строки
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Сетевой интерфейс для мониторинга
    #[arg(short, long)]
    interface: String,
    
    /// MAC-адрес точки доступа для деаутентификации
    #[arg(short, long)]
    deauth: Option<String>,
}

fn main() -> Result<()> {
    // Инициализация логгера
    env_logger::init();
    
    // Парсинг аргументов командной строки
    let args = Args::parse();
    
    // Переводим интерфейс в режим мониторинга
    set_monitor_mode(&args.interface)?;
    
    // Создаем захват пакетов
    let mut cap = create_capture(&args.interface)?;
    
    // Хранилище для точек доступа
    let mut access_points: HashMap<String, AccessPoint> = HashMap::new();
    
    info!("Начинаем сканирование WiFi сетей...");
    println!("{}", "Сканирование WiFi сетей...".green().bold());
    
    // Если указан MAC-адрес для деаутентификации
    if let Some(target_mac) = args.deauth {
        let target_mac = MacAddr::parse_str(&target_mac)?;
        
        // Ждем обнаружения целевой точки доступа
        while let Ok(packet) = cap.next_packet() {
            if let Err(e) = process_packet(packet, &mut access_points) {
                warn!("Ошибка обработки пакета: {}", e);
            }
            
            // Если нашли целевую точку доступа
            if let Some(ap) = access_points.get(&target_mac.to_string()) {
                info!("Найдена целевая точка доступа: {}", ap.ssid);
                
                // Конвертируем MAC-адреса клиентов
                let clients: Vec<MacAddr> = ap.clients
                    .iter()
                    .filter_map(|c| MacAddr::parse_str(c).ok())
                    .collect();
                
                // Деаутентифицируем всех клиентов
                deauth_all_clients(&args.interface, target_mac, &clients)?;
                break;
            }
        }
    } else {
        // Обычный режим сканирования
        while let Ok(packet) = cap.next_packet() {
            if let Err(e) = process_packet(packet, &mut access_points) {
                warn!("Ошибка обработки пакета: {}", e);
            }
            
            if access_points.len() > 0 {
                print_access_points(&access_points);
            }
        }
    }
    
    Ok(())
}

/// Установка режима мониторинга для интерфейса
fn set_monitor_mode(interface: &str) -> Result<()> {
    info!("Перевод интерфейса {} в режим мониторинга", interface);
    
    // Останавливаем интерфейс
    Command::new("ifconfig")
        .arg(interface)
        .arg("down")
        .status()
        .context("Не удалось остановить интерфейс")?;
    
    // Устанавливаем режим мониторинга
    Command::new("iwconfig")
        .arg(interface)
        .arg("mode")
        .arg("monitor")
        .status()
        .context("Не удалось установить режим мониторинга")?;
    
    // Запускаем интерфейс
    Command::new("ifconfig")
        .arg(interface)
        .arg("up")
        .status()
        .context("Не удалось запустить интерфейс")?;
    
    Ok(())
}

/// Создание захвата пакетов
fn create_capture(interface: &str) -> Result<Capture<Active>> {
    let cap = Capture::from_device(interface)?
        .promisc(true)
        .snaplen(65535)
        .timeout(1000)
        .open()?;
    
    Ok(cap)
}

/// Обработка захваченного пакета
fn process_packet(packet: pcap::Packet, access_points: &mut HashMap<String, AccessPoint>) -> Result<()> {
    // Парсим заголовок WiFi пакета
    let header = WifiHeader::parse(&packet)?;
    
    // Обрабатываем только управляющие фреймы
    if header.frame_type() == packet::FrameType::Management {
        match header.management_subtype() {
            packet::ManagementSubtype::Beacon => {
                // Обработка Beacon фреймов
                if let Some(ssid) = extract_ssid(&packet) {
                    let bssid = header.address2.to_string();
                    let channel = extract_channel(&packet).unwrap_or(0);
                    let signal_strength = extract_signal_strength(&packet);
                    
                    access_points.insert(bssid.clone(), AccessPoint {
                        bssid,
                        ssid,
                        channel,
                        signal_strength,
                        clients: Vec::new(),
                    });
                }
            },
            packet::ManagementSubtype::ProbeRequest => {
                // Обработка Probe Request фреймов
                let client_mac = header.address2.to_string();
                let bssid = header.address1.to_string();
                
                if let Some(ap) = access_points.get_mut(&bssid) {
                    if !ap.clients.contains(&client_mac) {
                        ap.clients.push(client_mac);
                    }
                }
            },
            _ => {}
        }
    }
    
    Ok(())
}

/// Вывод информации о найденных точках доступа
fn print_access_points(access_points: &HashMap<String, AccessPoint>) {
    println!("\n{}", "Обнаруженные WiFi сети:".cyan().bold());
    println!("{:-<80}", "");
    println!("{:<20} {:<20} {:<10} {:<10} {}", 
        "BSSID".yellow(),
        "SSID".yellow(),
        "Channel".yellow(),
        "Signal".yellow(),
        "Clients".yellow()
    );
    println!("{:-<80}", "");
    
    for ap in access_points.values() {
        println!("{:<20} {:<20} {:<10} {:<10} {}",
            ap.bssid,
            ap.ssid,
            ap.channel,
            format!("{} dBm", ap.signal_strength),
            ap.clients.join(", ")
        );
    }
} 