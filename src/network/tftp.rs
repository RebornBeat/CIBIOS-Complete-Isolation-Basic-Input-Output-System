// =============================================================================
// NETWORK TFTP MODULE - cibios/src/network/tftp.rs  
// =============================================================================

use anyhow::{Context, Result as AnyhowResult};
use serde::{Deserialize, Serialize};
use log::{debug, error, info, warn};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use super::NetworkAdapter;

/// TFTP (Trivial File Transfer Protocol) client for firmware file downloads
#[derive(Debug)]
pub struct TFTPClient {
    network_adapter: Arc<NetworkAdapter>,
    configuration: TFTPConfiguration,
}

/// TFTP configuration for file transfers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TFTPConfiguration {
    pub timeout_seconds: u64,
    pub retry_count: u32,
    pub block_size: u16,
    pub mode: TFTPMode,
}

/// TFTP transfer modes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TFTPMode {
    Octet,  // Binary mode
    Netascii, // Text mode
}

/// TFTP transfer state
#[derive(Debug)]
pub struct TFTPTransfer {
    pub server_addr: SocketAddr,
    pub filename: String,
    pub mode: TFTPMode,
    pub block_size: u16,
    pub total_bytes: Option<u64>,
    pub transferred_bytes: u64,
}

/// TFTP packet types
#[derive(Debug, Clone)]
enum TFTPPacket {
    ReadRequest { filename: String, mode: String },
    WriteRequest { filename: String, mode: String },
    Data { block: u16, data: Vec<u8> },
    Acknowledgment { block: u16 },
    Error { error_code: u16, error_message: String },
}

impl TFTPClient {
    /// Initialize TFTP client
    pub async fn initialize(network_adapter: &Arc<NetworkAdapter>) -> AnyhowResult<Self> {
        info!("Initializing TFTP client");

        let configuration = TFTPConfiguration::default();

        Ok(Self {
            network_adapter: network_adapter.clone(),
            configuration,
        })
    }

    /// Download file from TFTP server
    pub async fn download_file(&self, server_ip: IpAddr, filename: &str) -> AnyhowResult<Vec<u8>> {
        info!("Downloading file from TFTP server {}: {}", server_ip, filename);

        let server_addr = SocketAddr::new(server_ip, 69); // TFTP standard port
        let mut transfer = TFTPTransfer {
            server_addr,
            filename: filename.to_string(),
            mode: self.configuration.mode.clone(),
            block_size: self.configuration.block_size,
            total_bytes: None,
            transferred_bytes: 0,
        };

        let file_data = self.perform_tftp_download(&mut transfer).await
            .context("TFTP download failed")?;

        info!("TFTP download completed: {} bytes", file_data.len());
        Ok(file_data)
    }

    /// Perform TFTP download operation
    async fn perform_tftp_download(&self, transfer: &mut TFTPTransfer) -> AnyhowResult<Vec<u8>> {
        // Create UDP socket for TFTP communication
        let socket = UdpSocket::bind("0.0.0.0:0").await
            .context("Failed to bind TFTP client socket")?;

        // Send read request
        let read_request = TFTPPacket::ReadRequest {
            filename: transfer.filename.clone(),
            mode: self.mode_to_string(&transfer.mode),
        };

        socket.send_to(&self.serialize_tftp_packet(&read_request)?, transfer.server_addr).await
            .context("Failed to send TFTP read request")?;

        // Receive file data
        let mut file_data = Vec::new();
        let mut expected_block = 1u16;

        loop {
            // Receive data packet
            let mut buffer = [0u8; 516]; // TFTP data packet max size
            let (len, server_addr) = timeout(
                Duration::from_secs(self.configuration.timeout_seconds),
                socket.recv_from(&mut buffer)
            ).await
                .context("TFTP data receive timeout")?
                .context("Failed to receive TFTP data")?;

            let packet = self.parse_tftp_packet(&buffer[..len])
                .context("Failed to parse TFTP packet")?;

            match packet {
                TFTPPacket::Data { block, data } => {
                    if block != expected_block {
                        warn!("Received unexpected TFTP block {} (expected {})", block, expected_block);
                        continue;
                    }

                    // Send acknowledgment
                    let ack = TFTPPacket::Acknowledgment { block };
                    socket.send_to(&self.serialize_tftp_packet(&ack)?, server_addr).await
                        .context("Failed to send TFTP acknowledgment")?;

                    // Add data to file
                    file_data.extend_from_slice(&data);
                    transfer.transferred_bytes += data.len() as u64;

                    // Check if this is the last packet (less than block size)
                    if data.len() < transfer.block_size as usize {
                        info!("TFTP transfer completed (final block received)");
                        break;
                    }

                    expected_block = expected_block.wrapping_add(1);
                }

                TFTPPacket::Error { error_code, error_message } => {
                    return Err(anyhow::anyhow!(
                        "TFTP server error {}: {}", error_code, error_message
                    ));
                }

                _ => {
                    warn!("Received unexpected TFTP packet type during download");
                }
            }
        }

        Ok(file_data)
    }

    /// Convert TFTP mode to string
    fn mode_to_string(&self, mode: &TFTPMode) -> String {
        match mode {
            TFTPMode::Octet => "octet".to_string(),
            TFTPMode::Netascii => "netascii".to_string(),
        }
    }

    /// Serialize TFTP packet to bytes
    fn serialize_tftp_packet(&self, packet: &TFTPPacket) -> AnyhowResult<Vec<u8>> {
        let mut buffer = Vec::new();

        match packet {
            TFTPPacket::ReadRequest { filename, mode } => {
                buffer.extend_from_slice(&1u16.to_be_bytes()); // RRQ opcode
                buffer.extend_from_slice(filename.as_bytes());
                buffer.push(0); // Null terminator
                buffer.extend_from_slice(mode.as_bytes());
                buffer.push(0); // Null terminator
            }

            TFTPPacket::WriteRequest { filename, mode } => {
                buffer.extend_from_slice(&2u16.to_be_bytes()); // WRQ opcode
                buffer.extend_from_slice(filename.as_bytes());
                buffer.push(0);
                buffer.extend_from_slice(mode.as_bytes());
                buffer.push(0);
            }

            TFTPPacket::Data { block, data } => {
                buffer.extend_from_slice(&3u16.to_be_bytes()); // DATA opcode
                buffer.extend_from_slice(&block.to_be_bytes());
                buffer.extend_from_slice(data);
            }

            TFTPPacket::Acknowledgment { block } => {
                buffer.extend_from_slice(&4u16.to_be_bytes()); // ACK opcode
                buffer.extend_from_slice(&block.to_be_bytes());
            }

            TFTPPacket::Error { error_code, error_message } => {
                buffer.extend_from_slice(&5u16.to_be_bytes()); // ERROR opcode
                buffer.extend_from_slice(&error_code.to_be_bytes());
                buffer.extend_from_slice(error_message.as_bytes());
                buffer.push(0);
            }
        }

        Ok(buffer)
    }

    /// Parse TFTP packet from bytes
    fn parse_tftp_packet(&self, data: &[u8]) -> AnyhowResult<TFTPPacket> {
        if data.len() < 2 {
            return Err(anyhow::anyhow!("TFTP packet too short"));
        }

        let opcode = u16::from_be_bytes([data[0], data[1]]);

        match opcode {
            3 => { // DATA
                if data.len() < 4 {
                    return Err(anyhow::anyhow!("TFTP DATA packet too short"));
                }
                let block = u16::from_be_bytes([data[2], data[3]]);
                let packet_data = data[4..].to_vec();
                Ok(TFTPPacket::Data { block, data: packet_data })
            }

            4 => { // ACK
                if data.len() != 4 {
                    return Err(anyhow::anyhow!("TFTP ACK packet wrong size"));
                }
                let block = u16::from_be_bytes([data[2], data[3]]);
                Ok(TFTPPacket::Acknowledgment { block })
            }

            5 => { // ERROR
                if data.len() < 4 {
                    return Err(anyhow::anyhow!("TFTP ERROR packet too short"));
                }
                let error_code = u16::from_be_bytes([data[2], data[3]]);
                let error_message = String::from_utf8_lossy(&data[4..]).trim_end_matches('\0').to_string();
                Ok(TFTPPacket::Error { error_code, error_message })
            }

            _ => Err(anyhow::anyhow!("Unknown TFTP opcode: {}", opcode)),
        }
    }
}

impl Default for TFTPConfiguration {
    fn default() -> Self {
        Self {
            timeout_seconds: 5,
            retry_count: 3,
            block_size: 512, // TFTP standard block size
            mode: TFTPMode::Octet,
        }
    }
}

use rand;
