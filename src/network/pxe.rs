// =============================================================================
// NETWORK PXE MODULE - cibios/src/network/pxe.rs
// =============================================================================

use anyhow::{Context, Result as AnyhowResult};
use serde::{Deserialize, Serialize};
use log::{debug, error, info, warn};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket as StdUdpSocket};
use std::time::Duration;
use tokio::time::timeout;
use super::{NetworkAdapter, NetworkVerification};

/// PXE (Preboot Execution Environment) client for network booting
#[derive(Debug)]
pub struct PXEClient {
    network_adapter: Arc<NetworkAdapter>,
    configuration: PXEConfiguration,
}

/// PXE configuration for network boot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PXEConfiguration {
    pub dhcp_server: Option<IpAddr>,
    pub boot_server: Option<IpAddr>,
    pub boot_filename: Option<String>,
    pub timeout_seconds: u64,
    pub retry_count: u32,
}

/// PXE boot result containing OS image
#[derive(Debug)]
pub struct PXEBootResult {
    pub os_image: Vec<u8>,
    pub boot_server: IpAddr,
    pub boot_filename: String,
}

/// DHCP packet structure for PXE
#[derive(Debug, Clone)]
struct DHCPPacket {
    op: u8,        // Message op code
    htype: u8,     // Hardware address type
    hlen: u8,      // Hardware address length
    hops: u8,      // Hops
    xid: u32,      // Transaction ID
    secs: u16,     // Seconds elapsed
    flags: u16,    // Flags
    ciaddr: [u8; 4],  // Client IP address
    yiaddr: [u8; 4],  // Your IP address
    siaddr: [u8; 4],  // Server IP address
    giaddr: [u8; 4],  // Gateway IP address
    chaddr: [u8; 16], // Client hardware address
    sname: [u8; 64],  // Server name
    file: [u8; 128],  // Boot file name
    options: Vec<u8>, // DHCP options
}

impl PXEClient {
    /// Initialize PXE client
    pub async fn initialize(network_adapter: &Arc<NetworkAdapter>) -> AnyhowResult<Self> {
        info!("Initializing PXE client");

        let configuration = PXEConfiguration {
            dhcp_server: None,
            boot_server: None,
            boot_filename: None,
            timeout_seconds: 30,
            retry_count: 3,
        };

        Ok(Self {
            network_adapter: network_adapter.clone(),
            configuration,
        })
    }

    /// Perform complete PXE boot sequence
    pub async fn perform_pxe_boot(&self) -> AnyhowResult<PXEBootResult> {
        info!("Starting PXE boot sequence");

        // Step 1: DHCP Discovery to find DHCP server
        let dhcp_offer = self.dhcp_discovery().await
            .context("DHCP discovery failed")?;

        // Step 2: DHCP Request to obtain IP configuration
        let dhcp_ack = self.dhcp_request(&dhcp_offer).await
            .context("DHCP request failed")?;

        // Step 3: Contact boot server specified in DHCP response
        let boot_server = self.extract_boot_server(&dhcp_ack)?;
        let boot_filename = self.extract_boot_filename(&dhcp_ack)?;

        // Step 4: Download OS image from boot server
        let os_image = self.download_boot_image(boot_server, &boot_filename).await
            .context("Boot image download failed")?;

        info!("PXE boot sequence completed successfully");

        Ok(PXEBootResult {
            os_image,
            boot_server,
            boot_filename,
        })
    }

    /// DHCP Discovery phase of PXE boot
    async fn dhcp_discovery(&self) -> AnyhowResult<DHCPPacket> {
        info!("Performing DHCP discovery for PXE boot");

        // Create DHCP discovery packet
        let mut discovery_packet = self.create_dhcp_discover_packet()?;
        
        // Add PXE-specific options
        self.add_pxe_options(&mut discovery_packet);

        // Broadcast DHCP discovery
        let socket = self.create_dhcp_socket().await?;
        let broadcast_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::BROADCAST), 67);

        socket.send_to(&self.serialize_dhcp_packet(&discovery_packet)?, broadcast_addr).await
            .context("Failed to send DHCP discovery")?;

        // Wait for DHCP offer
        let mut buffer = [0u8; 1024];
        let (len, _) = timeout(Duration::from_secs(self.configuration.timeout_seconds), 
                              socket.recv_from(&mut buffer)).await
            .context("DHCP discovery timeout")?
            .context("Failed to receive DHCP offer")?;

        let offer_packet = self.parse_dhcp_packet(&buffer[..len])
            .context("Failed to parse DHCP offer")?;

        info!("Received DHCP offer for PXE boot");
        Ok(offer_packet)
    }

    /// DHCP Request phase of PXE boot
    async fn dhcp_request(&self, offer: &DHCPPacket) -> AnyhowResult<DHCPPacket> {
        info!("Sending DHCP request for PXE boot");

        // Create DHCP request packet based on offer
        let mut request_packet = self.create_dhcp_request_packet(offer)?;
        
        // Add PXE-specific options
        self.add_pxe_options(&mut request_packet);

        // Send DHCP request
        let socket = self.create_dhcp_socket().await?;
        let server_addr = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::from(offer.siaddr)), 
            67
        );

        socket.send_to(&self.serialize_dhcp_packet(&request_packet)?, server_addr).await
            .context("Failed to send DHCP request")?;

        // Wait for DHCP ACK
        let mut buffer = [0u8; 1024];
        let (len, _) = timeout(Duration::from_secs(self.configuration.timeout_seconds),
                              socket.recv_from(&mut buffer)).await
            .context("DHCP request timeout")?
            .context("Failed to receive DHCP ACK")?;

        let ack_packet = self.parse_dhcp_packet(&buffer[..len])
            .context("Failed to parse DHCP ACK")?;

        info!("Received DHCP ACK for PXE boot");
        Ok(ack_packet)
    }

    /// Download boot image from PXE boot server
    async fn download_boot_image(&self, server_ip: IpAddr, filename: &str) -> AnyhowResult<Vec<u8>> {
        info!("Downloading boot image from {}: {}", server_ip, filename);

        // Use TFTP to download the boot image
        let tftp_client = super::tftp::TFTPClient::initialize(&self.network_adapter).await?;
        tftp_client.download_file(server_ip, filename).await
    }

    /// Create DHCP socket for PXE communication
    async fn create_dhcp_socket(&self) -> AnyhowResult<tokio::net::UdpSocket> {
        let socket = tokio::net::UdpSocket::bind("0.0.0.0:68").await
            .context("Failed to bind DHCP client socket")?;
        
        socket.set_broadcast(true)
            .context("Failed to enable broadcast on DHCP socket")?;

        Ok(socket)
    }

    /// Create DHCP discover packet for PXE boot
    fn create_dhcp_discover_packet(&self) -> AnyhowResult<DHCPPacket> {
        let mut packet = DHCPPacket {
            op: 1,      // BOOTREQUEST
            htype: 1,   // Ethernet
            hlen: 6,    // MAC address length
            hops: 0,
            xid: rand::random(),
            secs: 0,
            flags: 0x8000, // Broadcast flag
            ciaddr: [0; 4],
            yiaddr: [0; 4],
            siaddr: [0; 4],
            giaddr: [0; 4],
            chaddr: {
                let mut addr = [0u8; 16];
                addr[..6].copy_from_slice(&self.network_adapter.mac_address);
                addr
            },
            sname: [0; 64],
            file: [0; 128],
            options: Vec::new(),
        };

        // Add DHCP message type option (DISCOVER = 1)
        self.add_dhcp_option(&mut packet, 53, &[1]);

        Ok(packet)
    }

    /// Create DHCP request packet based on offer
    fn create_dhcp_request_packet(&self, offer: &DHCPPacket) -> AnyhowResult<DHCPPacket> {
        let mut packet = offer.clone();
        packet.op = 1; // BOOTREQUEST

        // Add DHCP message type option (REQUEST = 3)
        packet.options.clear();
        self.add_dhcp_option(&mut packet, 53, &[3]);
        
        // Add requested IP address option
        self.add_dhcp_option(&mut packet, 50, &offer.yiaddr);

        Ok(packet)
    }

    /// Add PXE-specific DHCP options
    fn add_pxe_options(&self, packet: &mut DHCPPacket) {
        // Add PXE vendor class identifier
        self.add_dhcp_option(packet, 60, b"PXEClient");
        
        // Add PXE client identifier
        let mut client_id = Vec::new();
        client_id.extend_from_slice(&[1]); // Type: Ethernet
        client_id.extend_from_slice(&self.network_adapter.mac_address);
        self.add_dhcp_option(packet, 61, &client_id);
    }

    /// Add DHCP option to packet
    fn add_dhcp_option(&self, packet: &mut DHCPPacket, option_type: u8, data: &[u8]) {
        packet.options.push(option_type);
        packet.options.push(data.len() as u8);
        packet.options.extend_from_slice(data);
    }

    /// Serialize DHCP packet to bytes
    fn serialize_dhcp_packet(&self, packet: &DHCPPacket) -> AnyhowResult<Vec<u8>> {
        let mut buffer = Vec::with_capacity(576); // Standard DHCP packet size

        buffer.push(packet.op);
        buffer.push(packet.htype);
        buffer.push(packet.hlen);
        buffer.push(packet.hops);
        buffer.extend_from_slice(&packet.xid.to_be_bytes());
        buffer.extend_from_slice(&packet.secs.to_be_bytes());
        buffer.extend_from_slice(&packet.flags.to_be_bytes());
        buffer.extend_from_slice(&packet.ciaddr);
        buffer.extend_from_slice(&packet.yiaddr);
        buffer.extend_from_slice(&packet.siaddr);
        buffer.extend_from_slice(&packet.giaddr);
        buffer.extend_from_slice(&packet.chaddr);
        buffer.extend_from_slice(&packet.sname);
        buffer.extend_from_slice(&packet.file);

        // DHCP magic cookie
        buffer.extend_from_slice(&[0x63, 0x82, 0x53, 0x63]);
        
        // Options
        buffer.extend_from_slice(&packet.options);
        
        // End option
        buffer.push(255);

        Ok(buffer)
    }

    /// Parse DHCP packet from bytes
    fn parse_dhcp_packet(&self, data: &[u8]) -> AnyhowResult<DHCPPacket> {
        if data.len() < 240 {
            return Err(anyhow::anyhow!("DHCP packet too short"));
        }

        let packet = DHCPPacket {
            op: data[0],
            htype: data[1],
            hlen: data[2],
            hops: data[3],
            xid: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
            secs: u16::from_be_bytes([data[8], data[9]]),
            flags: u16::from_be_bytes([data[10], data[11]]),
            ciaddr: [data[12], data[13], data[14], data[15]],
            yiaddr: [data[16], data[17], data[18], data[19]],
            siaddr: [data[20], data[21], data[22], data[23]],
            giaddr: [data[24], data[25], data[26], data[27]],
            chaddr: {
                let mut addr = [0u8; 16];
                addr.copy_from_slice(&data[28..44]);
                addr
            },
            sname: {
                let mut name = [0u8; 64];
                name.copy_from_slice(&data[44..108]);
                name
            },
            file: {
                let mut file = [0u8; 128];
                file.copy_from_slice(&data[108..236]);
                file
            },
            options: if data.len() > 240 { data[240..].to_vec() } else { Vec::new() },
        };

        Ok(packet)
    }

    /// Extract boot server IP from DHCP packet
    fn extract_boot_server(&self, packet: &DHCPPacket) -> AnyhowResult<IpAddr> {
        // Try to get boot server from DHCP options first
        if let Some(server_ip) = self.find_dhcp_option(packet, 66) {
            if server_ip.len() == 4 {
                return Ok(IpAddr::V4(Ipv4Addr::new(
                    server_ip[0], server_ip[1], server_ip[2], server_ip[3]
                )));
            }
        }

        // Fall back to siaddr field
        if packet.siaddr != [0; 4] {
            return Ok(IpAddr::V4(Ipv4Addr::new(
                packet.siaddr[0], packet.siaddr[1], packet.siaddr[2], packet.siaddr[3]
            )));
        }

        Err(anyhow::anyhow!("No boot server specified in DHCP response"))
    }

    /// Extract boot filename from DHCP packet
    fn extract_boot_filename(&self, packet: &DHCPPacket) -> AnyhowResult<String> {
        // Try to get filename from DHCP options first
        if let Some(filename_bytes) = self.find_dhcp_option(packet, 67) {
            if let Ok(filename) = String::from_utf8(filename_bytes.to_vec()) {
                return Ok(filename);
            }
        }

        // Fall back to file field
        let file_bytes = &packet.file[..];
        if let Some(null_pos) = file_bytes.iter().position(|&b| b == 0) {
            if null_pos > 0 {
                return String::from_utf8(file_bytes[..null_pos].to_vec())
                    .context("Invalid filename in DHCP file field");
            }
        }

        Err(anyhow::anyhow!("No boot filename specified in DHCP response"))
    }

    /// Find specific DHCP option in packet
    fn find_dhcp_option(&self, packet: &DHCPPacket, option_type: u8) -> Option<&[u8]> {
        let mut i = 0;
        while i < packet.options.len() {
            if packet.options[i] == 255 { // End option
                break;
            }
            
            if packet.options[i] == option_type {
                let length = packet.options[i + 1] as usize;
                if i + 2 + length <= packet.options.len() {
                    return Some(&packet.options[i + 2..i + 2 + length]);
                }
            }
            
            if i + 1 < packet.options.len() {
                i += 2 + packet.options[i + 1] as usize;
            } else {
                break;
            }
        }
        
        None
    }
}

impl Default for PXEConfiguration {
    fn default() -> Self {
        Self {
            dhcp_server: None,
            boot_server: None,
            boot_filename: None,
            timeout_seconds: 30,
            retry_count: 3,
        }
    }
}
