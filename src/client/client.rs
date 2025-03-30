use log::{debug, error, info, warn};
use std::collections::HashSet;
use std::io::{self, Error, ErrorKind, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

/// IRC Client implementation with security features
pub struct IRCClient {
	pub server: String,
	pub port: u16,
	pub token: String,
	pub stream: Option<TcpStream>,
	pub channels: HashSet<String>,
	pub current_channel: Option<String>,
	pub session_start: Instant,
}

impl IRCClient {
	/// Create a new IRC client
	pub fn new(server: &str, port: u16, token: &str) -> Self {
		IRCClient {
			server: server.to_string(),
			port,
			token: token.to_string(),
			stream: None,
			channels: HashSet::new(),
			current_channel: None,
			session_start: Instant::now(),
		}
	}

	/// Connect to the IRC server
	pub fn connect(&mut self) -> Result<(), String> {
		let addr = format!("{}:{}", self.server, self.port);

		match TcpStream::connect(addr) {
			Ok(stream) => {
				// Set read timeout to allow for periodic checking
				if let Err(e) = stream.set_read_timeout(Some(Duration::from_secs(1))) {
					return Err(format!("Failed to set read timeout: {}", e));
				}

				// Enable TCP keepalive
				if let Err(e) = stream.set_keepalive(Some(Duration::from_secs(60))) {
					warn!("Failed to set TCP keepalive: {}", e);
				}

				// Send token for authentication
				if let Err(e) = stream.write_all(self.token.as_bytes()) {
					return Err(format!("Failed to send authentication token: {}", e));
				}

				self.stream = Some(stream);
				self.session_start = Instant::now();

				info!("Connected to IRC server {}:{}", self.server, self.port);
				Ok(())
			}
			Err(e) => Err(format!("Failed to connect: {}", e)),
		}
	}

	/// Join a channel
	pub fn join_channel(&mut self, channel: &str) -> Result<(), String> {
		if let Some(stream) = &mut self.stream {
			let command = format!("JOIN {}\r\n", channel);

			if let Err(e) = stream.write_all(command.as_bytes()) {
				return Err(format!("Failed to join channel: {}", e));
			}

			// Set as current channel if this is the first one
			if self.current_channel.is_none() {
				self.current_channel = Some(channel.to_string());
			}

			self.channels.insert(channel.to_string());

			info!("Joined channel: {}", channel);
			Ok(())
		} else {
			Err("Not connected to server".to_string())
		}
	}

	/// Send a message to a channel or user
	pub fn send_message(&mut self, target: &str, message: &str) -> Result<(), String> {
		if let Some(stream) = &mut self.stream {
			// Don't allow empty messages
			if message.trim().is_empty() {
				return Ok(());
			}

			let command = format!("PRIVMSG {} :{}\r\n", target, message);

			if let Err(e) = stream.write_all(command.as_bytes()) {
				return Err(format!("Failed to send message: {}", e));
			}

			debug!("Sent message to {}: {}", target, message);
			Ok(())
		} else {
			Err("Not connected to server".to_string())
		}
	}

	/// Leave a channel
	pub fn leave_channel(&mut self, channel: &str) -> Result<(), String> {
		if let Some(stream) = &mut self.stream {
			let command = format!("PART {}\r\n", channel);

			if let Err(e) = stream.write_all(command.as_bytes()) {
				return Err(format!("Failed to leave channel: {}", e));
			}

			self.channels.remove(channel);

			// Update current channel if needed
			if let Some(current) = &self.current_channel {
				if current == channel {
					self.current_channel = self.channels.iter().next().cloned();
				}
			}

			info!("Left channel: {}", channel);
			Ok(())
		} else {
			Err("Not connected to server".to_string())
		}
	}

	/// Request secure deletion of all messages
	pub fn secure_clear(&mut self) -> Result<(), String> {
		if let Some(stream) = &mut self.stream {
			let command = "SECURECLEAR\r\n";

			if let Err(e) = stream.write_all(command.as_bytes()) {
				return Err(format!("Failed to send secure clear command: {}", e));
			}

			info!("Requested secure deletion of all messages");
			Ok(())
		} else {
			Err("Not connected to server".to_string())
		}
	}

	/// Disconnect from the server
	pub fn disconnect(&mut self) -> Result<(), String> {
		if let Some(stream) = &mut self.stream {
			// Send special command to request secure deletion of all messages
			let command = "QUIT :SECURE_DELETE\r\n";

			if let Err(e) = stream.write_all(command.as_bytes()) {
				return Err(format!("Failed to send secure quit command: {}", e));
			}

			// Wait briefly for the server to process
			std::thread::sleep(Duration::from_millis(500));

			self.stream = None;
			self.channels.clear();
			self.current_channel = None;

			info!("Disconnected from server");
			Ok(())
		} else {
			Err("Not connected to server".to_string())
		}
	}

	/// Read a message from the server
	pub fn read_message(&mut self) -> Result<String, io::Error> {
		if let Some(stream) = &mut self.stream {
			let mut buffer = [0; 1024];

			match stream.read(&mut buffer) {
				Ok(size) => {
					if size == 0 {
						return Err(Error::new(
							ErrorKind::ConnectionAborted,
							"Connection closed by server",
						));
					}

					let message = String::from_utf8_lossy(&buffer[0..size]).to_string();
					Ok(message)
				}
				Err(e) => {
					if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut {
						// Just a timeout, not an error for our purposes
						Err(Error::new(ErrorKind::WouldBlock, "No data available"))
					} else {
						Err(e)
					}
				} 
			}
		} else {
			Err(Error::new(
				ErrorKind::NotConnected,
				"Not connected to server",
			))
		}
	}

	/// Get session duration
	pub fn session_duration(&self) -> Duration {
		Instant::now().duration_since(self.session_start)
	}
}
