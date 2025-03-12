use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use log::{info, error, debug, warn};
use base64::decode as base64_decode;

use crate::server::models::{User, Channel, TokenClaims, ChatMessage};
use crate::server::session::Session;
use crate::server::crypto::Encryptor;
use crate::server::handler::{MessageHandler, ServerState};

// IRC Server Facade - The main interface to the IRC server
pub struct IRCServerFacade {
	server: Arc<Mutex<ServerState>>,
}

impl IRCServerFacade {
	pub fn new(jwt_secret: &str) -> Self {
		let server_state = ServerState {
			users: HashMap::new(),
			channels: HashMap::new(),
			jwt_secret: jwt_secret.to_string(),
			message_ttl: Duration::from_secs(3600), // 1 hour default
			session_timeout: Duration::from_secs(3600), // 1 hour default
		};
		
		let server = Arc::new(Mutex::new(server_state));
		
		// Start cleanup thread
		let cleanup_server = server.clone();
		thread::spawn(move || {
			Self::cleanup_thread(cleanup_server);
		});
		
		IRCServerFacade { server }
	}
	
	// Set the message time-to-live (how long before messages auto-delete)
	pub fn set_message_ttl(&self, hours: u64) -> Result<(), String> {
		let mut server = match self.server.lock() {
			Ok(s) => s,
			Err(_) => return Err("Failed to lock server for TTL update".to_string()),
		};
		
		server.message_ttl = Duration::from_secs(hours * 3600);
		info!("Message TTL set to {} hours", hours);
		Ok(())
	}
	
	// Set the session timeout duration
	pub fn set_session_timeout(&self, hours: u64) -> Result<(), String> {
		let mut server = match self.server.lock() {
			Ok(s) => s,
			Err(_) => return Err("Failed to lock server for timeout update".to_string()),
		};
		
		server.session_timeout = Duration::from_secs(hours * 3600);
		info!("Session timeout set to {} hours", hours);
		Ok(())
	}
	
	// Start the server
	pub fn start(&self, address: &str) -> Result<(), String> {
		let listener = match TcpListener::bind(address) {
			Ok(l) => l,
			Err(e) => return Err(format!("Failed to bind to address: {}", e)),
		};
		
		info!("IRC Server started on {}", address);
		
		let server = self.server.clone();
		
		// Handle incoming connections
		for stream in listener.incoming() {
			match stream {
				Ok(stream) => {
					let server_clone = server.clone();
					thread::spawn(move || {
						if let Err(e) = Self::handle_connection(server_clone, stream) {
							error!("Connection handling error: {}", e);
						}
					});
				}
				Err(e) => {
					warn!("Connection failed: {}", e);
				}
			}
		}
		
		Ok(())
	}
	
	// Handle client connection
	fn handle_connection(server: Arc<Mutex<ServerState>>, mut stream: TcpStream) -> Result<(), String> {
		// Set read timeout
		if let Err(e) = stream.set_read_timeout(Some(Duration::from_secs(300))) {
			return Err(format!("Failed to set read timeout: {}", e));
		}
		
		// Set TCP keepalive to detect dead connections
		if let Err(e) = stream.set_keepalive(Some(Duration::from_secs(60))) {
			warn!("Failed to set TCP keepalive: {}", e);
		}
		
		// Read authentication token
		let mut buffer = [0; 4096]; // Larger buffer for tokens with images
		let mut token = String::new();
		
		match stream.read(&mut buffer) {
			Ok(size) => {
				if size > 0 {
					token = String::from_utf8_lossy(&buffer[0..size]).to_string();
					token = token.trim().to_string();
				} else {
					return Err("Empty read from socket".to_string());
				}
			}
			Err(e) => {
				return Err(format!("Failed to read from socket: {}", e));
			}
		}
		
		// Validate token and create user
		let user_id = {
			let mut server_lock = match server.lock() {
				Ok(s) => s,
				Err(_) => return Err("Failed to lock server for token validation".to_string()),
			};
			
			// Validate token
			let validation = Validation::new(Algorithm::HS256);
			let key = DecodingKey::from_secret(server_lock.jwt_secret.as_bytes());
			
			let token_data = match jsonwebtoken::decode::<TokenClaims>(&token, &key, &validation) {
				Ok(t) => t,
				Err(e) => {
					let _ = stream.write_all(format!("ERROR :Authentication failed: {}\r\n", e).as_bytes());
					return Err(format!("Token validation failed: {}", e));
				}
			};
			
			let claims = token_data.claims;
			
			// Extract profile picture
			let profile_pic = match base64_decode(&claims.profile_pic) {
				Ok(data) => data,
				Err(e) => {
					let _ = stream.write_all(b"ERROR :Invalid profile picture data\r\n");
					return Err(format!("Failed to decode profile picture: {}", e));
				}
			};
			
			// Generate secure random session ID
			let session_id: String = thread_rng()
				.sample_iter(&Alphanumeric)
				.take(32)
				.map(char::from)
				.collect();
			
			// Generate encryption key
			let encryption_key = match Encryptor::generate_random_key() {
				Ok(key) => key,
				Err(e) => {
					let _ = stream.write_all(b"ERROR :Failed to generate encryption key\r\n");
					return Err(e);
				}
			};
			
			// Create session
			let session = Session::new(session_id, claims.sub.clone(), encryption_key);
			
			// Create user
			let user = User {
				id: claims.sub.clone(),
				username: claims.username.clone(),
				profile_pic,
				channels: HashSet::new(),
				stream: Some(Arc::new(Mutex::new(stream.try_clone().unwrap()))),
				session: Some(session),
				messages: VecDeque::new(),
			};
			
			// Add user to server
			let user_id = claims.sub.clone();
			server_lock.users.insert(user_id.clone(), user);
			
			info!("User authenticated: {} ({})", claims.username, user_id);
			
			user_id
		};
		
		// Send welcome message
		{
			let server_lock = match server.lock() {
				Ok(s) => s,
				Err(_) => return Err("Failed to lock server for welcome message".to_string()),
			};
			
			if let Some(user) = server_lock.users.get(&user_id) {
				if let Some(stream) = &user.stream {
					let welcome_message = format!(
						":{} 001 {} :Welcome to the Secure IRC Server, {}\r\n", 
						"server", 
						user_id, 
						user.username
					);
					
					let security_notice = format!(
						":{} NOTICE {} :SECURITY: All messages will be deleted after {} minutes\r\n",
						"server",
						user_id,
						server_lock.message_ttl.as_secs() / 60
					);
					
					if let Ok(mut s) = stream.lock() {
						let _ = s.write_all(welcome_message.as_bytes());
						let _ = s.write_all(security_notice.as_bytes());
					}
				}
			}
		}
		
		// Get a new copy of the stream for the message handler
		let stream_arc = {
			let server_lock = match server.lock() {
				Ok(s) => s,
				Err(_) => return Err("Failed to lock server for stream access".to_string()),
			};
			
			match server_lock.users.get(&user_id) {
				Some(user) => match &user.stream {
					Some(s) => s.clone(),
					None => return Err("User has no stream".to_string()),
				},
				None => return Err("User not found".to_string()),
			}
		};
		
		// Set up message handler
		let mut handler = MessageHandler::new(user_id.clone(), stream_arc.clone(), server.clone());
		
		// Main client loop
		loop {
			let mut buffer = [0; 1024];
			let mut command = String::new();
			
			// Read command
			let size = match stream.read(&mut buffer) {
				Ok(s) => {
					if s == 0 {
						debug!("Connection closed by client");
						break;  // Connection closed
					}
					s
				}
				Err(e) => {
					warn!("Read error: {}", e);
					break;
				}
			};
			
			command = String::from_utf8_lossy(&buffer[0..size]).trim().to_string();
			
			if command.is_empty() {
				continue;
			}
			
			debug!("Received command: {}", command);
			
			// Handle command
			if let Err(e) = handler.handle_message(&command) {
				warn!("Error handling message: {}", e);
				
				// Try to send error to client
				let err_msg = format!("ERROR :{}\r\n", e);
				if let Ok(mut s) = stream_arc.lock() {
					let _ = s.write_all(err_msg.as_bytes());
				}
				
				// If it's a critical error, disconnect
				if e.contains("authentication") || e.contains("token") {
					break;
				}
			}
			
			// Check if command was QUIT
			if command.starts_with("QUIT") {
				debug!("User quit: {}", user_id);
				break;
			}
		}
		
		// Disconnect user and clean up
		{
			let mut server_lock = match server.lock() {
				Ok(s) => s,
				Err(_) => return Err("Failed to lock server for disconnection".to_string()),
			};
			
			// Get username for logging
			let username = server_lock.users.get(&user_id)
				.map(|u| u.username.clone())
				.unwrap_or_else(|| "Unknown".to_string());
			
			info!("User disconnected: {} ({})", username, user_id);
			
			// Perform secure deletion of user data
			if let Some(user) = server_lock.users.get_mut(&user_id) {
				// Clear messages
				user.messages.clear();
				
				// Leave all channels
				for channel_name in &user.channels.clone() {
					if let Some(channel) = server_lock.channels.get_mut(channel_name) {
						channel.users.remove(&user_id);
						
						// Notify other users
						let leave_message = format!("* {} has disconnected", username);
						for other_id in &channel.users {
							if other_id != &user_id {
								if let Some(other) = server_lock.users.get(other_id) {
									if let Some(other_stream) = &other.stream {
										let msg = format!(":{} PRIVMSG {} :{}\r\n", 
														channel_name, other.username, leave_message);
										if let Ok(mut s) = other_stream.lock() {
											let _ = s.write_all(msg.as_bytes());
										}
									}
								}
							}
						}
					}
				}
			}
			
			// Remove user from server
			server_lock.users.remove(&user_id);
		}
		
		Ok(())
	}
	
	// Cleanup thread to periodically remove expired messages and sessions
	fn cleanup_thread(server: Arc<Mutex<ServerState>>) {
		loop {
			thread::sleep(Duration::from_secs(60)); // Check every minute
			
			let mut server_lock = match server.lock() {
				Ok(s) => s,
				Err(_) => {
					error!("Failed to lock server for cleanup");
					continue;
				}
			};
			
			let now = Instant::now();
			let message_ttl = server_lock.message_ttl;
			let session_timeout = server_lock.session_timeout;
			
			// Clean up expired messages in channels
			for (channel_name, channel) in &mut server_lock.channels {
				let before_count = channel.messages.len();
				channel.messages.retain(|msg| {
					now.duration_since(msg.timestamp) < message_ttl
				});
				let removed = before_count - channel.messages.len();
				
				if removed > 0 {
					debug!("Removed {} expired messages from channel {}", removed, channel_name);
					
					// Notify users in channel about message expiration
					let notice = format!("NOTICE :SECURITY: {} messages have been automatically deleted", removed);
					for user_id in &channel.users {
						if let Some(user) = server_lock.users.get(user_id) {
							if let Some(stream) = &user.stream {
								if let Ok(mut s) = stream.lock() {
									let _ = s.write_all(notice.as_bytes());
								}
							}
						}
					}
				}
			}
			
			// Clean up expired messages in users' private message history
			for (user_id, user) in &mut server_lock.users {
				let before_count = user.messages.len();
				user.messages.retain(|msg| {
					now.duration_since(msg.timestamp) < message_ttl
				});
				let removed = before_count - user.messages.len();
				
				if removed > 0 {
					debug!("Removed {} expired private messages for user {}", removed, user_id);
					
					// Notify user about message expiration
					if let Some(stream) = &user.stream {
						let notice = format!("NOTICE :SECURITY: {} private messages have been automatically deleted\r\n", removed);
						if let Ok(mut s) = stream.lock() {
							let _ = s.write_all(notice.as_bytes());
						}
					}
				}
			}
			
			// Find inactive sessions to disconnect
			let mut to_disconnect = Vec::new();
			for (user_id, user) in &server_lock.users {
				if let Some(session) = &user.session {
					if now.duration_since(session.last_activity) > session_timeout {
						to_disconnect.push(user_id.clone());
					}
				}
			}
			
			// Disconnect inactive users
			for user_id in to_disconnect {
				info!("Auto-disconnecting inactive user: {}", user_id);
				
				// Send disconnect notice to user
				if let Some(user) = server_lock.users.get(&user_id) {
					if let Some(stream) = &user.stream {
						let notice = "NOTICE :SECURITY: You have been disconnected due to inactivity. All messages have been deleted.\r\n";
						if let Ok(mut s) = stream.lock() {
							let _ = s.write_all(notice.as_bytes());
						}
					}
				}
				
				// Perform user disconnection and cleanup
				Self::disconnect_user(&mut server_lock, &user_id);
			}
			
			// Clean up empty channels
			server_lock.channels.retain(|name, channel| {
				if channel.users.is_empty() && now.duration_since(channel.last_activity) > Duration::from_secs(86400) {
					debug!("Removing empty channel {}", name);
					false
				} else {
					true
				}
			});
		}
	}
	
	// Disconnect a user and clean up their data
	fn disconnect_user(server: &mut ServerState, user_id: &str) {
		let username = server.users.get(user_id)
			.map(|u| u.username.clone())
			.unwrap_or_else(|| "Unknown".to_string());
		
		// Remove user from all channels
		if let Some(user) = server.users.get(user_id) {
			for channel_name in &user.channels.clone() {
				if let Some(channel) = server.channels.get_mut(channel_name) {
					channel.users.remove(user_id);
					
					// Notify other users
					let leave_message = format!("* {} has been disconnected due to inactivity", username);
					for other_id in &channel.users {
						if other_id != user_id {
							if let Some(other) = server.users.get(other_id) {
								if let Some(other_stream) = &other.stream {
									let msg = format!(":{} PRIVMSG {} :{}\r\n", 
													channel_name, other.username, leave_message);
									if let Ok(mut s) = other_stream.lock() {
										let _ = s.write_all(msg.as_bytes());
									}
								}
							}
						}
					}
				}
			}
		}
		
		// Remove user from server
		server.users.remove(user_id);
		info!("User disconnected and data cleared: {}", username);
	}
}