use log::{debug, error, info, warn};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::server::crypto::Encryptor;
use crate::server::models::{Channel, ChatMessage, MessageType, TokenClaims, User};
use crate::server::session::Session;

pub struct MessageHandler {
	user_id: String,
	stream: Arc<Mutex<TcpStream>>,
	server: Arc<Mutex<ServerState>>,
}

pub struct ServerState {
	pub users: std::collections::HashMap<String, User>,
	pub channels: std::collections::HashMap<String, Channel>,
	pub jwt_secret: String,
	pub message_ttl: Duration,
	pub session_timeout: Duration,
}

impl MessageHandler {
	pub fn new(
		user_id: String,
		stream: Arc<Mutex<TcpStream>>,
		server: Arc<Mutex<ServerState>>,
	) -> Self {
		MessageHandler {
			user_id,
			stream,
			server,
		}
	}

	pub fn handle_message(&mut self, command: &str) -> Result<(), String> {
		let parts: Vec<&str> = command.splitn(3, ' ').collect();
		if parts.is_empty() {
			return Ok(());
		}

		// Update user's last activity time
		{
			let mut server = self.server.lock().unwrap();
			if let Some(user) = server.users.get_mut(&self.user_id) {
				if let Some(session) = &mut user.session {
					session.update_activity();
				}
			}
		}

		match parts[0].to_uppercase().as_str() {
			"JOIN" => self.handle_join(parts),
			"PART" => self.handle_leave(parts),
			"PRIVMSG" => self.handle_privmsg(parts),
			"LIST" => self.handle_list(),
			"WHO" => self.handle_who(parts),
			"QUIT" => self.handle_quit(parts),
			"SECURECLEAR" => self.handle_secure_clear(),
			_ => self.handle_unknown(parts[0]),
		}
	}

	fn handle_join(&mut self, parts: Vec<&str>) -> Result<(), String> {
		if parts.len() < 2 {
			return self.send_error("Not enough parameters for JOIN");
		}

		let channel = parts[1];

		let mut server = self.server.lock().unwrap();

		// Create channel if it doesn't exist
		if !server.channels.contains_key(channel) {
			server.channels.insert(
				channel.to_string(),
				Channel {
					name: channel.to_string(),
					topic: String::new(),
					users: std::collections::HashSet::new(),
					messages: std::collections::VecDeque::new(),
					created_at: Instant::now(),
					last_activity: Instant::now(),
				},
			);
		}

		// Add user to channel
		if let Some(ch) = server.channels.get_mut(channel) {
			ch.users.insert(self.user_id.clone());
			ch.last_activity = Instant::now();
		}

		// Add channel to user's channels
		if let Some(user) = server.users.get_mut(&self.user_id) {
			user.channels.insert(channel.to_string());

			// Send join confirmation to user
			if let Some(stream) = &user.stream {
				let _ = stream
					.lock()
					.unwrap()
					.write_all(format!(":{} JOIN {}\r\n", self.user_id, channel).as_bytes());
			}
		}

		// Get username for broadcast
		let username = match server.users.get(&self.user_id) {
			Some(user) => user.username.clone(),
			None => return Err("User not found".to_string()),
		};

		// Broadcast join message to channel
		let join_message = format!("* {} has joined {}", username, channel);
		Self::broadcast_to_channel(&mut server, channel, &join_message, Some(&self.user_id));

		// Store join message in channel history
		Self::store_channel_message(&mut server, channel, "SYSTEM", &join_message);

		Ok(())
	}

	fn handle_leave(&mut self, parts: Vec<&str>) -> Result<(), String> {
		if parts.len() < 2 {
			return self.send_error("Not enough parameters for PART");
		}

		let channel = parts[1];

		let mut server = self.server.lock().unwrap();

		// Get username for broadcast
		let username = match server.users.get(&self.user_id) {
			Some(user) => user.username.clone(),
			None => return Err("User not found".to_string()),
		};

		// Remove user from channel
		if let Some(ch) = server.channels.get_mut(channel) {
			ch.users.remove(&self.user_id);
			ch.last_activity = Instant::now();

			// Remove empty channels
			if ch.users.is_empty() {
				server.channels.remove(channel);
			} else {
				// Broadcast leave message to remaining users
				let leave_message = format!("* {} has left {}", username, channel);
				Self::broadcast_to_channel(&mut server, channel, &leave_message, None);

				// Store leave message in channel history
				Self::store_channel_message(&mut server, channel, "SYSTEM", &leave_message);
			}
		}

		// Remove channel from user's list
		if let Some(user) = server.users.get_mut(&self.user_id) {
			user.channels.remove(channel);

			// Send part confirmation to user
			if let Some(stream) = &user.stream {
				let _ = stream
					.lock()
					.unwrap()
					.write_all(format!(":{} PART {}\r\n", self.user_id, channel).as_bytes());
			}
		}

		Ok(())
	}

	fn handle_privmsg(&mut self, parts: Vec<&str>) -> Result<(), String> {
		if parts.len() < 3 {
			return self.send_error("Not enough parameters for PRIVMSG");
		}

		let target = parts[1];
		let message = parts[2];

		let mut server = self.server.lock().unwrap();

		// Get sender info
		let sender = match server.users.get(&self.user_id) {
			Some(user) => user,
			None => return Err("Sender not found".to_string()),
		};

		// Update sender's session activity
		if let Some(user) = server.users.get_mut(&self.user_id) {
			if let Some(session) = &mut user.session {
				session.update_activity();
			}
		}

		// Check if target is a channel or user
		if target.starts_with('#') {
			// Channel message
			// Check if user is in channel
			if !sender.channels.contains(target) {
				return self.send_error(&format!("You are not in channel {}", target));
			}

			// Format the message
			let formatted_message = format!("<{}> {}", sender.username, message);

			// Store in channel history
			Self::store_channel_message(&mut server, target, &sender.username, message);

			// Broadcast message
			Self::broadcast_to_channel(
				&mut server,
				target,
				&formatted_message,
				Some(&self.user_id),
			);
		} else {
			// Private message
			// Find recipient by username
			let recipient_id = Self::find_user_by_username(&server, target)
				.ok_or_else(|| format!("User {} not found", target))?;

			// Store message in sender's and recipient's history
			Self::store_private_message(&mut server, &self.user_id, &recipient_id, message);

			// Send message to recipient
			if let Some(recipient) = server.users.get(&recipient_id) {
				if let Some(stream) = &recipient.stream {
					let pm_message = format!("PRIVMSG {} :{}\r\n", sender.username, message);
					if let Err(e) = stream.lock().unwrap().write_all(pm_message.as_bytes()) {
						return Err(format!("Failed to send message: {}", e));
					}
				}
			}
		}

		Ok(())
	}

	fn handle_list(&mut self) -> Result<(), String> {
		let server = self.server.lock().unwrap();

		// Send list of channels
		let mut channel_list = String::new();
		for (name, channel) in &server.channels {
			channel_list.push_str(&format!(
				":{} 322 {} {} {} :{}\r\n",
				"server",
				self.user_id,
				name,
				channel.users.len(),
				channel.topic
			));
		}

		channel_list.push_str(&format!(
			":{} 323 {} :End of LIST\r\n",
			"server", self.user_id
		));

		if let Some(user) = server.users.get(&self.user_id) {
			if let Some(stream) = &user.stream {
				if let Err(e) = stream.lock().unwrap().write_all(channel_list.as_bytes()) {
					return Err(format!("Failed to send channel list: {}", e));
				}
			}
		}

		Ok(())
	}

	fn handle_who(&mut self, parts: Vec<&str>) -> Result<(), String> {
		if parts.len() < 2 {
			return self.send_error("Not enough parameters for WHO");
		}

		let channel = parts[1];
		let server = self.server.lock().unwrap();

		// Check if channel exists
		let ch = match server.channels.get(channel) {
			Some(c) => c,
			None => return self.send_error(&format!("Channel {} not found", channel)),
		};

		// Send list of users in channel
		let mut who_list = String::new();
		for user_id in &ch.users {
			if let Some(user) = server.users.get(user_id) {
				who_list.push_str(&format!(
					":{} 352 {} {} {} {} {} {} H :0 {}\r\n",
					"server",
					self.user_id,
					channel,
					user.username,
					"hostname",
					"server",
					user.username,
					user.username
				));
			}
		}

		who_list.push_str(&format!(
			":{} 315 {} {} :End of WHO list\r\n",
			"server", self.user_id, channel
		));

		if let Some(user) = server.users.get(&self.user_id) {
			if let Some(stream) = &user.stream {
				if let Err(e) = stream.lock().unwrap().write_all(who_list.as_bytes()) {
					return Err(format!("Failed to send WHO list: {}", e));
				}
			}
		}

		Ok(())
	}

	fn handle_quit(&mut self, parts: Vec<&str>) -> Result<(), String> {
		let secure_delete = parts.len() > 1 && parts[1].contains("SECURE_DELETE");

		let mut server = self.server.lock().unwrap();

		if secure_delete {
			info!("Secure deletion requested for user: {}", self.user_id);

			// Perform secure deletion
			if let Some(user) = server.users.get_mut(&self.user_id) {
				// Clear and securely delete all messages
				for mut msg in user.messages.drain(..) {
					Self::secure_delete_message(&mut msg);
				}

				// Remove from all channels and clear their messages
				for channel_name in &user.channels.clone() {
					if let Some(channel) = server.channels.get_mut(channel_name) {
						channel.messages.retain(|msg| msg.sender != user.username);
					}
				}
			}
		}

		// Disconnect user
		Self::disconnect_user(&mut server, &self.user_id);

		Ok(())
	}

	fn handle_secure_clear(&mut self) -> Result<(), String> {
		let mut server = self.server.lock().unwrap();

		// Clear all messages for this user
		if let Some(user) = server.users.get_mut(&self.user_id) {
			for mut msg in user.messages.drain(..) {
				Self::secure_delete_message(&mut msg);
			}

			// Notify the user
			if let Some(stream) = &user.stream {
				let _ = stream
					.lock()
					.unwrap()
					.write_all(b"NOTICE :All your messages have been securely deleted\r\n");
			}
		}

		Ok(())
	}

	fn handle_unknown(&mut self, command: &str) -> Result<(), String> {
		self.send_error(&format!("Unknown command: {}", command))
	}

	fn send_error(&self, message: &str) -> Result<(), String> {
		let server = self.server.lock().unwrap();

		if let Some(user) = server.users.get(&self.user_id) {
			if let Some(stream) = &user.stream {
				if let Err(e) = stream
					.lock()
					.unwrap()
					.write_all(format!("ERROR :{}\r\n", message).as_bytes())
				{
					return Err(format!("Failed to send error message: {}", e));
				}
			}
		}

		Ok(())
	}

	// Helper methods

	fn broadcast_to_channel(
		server: &mut ServerState,
		channel_name: &str,
		message: &str,
		exclude_user: Option<&str>,
	) {
		let channel = match server.channels.get(channel_name) {
			Some(c) => c,
			None => return,
		};

		for user_id in &channel.users {
			if let Some(excluded) = exclude_user {
				if user_id == excluded {
					continue;
				}
			}

			if let Some(user) = server.users.get(user_id) {
				if let Some(stream) = &user.stream {
					let message = format!(
						":{} PRIVMSG {} :{}\r\n",
						channel_name, user.username, message
					);
					if let Ok(mut stream) = stream.lock() {
						let _ = stream.write_all(message.as_bytes());
					}
				}
			}
		}
	}

	fn store_channel_message(
		server: &mut ServerState,
		channel_name: &str,
		sender: &str,
		content: &str,
	) {
		if let Some(channel) = server.channels.get_mut(channel_name) {
			// Encrypt the message content
			let encrypted = Vec::new(); // In a real implementation, this would be encrypted

			let message = ChatMessage {
				sender: sender.to_string(),
				content: content.to_string(),
				timestamp: Instant::now(),
				encrypted,
			};

			channel.messages.push_back(message);
			channel.last_activity = Instant::now();

			// Limit message history
			while channel.messages.len() > 100 {
				channel.messages.pop_front();
			}
		}
	}

	fn store_private_message(
		server: &mut ServerState,
		sender_id: &str,
		recipient_id: &str,
		content: &str,
	) {
		// Encrypt the message
		let encrypted = Vec::new(); // In a real implementation, this would be encrypted

		let timestamp = Instant::now();
		let sender_username = server
			.users
			.get(sender_id)
			.map(|u| u.username.clone())
			.unwrap_or_else(|| "Unknown".to_string());

		// Create message records
		let msg = ChatMessage {
			sender: sender_username.clone(),
			content: content.to_string(),
			timestamp,
			encrypted: encrypted.clone(),
		};

		// Store in sender's history
		if let Some(user) = server.users.get_mut(sender_id) {
			user.messages.push_back(msg.clone());

			// Limit history size
			while user.messages.len() > 100 {
				user.messages.pop_front();
			}
		}

		// Store in recipient's history
		if let Some(user) = server.users.get_mut(recipient_id) {
			user.messages.push_back(msg);

			// Limit history size
			while user.messages.len() > 100 {
				user.messages.pop_front();
			}
		}
	}

	fn secure_delete_message(message: &mut ChatMessage) {
		// Overwrite content with zeros using safe code
		let zeros = vec![0u8; message.content.len()];
		unsafe {
			// This is unsafe because we're manipulating the string's bytes directly
			std::ptr::copy(
				zeros.as_ptr(),
				message.content.as_bytes_mut().as_mut_ptr(),
				message.content.len(),
			);
		}

		// Overwrite encrypted content with zeros
		for byte in &mut message.encrypted {
			*byte = 0;
		}
	}

	fn disconnect_user(server: &mut ServerState, user_id: &str) {
		// Get username for logging
		let username = server
			.users
			.get(user_id)
			.map(|u| u.username.clone())
			.unwrap_or_else(|| "Unknown".to_string());

		info!("Disconnecting user: {} ({})", username, user_id);

		if let Some(user) = server.users.get(user_id) {
			// Leave all channels and notify others
			for channel in user.channels.clone() {
				// Remove user from channel
				if let Some(ch) = server.channels.get_mut(&channel) {
					ch.users.remove(user_id);

					// Broadcast leave message
					let leave_message = format!("* {} has disconnected", username);
					Self::broadcast_to_channel(server, &channel, &leave_message, None);
				}
			}

			// Clear all private messages
			// In a secure system, we want to completely remove messages when a user disconnects
			if let Some(user) = server.users.get_mut(user_id) {
				user.messages.clear();
			}
		}

		// Remove user completely
		server.users.remove(user_id);

		info!("User disconnected and messages cleared: {}", username);
	}

	fn find_user_by_username(server: &ServerState, username: &str) -> Option<String> {
		for (id, user) in &server.users {
			if user.username == username {
				return Some(id.clone());
			}
		}
		None
	}
}
