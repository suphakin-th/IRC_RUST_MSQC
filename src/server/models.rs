use std::collections::{HashSet, VecDeque};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::server::session::Session;

// Chat message with expiration
#[derive(Clone)]
pub struct ChatMessage {
	pub sender: String,
	pub content: String,
	pub timestamp: Instant,
	pub encrypted: Vec<u8>,
}

// Message types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MessageType {
	PrivateMessage,
	ChannelMessage,
	SystemMessage,
}

// Message representation
pub struct Message {
	pub message_type: MessageType,
	pub sender: String,
	pub content: String,
	pub timestamp: u64,
	pub target: String,              // Channel name or username
	pub expiration: Option<Instant>, // When this message should be deleted
}

// User representation
pub struct User {
	pub id: String,
	pub username: String,
	pub profile_pic: Vec<u8>, // Raw 8-bit profile picture data
	pub channels: HashSet<String>,
	pub stream: Option<Arc<Mutex<TcpStream>>>,
	pub session: Option<Session>,
	pub messages: VecDeque<ChatMessage>, // Store recent messages
}

// Channel representation
pub struct Channel {
	pub name: String,
	pub topic: String,
	pub users: HashSet<String>,
	pub messages: VecDeque<ChatMessage>, // History with expiration
	pub created_at: Instant,
	pub last_activity: Instant,
}

// Token Claims Structure
#[derive(Debug, Serialize, Deserialize)]
pub struct TokenClaims {
	pub sub: String,                 // User ID
	pub username: String,            // Username
	pub profile_pic: String,         // Base64 encoded 8-bit profile picture
	pub exp: usize,                  // Expiration timestamp
	pub iat: usize,                  // Issued at timestamp
	pub nbf: Option<usize>,          // Not valid before timestamp
	pub jti: Option<String>,         // JWT ID (unique identifier for this token)
	pub device_id: Option<String>,   // Device identifier for restricting access
	pub allowed_ips: Option<String>, // Allowed IP addresses (CIDR notation)
}
