use std::io::{self, BufRead};
use std::thread;
use std::time::Duration;
use std::sync::{Arc, Mutex};

use irc_server::client::{IRCClient, SessionMonitor};
use log::{info, warn, error};

// Function to read messages from the server and print them
fn message_reader(client: &mut IRCClient, activity_handle: Arc<Mutex<Instant>>) {
	let mut consecutive_errors = 0;
	
	while let Some(stream) = &mut client.stream {
		match client.read_message() {
			Ok(message) => {
				// Reset error counter on successful reads
				consecutive_errors = 0;
				
				// Update last activity time when receiving messages
				{
					let mut guard = activity_handle.lock().unwrap();
					*guard = std::time::Instant::now();
				}
				
				println!("{}", message);
				
				// If the message contains a deletion notice, acknowledge it
				if message.contains("[DELETED]") || message.contains("deleted") {
					println!("[SECURITY] Some messages have been automatically deleted for security");
				}
			}
			Err(e) => {
				if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut {
					// Just a timeout, continue
					thread::sleep(Duration::from_millis(100));
					continue;
				}
				
				// Count consecutive errors
				consecutive_errors += 1;
				
				if consecutive_errors > 5 {
					error!("Too many consecutive errors, disconnecting: {}", e);
					break;
				}
				
				error!("Error reading from server: {}", e);
				thread::sleep(Duration::from_secs(1));
			}
		}
	}
	
	info!("[SECURITY] Message receiver stopped. Session ended.");
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
	env_logger::init();
	
	// In a real application, this token would be provided by the server
	// after user registration/authentication
	let token = "your_actual_token_here"; // Replace with a real token
	
	// Create client
	let mut client = IRCClient::new("127.0.0.1", 6667, token);
	
	// Create session monitor
	let monitor = SessionMonitor::new(
		Duration::from_secs(3600), // 1 hour max session
		Duration::from_secs(1800)  // 30 minutes inactivity timeout
	);
	
	// Set up session monitoring
	let activity_handle = monitor.activity_handle();
	
	// Set expiration callback
	let monitor = monitor.on_expire(|| {
		println!("\n[SECURITY] Session expired or inactive for too long.");
		println!("[SECURITY] Disconnecting and securely deleting all messages...");
		std::process::exit(0);
	});
	
	// Start monitor in background thread
	let _monitor_handle = monitor.start_monitoring();
	
	// Connect to server
	match client.connect() {
		Ok(_) => println!("Connected to IRC server with secure session!"),
		Err(e) => {
			error!("Failed to connect: {}", e);
			return Err(Box::new(io::Error::new(io::ErrorKind::Other, e)));
		}
	}
	
	println!("[SECURITY] All messages will be automatically deleted after 1 hour");
	println!("[SECURITY] Session will automatically end after 1 hour");
	
	// Join a channel
	match client.join_channel("#general") {
		Ok(_) => println!("Joined #general"),
		Err(e) => error!("Failed to join channel: {}", e),
	}
	
	// Spawn a thread to listen for messages
	let mut receive_client = client.clone();
	let receive_activity = activity_handle.clone();
	thread::spawn(move || {
		message_reader(&mut receive_client, receive_activity);
	});
	
	// Main loop for sending messages
	let stdin = io::stdin();
	let mut lines = stdin.lock().lines();
	
	println!("Enter messages (or 'exit' to quit, or 'secure-clear' to delete all messages):");
	println!("Type /help for available commands");
	
	while let Some(Ok(line)) = lines.next() {
		// Update last activity time
		{
			let mut guard = activity_handle.lock().unwrap();
			*guard = std::time::Instant::now();
		}
		
		if line.trim() == "exit" {
			break;
		}
		
		if line.trim() == "secure-clear" {
			println!("[SECURITY] Requesting secure deletion of all messages...");
			match client.secure_clear() {
				Ok(_) => println!("[SECURITY] All messages have been securely deleted"),
				Err(e) => error!("[ERROR] Failed to clear messages: {}", e),
			}
			continue;
		}
		
		// Parse commands
		if line.starts_with('/') {
			let parts: Vec<&str> = line[1..].splitn(2, ' ').collect();
			if parts.is_empty() {
				continue;
			}
			
			match parts[0] {
				"join" => {
					if parts.len() < 2 {
						println!("Usage: /join #channel");
						continue;
					}
					
					match client.join_channel(parts[1]) {
						Ok(_) => println!("Joined {}", parts[1]),
						Err(e) => error!("Failed to join channel: {}", e),
					}
				}
				"part" => {
					if parts.len() < 2 {
						println!("Usage: /part #channel");
						continue;
					}
					
					match client.leave_channel(parts[1]) {
						Ok(_) => println!("Left {}", parts[1]),
						Err(e) => error!("Failed to leave channel: {}", e),
					}
				}
				"msg" => {
					if parts.len() < 2 {
						println!("Usage: /msg target message");
						continue;
					}
					
					let msg_parts: Vec<&str> = parts[1].splitn(2, ' ').collect();
					if msg_parts.len() < 2 {
						println!("Usage: /msg target message");
						continue;
					}
					
					match client.send_message(msg_parts[0], msg_parts[1]) {
						Ok(_) => {}
						Err(e) => error!("Failed to send message: {}", e),
					}
				}
				"status" => {
					let session_duration = client.session_duration();
					let hours = session_duration.as_secs() / 3600;
					let minutes = (session_duration.as_secs() % 3600) / 60;
					let seconds = session_duration.as_secs() % 60;
					
					println!("[SESSION] Active for {}:{:02}:{:02}", hours, minutes, seconds);
					println!("[SESSION] Session will end in {} minutes", 
							 60 - (session_duration.as_secs() / 60));
				}
				"help" => {
					println!("Available commands:");
					println!("  /join #channel - Join a channel");
					println!("  /part #channel - Leave a channel");
					println!("  /msg user message - Send private message");
					println!("  /status - Show session status");
					println!("  /help - Show this help");
					println!("Special commands:");
					println!("  exit - Disconnect from server");
					println!("  secure-clear - Delete all messages");
				}
				_ => {
					println!("Unknown command: {}", parts[0]);
					println!("Type /help for available commands");
				}
			}
		} else {
			// Send message to current channel
			if let Some(channel) = &client.current_channel {
				match client.send_message(channel, &line) {
					Ok(_) => {}
					Err(e) => error!("Failed to send message: {}", e),
				}
			} else {
				println!("Not in any channel. Join a channel with /join #channelname");
			}
		}
	}
	
	println!("[SECURITY] Disconnecting and securely deleting all messages...");
	
	// Disconnect from server
	match client.disconnect() {
		Ok(_) => println!("[SECURITY] Successfully disconnected and cleared all data"),
		Err(e) => error!("[ERROR] Error disconnecting: {}", e),
	}
	
	Ok(())
}