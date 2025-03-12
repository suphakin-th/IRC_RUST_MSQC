use base64::encode;
use irc_server::server::facade::IRCServerFacade;
use log::{error, info};
use ring::rand::SystemRandom;
use std::env;

fn main() {
	env_logger::init();

	// Parse command line arguments
	let args: Vec<String> = env::args().collect();
	let bind_address = args
		.get(1)
		.cloned()
		.unwrap_or_else(|| "0.0.0.0:6667".to_string());
	let message_ttl_hours = args
		.get(2)
		.cloned()
		.unwrap_or_else(|| "1".to_string())
		.parse::<u64>()
		.unwrap_or(1);
	let session_timeout_hours = args
		.get(3)
		.cloned()
		.unwrap_or_else(|| "1".to_string())
		.parse::<u64>()
		.unwrap_or(1);

	// Generate a secure random JWT secret
	let mut jwt_secret = [0u8; 32];
	let rng = SystemRandom::new();
	if let Err(e) = rng.fill(&mut jwt_secret) {
		error!("Failed to generate secure JWT secret: {:?}", e);
		return;
	}

	let jwt_secret_str = encode(&jwt_secret);
	info!("Generated secure JWT secret: {}", jwt_secret_str);

	// Create and configure the server
	let server = IRCServerFacade::new(&jwt_secret_str);

	// Configure message deletion after specified time
	if let Err(e) = server.set_message_ttl(message_ttl_hours) {
		error!("Failed to set message TTL: {}", e);
	}

	// Configure session timeout after specified time of inactivity
	if let Err(e) = server.set_session_timeout(session_timeout_hours) {
		error!("Failed to set session timeout: {}", e);
	}

	// Start the server
	info!(
		"Starting secure IRC server on {} with message auto-deletion after {} hour(s)",
		bind_address, message_ttl_hours
	);
	match server.start(&bind_address) {
		Ok(_) => info!("Server started successfully"),
		Err(e) => error!("Failed to start server: {}", e),
	}
}
