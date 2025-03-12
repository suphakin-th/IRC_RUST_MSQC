use std::collections::HashMap;
use std::env;
use std::time::Duration;

use irc_server::utils::token::TokenGenerator;
use log::{error, info};

fn main() -> Result<(), Box<dyn std::error::Error>> {
	env_logger::init();

	// Parse command line arguments
	let args: Vec<String> = env::args().collect();

	if args.len() < 5 {
		println!(
			"Usage: {} <user_id> <username> <image_path> <jwt_secret> [days_valid]",
			args[0]
		);
		println!("  user_id: Unique identifier for the user");
		println!("  username: Display name for the user");
		println!("  image_path: Path to the user's 8-bit profile image");
		println!("  jwt_secret: Secret key used to sign the token");
		println!("  days_valid: (Optional) Number of days the token is valid for (default: 1)");
		return Ok(());
	}

	let user_id = &args[1];
	let username = &args[2];
	let image_path = &args[3];
	let jwt_secret = &args[4];

	// Default to 1 day if not specified (for security)
	let days_valid = if args.len() > 5 {
		args[5].parse::<u64>().unwrap_or(1)
	} else {
		1
	};

	// Add additional security options
	let include_security_fields = true;

	// Create additional claims
	let mut additional_claims = HashMap::new();
	if include_security_fields {
		// Device identifier (could be hardware ID, fingerprint, etc.)
		additional_claims.insert(
			"device_id".to_string(),
			format!("{:x}", rand::random::<u64>()),
		);

		// Allowed IP address ranges (CIDR notation)
		additional_claims.insert(
			"allowed_ips".to_string(),
			"127.0.0.1/32,192.168.1.0/24".to_string(),
		);
	}

	info!("Generating token for user {} ({})", username, user_id);
	info!("Token will be valid for {} days", days_valid);

	// Create token generator
	let token_generator = TokenGenerator::new(jwt_secret);

	// Load and convert image
	let img_data = token_generator.load_and_convert_image(image_path)?;
	info!(
		"Loaded profile image: {} ({} bytes converted to 8-bit format)",
		image_path,
		img_data.len()
	);

	// Generate token
	let token = token_generator.generate_token(
		user_id,
		username,
		&img_data,
		days_valid,
		Some(additional_claims),
	)?;

	println!("Token generated successfully:");
	println!("{}", token);
	println!("\nThis token will expire in {} days", days_valid);

	Ok(())
}
