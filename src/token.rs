// Token generator utility for the IRC server
// This tool generates authentication tokens with embedded 8-bit profile pictures

use std::env;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use base64::{decode, encode};
use image::{GenericImageView, ImageBuffer, Rgba};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

// Token Claims Structure with enhanced security
#[derive(Debug, Serialize, Deserialize)]
struct TokenClaims {
	sub: String,           // User ID
	username: String,      // Username
	profile_pic: String,   // Base64 encoded 8-bit profile picture
	exp: usize,            // Expiration timestamp
	iat: usize,            // Issued at timestamp
	nbf: Option<usize>,    // Not valid before timestamp
	jti: Option<String>,   // JWT ID (unique identifier for this token)
	device_id: Option<String>, // Device identifier for restricting access
	allowed_ips: Option<String>, // Allowed IP addresses (CIDR notation)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
	// Parse command line arguments
	let args: Vec<String> = env::args().collect();
	
	if args.len() < 5 {
		println!("Usage: {} <user_id> <username> <image_path> <jwt_secret> [days_valid]", args[0]);
		println!("  user_id: Unique identifier for the user");
		println!("  username: Display name for the user");
		println!("  image_path: Path to the user's 8-bit profile image");
		println!("  jwt_secret: Secret key used to sign the token");
		println!("  days_valid: (Optional) Number of days the token is valid for (default: 30)");
		return Ok(());
	}
	
	let user_id = &args[1];
	let username = &args[2];
	let image_path = &args[3];
	let jwt_secret = &args[4];
	
	// Add additional security options
	let include_security_fields = true;
	
	// Add device identifier and IP address for access control
	// In a real application, these would be validated on connection
	let mut additional_claims = HashMap::new();
	if include_security_fields {
		// Device identifier (could be hardware ID, fingerprint, etc.)
		additional_claims.insert("device_id".to_string(), 
								format!("{:x}", rand::random::<u64>()));
		
		// Allowed IP address ranges (CIDR notation)
		additional_claims.insert("allowed_ips".to_string(), 
								"127.0.0.1/32,192.168.1.0/24".to_string());
								
		// Set shorter expiration for security (12 hours instead of 30 days)
		days_valid = std::cmp::min(days_valid, 1);
		println!("Security mode enabled: token validity reduced to {} days", days_valid);
	}
	
	// Load and process the image
	let img_data = load_and_convert_image(image_path)?;
	
	// Generate the token
	let token = generate_token(user_id, username, &img_data, days_valid, jwt_secret)?;
	
	println!("Token generated successfully:");
	println!("{}", token);
	
	Ok(())
}

// Load and convert an image to 8-bit format
fn load_and_convert_image(image_path: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
	// Check if file exists
	if !Path::new(image_path).exists() {
		return Err(format!("Image file not found: {}", image_path).into());
	}
	
	// Load the image
	let img = image::open(image_path)?;
	
	// Resize to 64x64 for profile picture
	let resized = img.resize_exact(64, 64, image::imageops::FilterType::Nearest);
	
	// Convert to 8-bit color depth (256 colors)
	// This is a simplified conversion - in a real implementation, you'd want to use
	// proper color quantization to get the best 8-bit representation
	let quantized = resized.to_rgba8();
	
	// Convert to indexed color (8-bit palette)
	let palette = image::imageops::colorops::quantize(&quantized, 256);
	
	// Encode as PNG (which can be 8-bit)
	let mut buffer = Vec::new();
	let mut cursor = std::io::Cursor::new(&mut buffer);
	palette.write_to(&mut cursor, image::ImageOutputFormat::Png)?;
	
	Ok(buffer)
}

// Generate JWT token with embedded profile picture
fn generate_token(
	user_id: &str,
	username: &str,
	profile_pic_data: &[u8], 
	days_valid: u64,
	jwt_secret: &str
) -> Result<String, Box<dyn std::error::Error>> {
	// Get current timestamp
	let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
	
	// Calculate expiration timestamp
	let expiration = now + (days_valid * 86400); // 86400 seconds in a day
	
	// Base64 encode the profile picture
	let profile_pic_base64 = base64::encode(profile_pic_data);
	
	// Generate a unique token ID
	let token_id = format!("{:x}-{:x}", rand::random::<u64>(), now);
	
	// Create token claims
	let claims = TokenClaims {
		sub: user_id.to_string(),
		username: username.to_string(),
		profile_pic: profile_pic_base64,
		iat: now as usize,
		exp: expiration as usize,
		nbf: Some(now as usize),  // Token valid immediately
		jti: Some(token_id),     // Unique token ID to prevent replay
		device_id: additional_claims.get("device_id").cloned(),
		allowed_ips: additional_claims.get("allowed_ips").cloned(),
	};
	
	// Generate the token
	let header = Header::new(Algorithm::HS256);
	let encoding_key = EncodingKey::from_secret(jwt_secret.as_bytes());
	
	let token = jsonwebtoken::encode(&header, &claims, &encoding_key)?;
	
	Ok(token)
}

// Verify a token is valid (for testing)
fn verify_token(token: &str, jwt_secret: &str) -> Result<(), Box<dyn std::error::Error>> {
	// Create decoding key
	let decoding_key = jsonwebtoken::DecodingKey::from_secret(jwt_secret.as_bytes());
	
	// Setup validation
	let mut validation = jsonwebtoken::Validation::new(Algorithm::HS256);
	validation.validate_exp = true;
	
	// Verify token
	let token_data = jsonwebtoken::decode::<TokenClaims>(token, &decoding_key, &validation)?;
	
	println!("Token is valid!");
	println!("User ID: {}", token_data.claims.sub);
	println!("Username: {}", token_data.claims.username);
	println!("Issued at: {}", token_data.claims.iat);
	println!("Expires at: {}", token_data.claims.exp);
	println!("Profile picture size: {} bytes", 
		base64::decode(&token_data.claims.profile_pic)?.len());
	
	Ok(())
}

// Example usage within a full application
// This function would be called during user registration/login
fn example_token_workflow() {
	// In a real application, these values would come from your user database
	let user_id = "user123";
	let username = "CoolUser";
	let profile_image_path = "path/to/avatar.png";
	let jwt_secret = "your_very_secure_jwt_secret";
	
	// Generate a token
	match load_and_convert_image(profile_image_path) {
		Ok(img_data) => {
			match generate_token(user_id, username, &img_data, 30, jwt_secret) {
				Ok(token) => {
					println!("Generated token: {}", token);
					// Store or send token to client
				},
				Err(e) => eprintln!("Error generating token: {}", e),
			}
		},
		Err(e) => eprintln!("Error loading image: {}", e),
	}
}