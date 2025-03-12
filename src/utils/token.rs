use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use image::{GenericImageView, ImageBuffer, Rgba};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use log::debug;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};

use crate::server::models::TokenClaims;

/// Token generator for creating secure authentication tokens
pub struct TokenGenerator {
	jwt_secret: String,
}

impl TokenGenerator {
	/// Create a new token generator
	pub fn new(jwt_secret: &str) -> Self {
		TokenGenerator {
			jwt_secret: jwt_secret.to_string(),
		}
	}

	/// Generate a token for a user
	pub fn generate_token(
		&self,
		user_id: &str,
		username: &str,
		profile_pic_data: &[u8],
		days_valid: u64,
		additional_claims: Option<HashMap<String, String>>,
	) -> Result<String, String> {
		// Get current timestamp
		let now = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.map_err(|e| format!("Failed to get current time: {}", e))?
			.as_secs();

		// Calculate expiration timestamp
		let expiration = now + (days_valid * 86400); // 86400 seconds in a day

		// Base64 encode the profile picture
		let profile_pic_base64 = base64::encode(profile_pic_data);

		// Generate a unique token ID
		let token_id = format!("{:x}-{:x}", thread_rng().gen::<u64>(), now);

		// Create token claims
		let mut claims = TokenClaims {
			sub: user_id.to_string(),
			username: username.to_string(),
			profile_pic: profile_pic_base64,
			iat: now as usize,
			exp: expiration as usize,
			nbf: Some(now as usize), // Token valid immediately
			jti: Some(token_id),     // Unique token ID to prevent replay
			device_id: None,
			allowed_ips: None,
		};

		// Add any additional claims
		if let Some(extra_claims) = additional_claims {
			if let Some(device_id) = extra_claims.get("device_id") {
				claims.device_id = Some(device_id.clone());
			}

			if let Some(allowed_ips) = extra_claims.get("allowed_ips") {
				claims.allowed_ips = Some(allowed_ips.clone());
			}
		}

		// Generate the token
		let header = Header::new(Algorithm::HS256);
		let encoding_key = EncodingKey::from_secret(self.jwt_secret.as_bytes());

		let token = jsonwebtoken::encode(&header, &claims, &encoding_key)
			.map_err(|e| format!("Failed to generate token: {}", e))?;

		debug!("Generated token for user {} with ID {}", username, user_id);
		Ok(token)
	}

	/// Load an image and convert it to 8-bit format for profile pictures
	pub fn load_and_convert_image(&self, image_path: &str) -> Result<Vec<u8>, String> {
		// Check if file exists
		if !std::path::Path::new(image_path).exists() {
			return Err(format!("Image file not found: {}", image_path));
		}

		// Load the image
		let img = image::open(image_path).map_err(|e| format!("Failed to open image: {}", e))?;

		// Resize to 64x64 for profile picture
		let resized = img.resize_exact(64, 64, image::imageops::FilterType::Nearest);

		// Convert to 8-bit format
		let quantized = resized.to_rgba8();

		// Convert to indexed color (8-bit palette)
		let palette = image::imageops::colorops::quantize(&quantized, 256);

		// Encode as PNG
		let mut buffer = Vec::new();
		let mut cursor = std::io::Cursor::new(&mut buffer);
		palette
			.write_to(&mut cursor, image::ImageOutputFormat::Png)
			.map_err(|e| format!("Failed to encode image: {}", e))?;

		debug!(
			"Converted image to 8-bit format, size: {} bytes",
			buffer.len()
		);
		Ok(buffer)
	}
}
