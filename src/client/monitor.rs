use log::{info, warn};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Session monitor to track session lifetime and inactivity
pub struct SessionMonitor {
	/// When the session started
	start_time: Instant,
	/// Maximum session duration
	max_duration: Duration,
	/// Time of last activity
	last_activity: Arc<Mutex<Instant>>,
	/// Inactivity timeout
	inactivity_timeout: Duration,
	/// Warning threshold for inactivity (when to start warning)
	warning_threshold: Duration,
	/// Callback for session expiration
	on_expire: Option<Box<dyn Fn() + Send>>,
}

impl SessionMonitor {
	/// Create a new session monitor
	pub fn new(max_duration: Duration, inactivity_timeout: Duration) -> Self {
		SessionMonitor {
			start_time: Instant::now(),
			max_duration,
			last_activity: Arc::new(Mutex::new(Instant::now())),
			inactivity_timeout,
			warning_threshold: inactivity_timeout.saturating_sub(Duration::from_secs(300)), // 5 minutes before timeout
			on_expire: None,
		}
	}

	/// Set a callback to be called when the session expires
	pub fn on_expire<F>(mut self, callback: F) -> Self
	where
		F: Fn() + Send + 'static,
	{
		self.on_expire = Some(Box::new(callback));
		self
	}

	/// Get a handle to update activity
	pub fn activity_handle(&self) -> Arc<Mutex<Instant>> {
		self.last_activity.clone()
	}

	/// Update last activity time
	pub fn update_activity(&self) {
		let mut guard = self.last_activity.lock().unwrap();
		*guard = Instant::now();
	}

	/// Start monitoring session in a background thread
	pub fn start_monitoring(self) -> thread::JoinHandle<()> {
		thread::spawn(move || {
			self.monitor_session();
		})
	}

	/// Monitor session for expiration
	fn monitor_session(self) {
		let mut warned_about_inactivity = false;
		let mut warned_about_duration = false;

		loop {
			thread::sleep(Duration::from_secs(30)); // Check every 30 seconds

			let now = Instant::now();
			let session_duration = now.duration_since(self.start_time);

			// Check if we've exceeded the absolute session limit
			if session_duration >= self.max_duration {
				info!(
					"Session maximum duration reached ({:?}).",
					self.max_duration
				);

				if let Some(callback) = &self.on_expire {
					callback();
				}

				break;
			}

			// Warn when approaching max duration
			if !warned_about_duration
				&& session_duration >= self.max_duration.saturating_sub(Duration::from_secs(300))
			{
				warn!("Session will expire in less than 5 minutes");
				warned_about_duration = true;
			}

			// Check if there's been no activity for too long
			let last_active = {
				let guard = self.last_activity.lock().unwrap();
				*guard
			};

			let idle_time = now.duration_since(last_active);

			if idle_time >= self.inactivity_timeout {
				info!("Session inactive for {:?}, exceeding timeout", idle_time);

				if let Some(callback) = &self.on_expire {
					callback();
				}

				break;
			}

			// Warn about approaching inactivity timeout
			if !warned_about_inactivity && idle_time >= self.warning_threshold {
				let remaining = self.inactivity_timeout.saturating_sub(idle_time);
				warn!(
					"Session inactive for {:?}, will timeout in {:?}",
					idle_time, remaining
				);
				warned_about_inactivity = true;
			} else if warned_about_inactivity && idle_time < self.warning_threshold {
				// Reset warning if activity resumed
				warned_about_inactivity = false;
			}
		}
	}

	/// Get session duration
	pub fn duration(&self) -> Duration {
		Instant::now().duration_since(self.start_time)
	}

	/// Get idle time
	pub fn idle_time(&self) -> Duration {
		let last_active = {
			let guard = self.last_activity.lock().unwrap();
			*guard
		};
		Instant::now().duration_since(last_active)
	}

	/// Get remaining time before session expires
	pub fn remaining_time(&self) -> Duration {
		self.max_duration.saturating_sub(self.duration())
	}

	/// Get remaining time before inactivity timeout
	pub fn remaining_idle_time(&self) -> Duration {
		self.inactivity_timeout.saturating_sub(self.idle_time())
	}

	/// Format duration in a human-readable way
	pub fn format_duration(duration: Duration) -> String {
		let total_seconds = duration.as_secs();
		let hours = total_seconds / 3600;
		let minutes = (total_seconds % 3600) / 60;
		let seconds = total_seconds % 60;

		if hours > 0 {
			format!("{}h {}m {}s", hours, minutes, seconds)
		} else if minutes > 0 {
			format!("{}m {}s", minutes, seconds)
		} else {
			format!("{}s", seconds)
		}
	}
}
