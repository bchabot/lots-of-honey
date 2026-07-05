<?php
/**
 * Handles request interception and honeypot actions.
 *
 * @package Lots_Of_Honey
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class LOH_Interceptor {

	/**
	 * Singleton instance of the class
	 *
	 * @var LOH_Interceptor
	 */
	private static $instance = null;

	/**
	 * Get class instance
	 */
	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Constructor
	 */
	private function __construct() {}

	/**
	 * Intercept the request if the current site is a honeypot
	 */
	public function maybe_intercept() {
		// Determine if the current site is configured as a honeypot
		if ( ! $this->is_current_site_honeypot() ) {
			return;
		}

		// Get visitor IP
		$ip = $this->get_client_ip();

		// Get options depending on activation mode (network vs single site)
		$options = $this->get_options();

		// Check if IP is whitelisted
		if ( $this->is_ip_in_whitelist( $ip, $options['loh_ip_whitelist'] ) ) {
			return;
		}

		// Allow super admins or admins with manage_options capability to access the dashboard
		if ( is_user_logged_in() && ( is_super_admin() || current_user_can( 'manage_options' ) ) ) {
			return;
		}

		// Perform honeypot action
		$this->execute_honeypot( $ip, $options );
	}

	/**
	 * Check if the current site is a honeypot
	 *
	 * @return bool
	 */
	public function is_current_site_honeypot() {
		if ( ! is_multisite() ) {
			return '1' === get_option( 'loh_enabled', '1' );
		}

		// In Multisite, check if network activated
		$active_sitewide = get_site_option( 'active_sitewide_plugins' );
		$is_network_active = isset( $active_sitewide['lots-of-honey/lots-of-honey.php'] );

		if ( $is_network_active ) {
			$enabled = '1' === get_site_option( 'loh_enabled', '1' );
			if ( ! $enabled ) {
				return false;
			}
			$honeypot_sites = get_site_option( 'loh_honeypot_sites', array() );
			if ( ! is_array( $honeypot_sites ) ) {
				$honeypot_sites = array();
			}
			return in_array( get_current_blog_id(), $honeypot_sites );
		}

		// Single-site activation in multisite network
		return '1' === get_option( 'loh_enabled', '1' );
	}

	/**
	 * Get configuration options
	 *
	 * @return array
	 */
	private function get_options() {
		$keys = array(
			'loh_enabled'      => '1',
			'loh_mode'         => 'tarpit',
			'loh_tarpit_delay' => 10,
			'loh_ip_whitelist' => '',
		);

		$options = array();
		$is_network_active = false;

		if ( is_multisite() ) {
			$active_sitewide = get_site_option( 'active_sitewide_plugins' );
			$is_network_active = isset( $active_sitewide['lots-of-honey/lots-of-honey.php'] );
		}

		foreach ( $keys as $key => $default ) {
			if ( $is_network_active ) {
				$options[ $key ] = get_site_option( $key, $default );
			} else {
				$options[ $key ] = get_option( $key, $default );
			}
		}

		return $options;
	}

	/**
	 * Retrieve client IP address
	 *
	 * @return string
	 */
	public function get_client_ip() {
		$ip = '';
		if ( ! empty( $_SERVER['HTTP_CLIENT_IP'] ) ) {
			$ip = $_SERVER['HTTP_CLIENT_IP'];
		} elseif ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
			$ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
		} elseif ( ! empty( $_SERVER['REMOTE_ADDR'] ) ) {
			$ip = $_SERVER['REMOTE_ADDR'];
		}

		if ( strpos( $ip, ',' ) !== false ) {
			$parts = explode( ',', $ip );
			$ip = trim( $parts[0] );
		}

		return sanitize_text_field( $ip );
	}

	/**
	 * Check if IP is in the whitelist (supports exact IP and CIDR)
	 *
	 * @param string $ip               Client IP.
	 * @param string $whitelist_string Whitelist configuration string.
	 * @return bool
	 */
	public function is_ip_in_whitelist( $ip, $whitelist_string ) {
		if ( empty( $whitelist_string ) ) {
			return false;
		}

		$whitelist = array_map( 'trim', explode( "\n", str_replace( "\r", '', $whitelist_string ) ) );
		foreach ( $whitelist as $allowed ) {
			if ( empty( $allowed ) ) {
				continue;
			}

			// Exact match
			if ( $ip === $allowed ) {
				return true;
			}

			// CIDR match
			if ( strpos( $allowed, '/' ) !== false ) {
				if ( $this->ip_in_cidr( $ip, $allowed ) ) {
					return true;
				}
			}
		}

		return false;
	}

	/**
	 * Check if IP is within a CIDR subnet
	 *
	 * @param string $ip   IP address.
	 * @param string $cidr CIDR subnet.
	 * @return bool
	 */
	private function ip_in_cidr( $ip, $cidr ) {
		list( $subnet, $bits ) = explode( '/', $cidr );
		$ip_long = ip2long( $ip );
		$subnet_long = ip2long( $subnet );
		if ( false === $ip_long || false === $subnet_long ) {
			return false;
		}
		$mask = -1 << ( 32 - $bits );
		$subnet_long &= $mask;
		return ( $ip_long & $mask ) == $subnet_long;
	}

	/**
	 * Execute the honeypot action
	 *
	 * @param string $ip      Client IP.
	 * @param array  $options Configuration options.
	 */
	private function execute_honeypot( $ip, $options ) {
		$method = isset( $_SERVER['REQUEST_METHOD'] ) ? $_SERVER['REQUEST_METHOD'] : 'GET';
		$uri = isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : '';
		$user_agent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? $_SERVER['HTTP_USER_AGENT'] : '';

		// Capture headers
		$headers = array();
		foreach ( $_SERVER as $key => $value ) {
			if ( strpos( $key, 'HTTP_' ) === 0 ) {
				$header_name = str_replace( ' ', '-', ucwords( strtolower( str_replace( '_', ' ', substr( $key, 5 ) ) ) ) );
				$headers[ $header_name ] = $value;
			}
		}

		// Capture payload (sanitized)
		$payload = array();
		if ( 'POST' === $method ) {
			$payload = $_POST;
		} elseif ( 'GET' === $method ) {
			$payload = $_GET;
		}

		// Sanitize sensitive fields (like password fields in payload to protect credentials if a real user made a mistake)
		// But in a honeypot, we specifically want to know if they tried standard admin/admin, so we'll store it but redact if it looks like actual personal info
		$sensitive_keys = array( 'password', 'pwd', 'pass', 'secret', 'key' );
		foreach ( $payload as $k => $v ) {
			if ( in_array( strtolower( $k ), $sensitive_keys, true ) ) {
				// We keep first 3 and last 1 characters if it's long, or just keep it as is since it's a honeypot, but sanitize for safety
				$payload[ $k ] = sanitize_text_field( $v );
			} else {
				if ( is_array( $v ) ) {
					$payload[ $k ] = map_deep( $v, 'sanitize_text_field' );
				} else {
					$payload[ $k ] = sanitize_text_field( $v );
				}
			}
		}

		$mode = $options['loh_mode'];
		$delay = (int) $options['loh_tarpit_delay'];

		// Check if they are trying to log in or hit wp-login.php/wp-admin
		$is_login_page = ( strpos( $uri, 'wp-login.php' ) !== false );

		// If hitting login or admin and we are in "fake_login" mode, or if they hit login specifically
		if ( $is_login_page || 'fake_login' === $mode ) {
			$mode = 'fake_login';
		}

		// Log request
		LOH_Database::insert_log( $ip, $method, $uri, $user_agent, $headers, $payload, $mode );

		// Execute the action
		switch ( $mode ) {
			Case 'tarpit':
				if ( $delay > 0 ) {
					sleep( min( $delay, 60 ) ); // Max 60s sleep to prevent server timeout issues
				}
				$this->serve_blocked_page();
				break;

			Case 'block':
				$this->serve_blocked_page();
				break;

			Case 'fake_404':
				$this->serve_404_page();
				break;

			Case 'fake_login':
				$this->serve_fake_login();
				break;

			Default:
				$this->serve_blocked_page();
				break;
		}
	}

	/**
	 * Serve a premium but authentic looking 403 Forbidden page
	 */
	private function serve_blocked_page() {
		status_header( 403 );
		header( 'Content-Type: text/html; charset=utf-8' );
		?>
		<!DOCTYPE html>
		<html>
		<head>
			<title>403 Forbidden</title>
			<style>
				body { background-color: #f7f9fa; color: #333; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif; text-align: center; padding: 15% 5% 5% 5%; }
				h1 { font-size: 50px; margin: 0; color: #dc3545; }
				p { font-size: 18px; color: #6c757d; }
				hr { max-width: 50px; border: 1px solid #dee2e6; margin: 20px auto; }
			</style>
		</head>
		<body>
			<h1>403 Forbidden</h1>
			<hr>
			<p>Access to this resource on the server is denied.</p>
		</body>
		</html>
		<?php
		exit;
	}

	/**
	 * Serve a generic 404 Not Found page
	 */
	private function serve_404_page() {
		status_header( 404 );
		header( 'Content-Type: text/html; charset=utf-8' );
		?>
		<!DOCTYPE html>
		<html>
		<head>
			<title>404 Not Found</title>
			<style>
				body { background-color: #fff; color: #000; font-family: "Courier New", Courier, monospace; padding: 50px; }
				h1 { font-size: 24px; font-weight: normal; margin: 0 0 10px 0; }
				p { font-size: 14px; margin: 0; }
			</style>
		</head>
		<body>
			<h1>Not Found</h1>
			<p>The requested URL was not found on this server.</p>
		</body>
		</html>
		<?php
		exit;
	}

	/**
	 * Serve a fake WordPress Login page that always fails
	 */
	private function serve_fake_login() {
		status_header( 200 );
		header( 'Content-Type: text/html; charset=utf-8' );

		$submitted_username = isset( $_POST['log'] ) ? sanitize_text_field( $_POST['log'] ) : '';
		$error_message = '';

		if ( ! empty( $submitted_username ) ) {
			$error_message = sprintf(
				__( '<strong>Error</strong>: The username <strong>%s</strong> is not registered on this site. If you are unsure of your username, try your email address instead.', 'lots-of-honey' ),
				esc_html( $submitted_username )
			);
		}

		$login_url = esc_url( $_SERVER['REQUEST_URI'] );
		?>
		<!DOCTYPE html>
		<html lang="en-US">
		<head>
			<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
			<title>Log In &lsaquo; WordPress</title>
			<meta name='robots' content='max-image-preview:large, noindex, noarchive' />
			<link rel='stylesheet' id='dashicons-css' href='<?php echo esc_url( includes_url( 'css/dashicons.min.css' ) ); ?>' type='text/css' media='all' />
			<link rel='stylesheet' id='buttons-css' href='<?php echo esc_url( includes_url( 'css/buttons.min.css' ) ); ?>' type='text/css' media='all' />
			<link rel='stylesheet' id='forms-css' href='<?php echo esc_url( admin_url( 'css/forms.min.css' ) ); ?>' type='text/css' media='all' />
			<link rel='stylesheet' id='l10n-css' href='<?php echo esc_url( admin_url( 'css/l10n.min.css' ) ); ?>' type='text/css' media='all' />
			<link rel='stylesheet' id='login-css' href='<?php echo esc_url( admin_url( 'css/login.min.css' ) ); ?>' type='text/css' media='all' />
			<meta name='referrer' content='strict-origin-when-cross-origin' />
			<meta name='viewport' content='width=device-width' />
		</head>
		<body class="login no-js login-action-login wp-core-ui">
			<script type="text/javascript">
				document.body.className = document.body.className.replace('no-js', 'js');
			</script>
			<div id="login">
				<h1><a href="https://wordpress.org/">Powered by WordPress</a></h1>

				<?php if ( ! empty( $error_message ) ) : ?>
					<div id="login_error">
						<?php echo $error_message; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?><br />
					</div>
				<?php endif; ?>

				<form name="loginform" id="loginform" action="<?php echo $login_url; ?>" method="post" novalidate="novalidate">
					<p>
						<label for="user_login">Username or Email Address</label>
						<input type="text" name="log" id="user_login" class="input" value="<?php echo esc_attr( $submitted_username ); ?>" size="20" autocapitalize="off" autocomplete="username" required="required" />
					</p>
					<div class="user-pass-wrap">
						<label for="user_pass">Password</label>
						<div class="wp-pwd">
							<input type="password" name="pwd" id="user_pass" class="input password-input" size="20" autocomplete="current-password" required="required" />
						</div>
					</div>
					<p class="forgetmenot">
						<input name="rememberme" type="checkbox" id="rememberme" value="forever" />
						<label for="rememberme">Remember Me</label>
					</p>
					<p class="submit">
						<input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="Log In" />
					</p>
				</form>

				<p id="nav">
					<a href="<?php echo esc_url( wp_lostpassword_url() ); ?>">Lost your password?</a>
				</p>
				<p id="backtoblog">
					<a href="<?php echo esc_url( home_url( '/' ) ); ?>">&larr; Go to Home</a>
				</p>
			</div>
			<div class="clear"></div>
		</body>
		</html>
		<?php
		exit;
	}
}
