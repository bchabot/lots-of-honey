<?php
/**
 * Admin interface and settings for Lots of Honey plugin.
 *
 * @package Lots_Of_Honey
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class LOH_Admin {

	/**
	 * Singleton instance of the class
	 *
	 * @var LOH_Admin
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
	private function __construct() {
		add_action( 'admin_menu', array( $this, 'add_admin_menu' ) );
		add_action( 'network_admin_menu', array( $this, 'add_network_admin_menu' ) );
		add_action( 'admin_init', array( $this, 'register_settings' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_admin_assets' ) );
	}

	/**
	 * Enqueue styles and scripts
	 */
	public function enqueue_admin_assets( $hook ) {
		// Only load on our plugin pages
		if ( strpos( $hook, 'lots-of-honey' ) === false ) {
			return;
		}

		wp_enqueue_style( 'dashicons' );
	}

	/**
	 * Check if plugin is active network-wide
	 */
	private function is_network_active() {
		if ( ! is_multisite() ) {
			return false;
		}
		$active_sitewide = get_site_option( 'active_sitewide_plugins' );
		return isset( $active_sitewide[ defined( 'LOH_PLUGIN_BASENAME' ) ? LOH_PLUGIN_BASENAME : 'lots-of-honey/lots-of-honey.php' ] );
	}

	/**
	 * Add Network Admin menu
	 */
	public function add_network_admin_menu() {
		add_menu_page(
			__( 'Lots of Honey', 'lots-of-honey' ),
			__( 'Lots of Honey', 'lots-of-honey' ),
			'manage_network_options',
			'lots-of-honey-network',
			array( $this, 'render_network_admin_page' ),
			'dashicons-shield-alt',
			30
		);
	}

	/**
	 * Add Single Site Admin menu
	 */
	public function add_admin_menu() {
		// If network active and we're not in network admin, show local logs and status only
		$title = __( 'Lots of Honey', 'lots-of-honey' );
		add_menu_page(
			$title,
			$title,
			'manage_options',
			'lots-of-honey',
			array( $this, 'render_admin_page' ),
			'dashicons-shield-alt',
			30
		);
	}

	/**
	 * Register plugin settings
	 */
	public function register_settings() {
		register_setting( 'loh_settings_group', 'loh_enabled' );
		register_setting( 'loh_settings_group', 'loh_mode' );
		register_setting( 'loh_settings_group', 'loh_tarpit_delay' );
		register_setting( 'loh_settings_group', 'loh_ip_whitelist' );
	}

	/**
	 * Render the network admin page
	 */
	public function render_network_admin_page() {
		if ( ! current_user_can( 'manage_network_options' ) ) {
			wp_die( __( 'You do not have sufficient permissions to access this page.', 'lots-of-honey' ) );
		}

		// Handle actions
		$this->handle_network_actions();

		$current_tab = isset( $_GET['tab'] ) ? sanitize_key( $_GET['tab'] ) : 'logs';

		$this->render_admin_styles();
		?>
		<div class="wrap loh-admin-wrap">
			<div class="loh-header">
				<div class="loh-logo">
					<span class="dashicons dashicons-shield-alt"></span>
					<h1><?php esc_html_e( 'Lots of Honey &mdash; Network Honeypot Control', 'lots-of-honey' ); ?></h1>
				</div>
				<div class="loh-version">v<?php echo esc_html( LOH_VERSION ); ?></div>
			</div>

			<h2 class="nav-tab-wrapper">
				<a href="?page=lots-of-honey-network&tab=logs" class="nav-tab <?php echo 'logs' === $current_tab ? 'nav-tab-active' : ''; ?>">
					<span class="dashicons dashicons-list-view"></span> <?php esc_html_e( 'Captured Logs', 'lots-of-honey' ); ?>
				</a>
				<a href="?page=lots-of-honey-network&tab=settings" class="nav-tab <?php echo 'settings' === $current_tab ? 'nav-tab-active' : ''; ?>">
					<span class="dashicons dashicons-admin-settings"></span> <?php esc_html_e( 'Network Settings', 'lots-of-honey' ); ?>
				</a>
				<a href="?page=lots-of-honey-network&tab=banlist" class="nav-tab <?php echo 'banlist' === $current_tab ? 'nav-tab-active' : ''; ?>">
					<span class="dashicons dashicons-dismiss"></span> <?php esc_html_e( 'IP Banlist', 'lots-of-honey' ); ?>
				</a>
			</h2>

			<div class="loh-content">
				<?php
				if ( 'settings' === $current_tab ) {
					$this->render_network_settings_tab();
				} elseif ( 'banlist' === $current_tab ) {
					$this->render_network_banlist_tab();
				} else {
					$this->render_logs_tab( null ); // Show all logs for the network
				}
				?>
			</div>
		</div>
		<?php
		$this->render_admin_scripts();
	}

	/**
	 * Render the single site admin page
	 */
	public function render_admin_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( __( 'You do not have sufficient permissions to access this page.', 'lots-of-honey' ) );
		}

		// Handle actions
		$this->handle_site_actions();

		$is_net_active = $this->is_network_active();
		$current_tab = isset( $_GET['tab'] ) ? sanitize_key( $_GET['tab'] ) : 'logs';

		$this->render_admin_styles();
		?>
		<div class="wrap loh-admin-wrap">
			<div class="loh-header">
				<div class="loh-logo">
					<span class="dashicons dashicons-shield-alt"></span>
					<h1><?php esc_html_e( 'Lots of Honey Control Panel', 'lots-of-honey' ); ?></h1>
				</div>
				<div class="loh-version">v<?php echo esc_html( LOH_VERSION ); ?></div>
			</div>

			<?php if ( $is_net_active ) : ?>
				<div class="loh-banner loh-banner-info">
					<span class="dashicons dashicons-info"></span>
					<div>
						<strong><?php esc_html_e( 'Network Admin Controlled', 'lots-of-honey' ); ?></strong>
						<p><?php esc_html_e( 'This plugin is network activated. Honeypot settings are globally managed by the Network Administrator. Below are the honeypot access logs recorded on this specific site.', 'lots-of-honey' ); ?></p>
					</div>
				</div>
			<?php endif; ?>

			<h2 class="nav-tab-wrapper">
				<a href="?page=lots-of-honey&tab=logs" class="nav-tab <?php echo 'logs' === $current_tab ? 'nav-tab-active' : ''; ?>">
					<span class="dashicons dashicons-list-view"></span> <?php esc_html_e( 'Site Logs', 'lots-of-honey' ); ?>
				</a>
				<?php if ( ! $is_net_active ) : ?>
					<a href="?page=lots-of-honey&tab=settings" class="nav-tab <?php echo 'settings' === $current_tab ? 'nav-tab-active' : ''; ?>">
						<span class="dashicons dashicons-admin-settings"></span> <?php esc_html_e( 'Honeypot Settings', 'lots-of-honey' ); ?>
					</a>
				<?php endif; ?>
			</h2>

			<div class="loh-content">
				<?php
				if ( 'settings' === $current_tab && ! $is_net_active ) {
					$this->render_site_settings_tab();
				} else {
					$this->render_logs_tab( get_current_blog_id() );
				}
				?>
			</div>
		</div>
		<?php
		$this->render_admin_scripts();
	}

	/**
	 * Handle settings saving & actions in Network Admin
	 */
	private function handle_network_actions() {
		// Handle Banlist Export (GET Action)
		if ( isset( $_GET['action'] ) && 'export_banlist' === $_GET['action'] ) {
			if ( ! current_user_can( 'manage_network_options' ) ) {
				wp_die( __( 'Unauthorized action.', 'lots-of-honey' ) );
			}
			$ban_list = get_site_option( 'loh_ban_list', array() );
			if ( ! is_array( $ban_list ) ) {
				$ban_list = array();
			}
			header( 'Content-Type: text/plain; charset=utf-8' );
			header( 'Content-Disposition: attachment; filename="banned-ips.txt"' );
			foreach ( $ban_list as $ip => $timestamp ) {
				echo esc_html( $ip ) . "\r\n";
			}
			exit;
		}

		// Handle Remove IP from Banlist (GET Action)
		if ( isset( $_GET['action'] ) && 'unban_ip' === $_GET['action'] && isset( $_GET['ip'] ) ) {
			if ( ! current_user_can( 'manage_network_options' ) ) {
				wp_die( __( 'Unauthorized action.', 'lots-of-honey' ) );
			}
			if ( ! isset( $_GET['_wpnonce'] ) || ! wp_verify_nonce( $_GET['_wpnonce'], 'loh_unban_ip_nonce' ) ) {
				wp_die( __( 'Security check failed.', 'lots-of-honey' ) );
			}
			$ip = sanitize_text_field( $_GET['ip'] );
			LOH_Interceptor::get_instance()->remove_ip_from_banlist( $ip );
			echo '<div class="notice notice-success is-dismissible"><p>' . sprintf( esc_html__( 'IP address %s removed from the banlist.', 'lots-of-honey' ), esc_html( $ip ) ) . '</p></div>';
		}

		if ( ! isset( $_POST['loh_network_nonce_field'] ) ) {
			return;
		}

		if ( ! wp_verify_nonce( $_POST['loh_network_nonce_field'], 'loh_network_settings_save' ) ) {
			wp_die( __( 'Security check failed.', 'lots-of-honey' ) );
		}

		if ( ! current_user_can( 'manage_network_options' ) ) {
			wp_die( __( 'Unauthorized action.', 'lots-of-honey' ) );
		}

		// Handle Clear Logs
		if ( isset( $_POST['loh_clear_all_logs'] ) ) {
			LOH_Database::clear_logs();
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'All network logs cleared successfully.', 'lots-of-honey' ) . '</p></div>';
			return;
		}

		// Handle Add IP to Banlist (POST Action)
		if ( isset( $_POST['loh_add_ban_ip'] ) && ! empty( $_POST['loh_ban_ip_address'] ) ) {
			$ip = sanitize_text_field( $_POST['loh_ban_ip_address'] );
			LOH_Interceptor::get_instance()->add_ip_to_banlist( $ip );
			echo '<div class="notice notice-success is-dismissible"><p>' . sprintf( esc_html__( 'IP address %s added to the banlist.', 'lots-of-honey' ), esc_html( $ip ) ) . '</p></div>';
		}

		// Save Settings
		if ( isset( $_POST['loh_save_network_settings'] ) ) {
			$enabled = isset( $_POST['loh_enabled'] ) ? '1' : '0';
			$mode = isset( $_POST['loh_mode'] ) ? sanitize_key( $_POST['loh_mode'] ) : 'block';
			$delay = isset( $_POST['loh_tarpit_delay'] ) ? absint( $_POST['loh_tarpit_delay'] ) : 10;
			$whitelist = isset( $_POST['loh_ip_whitelist'] ) ? sanitize_textarea_field( wp_unslash( $_POST['loh_ip_whitelist'] ) ) : '';
			$honeypot_sites = isset( $_POST['loh_honeypot_sites'] ) ? array_map( 'absint', $_POST['loh_honeypot_sites'] ) : array();
			$probe_patterns = isset( $_POST['loh_probe_patterns'] ) ? sanitize_textarea_field( wp_unslash( $_POST['loh_probe_patterns'] ) ) : '';

			update_site_option( 'loh_enabled', $enabled );
			update_site_option( 'loh_mode', $mode );
			update_site_option( 'loh_tarpit_delay', $delay );
			update_site_option( 'loh_ip_whitelist', $whitelist );
			update_site_option( 'loh_honeypot_sites', $honeypot_sites );
			update_site_option( 'loh_probe_patterns', $probe_patterns );

			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Network settings saved.', 'lots-of-honey' ) . '</p></div>';
		}
	}

	/**
	 * Handle settings saving & actions in Single Site Admin
	 */
	private function handle_site_actions() {
		// Clear Logs
		if ( isset( $_POST['loh_site_nonce_field'] ) && wp_verify_nonce( $_POST['loh_site_nonce_field'], 'loh_site_settings_save' ) ) {
			if ( ! current_user_can( 'manage_options' ) ) {
				wp_die( __( 'Unauthorized action.', 'lots-of-honey' ) );
			}

			if ( isset( $_POST['loh_clear_site_logs'] ) ) {
				LOH_Database::clear_logs( get_current_blog_id() );
				echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Site logs cleared successfully.', 'lots-of-honey' ) . '</p></div>';
				return;
			}
		}

		// Standard Settings save via register_setting option submission
		if ( isset( $_GET['settings-updated'] ) && 'true' === $_GET['settings-updated'] ) {
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Settings saved.', 'lots-of-honey' ) . '</p></div>';
		}
	}

	/**
	 * Render network settings page
	 */
	private function render_network_settings_tab() {
		$enabled = get_site_option( 'loh_enabled', '1' );
		$mode = get_site_option( 'loh_mode', 'tarpit' );
		$delay = get_site_option( 'loh_tarpit_delay', 10 );
		$whitelist = get_site_option( 'loh_ip_whitelist', '' );
		$honeypot_sites = get_site_option( 'loh_honeypot_sites', array() );

		if ( ! is_array( $honeypot_sites ) ) {
			$honeypot_sites = array();
		}

		$sites = get_sites( array( 'number' => 200 ) );
		?>
		<form method="post" action="">
			<?php wp_nonce_field( 'loh_network_settings_save', 'loh_network_nonce_field' ); ?>

			<div class="loh-card">
				<h3><?php esc_html_e( 'General Network Status', 'lots-of-honey' ); ?></h3>
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><label for="loh_enabled"><?php esc_html_e( 'Enable Honeypot Actions', 'lots-of-honey' ); ?></label></th>
						<td>
							<label class="loh-switch">
								<input type="checkbox" id="loh_enabled" name="loh_enabled" value="1" <?php checked( $enabled, '1' ); ?>>
								<span class="loh-slider"></span>
							</label>
							<p class="description"><?php esc_html_e( 'Globally toggle whether honeypot traps and blocks are enabled on designated sites.', 'lots-of-honey' ); ?></p>
						</td>
					</tr>
				</table>
			</div>

			<div class="loh-card">
				<h3><?php esc_html_e( 'Honeypot Trigger Action', 'lots-of-honey' ); ?></h3>
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><?php esc_html_e( 'Interception Mode', 'lots-of-honey' ); ?></th>
						<td>
							<fieldset>
								<label class="loh-radio-label">
									<input type="radio" name="loh_mode" value="block" <?php checked( $mode, 'block' ); ?>>
									<span><strong><?php esc_html_e( 'Block (403 Forbidden)', 'lots-of-honey' ); ?></strong> &mdash; <?php esc_html_e( 'Serve a standard 403 error page to immediately drop connection.', 'lots-of-honey' ); ?></span>
								</label><br><br>

								<label class="loh-radio-label">
									<input type="radio" name="loh_mode" value="tarpit" <?php checked( $mode, 'tarpit' ); ?>>
									<span><strong><?php esc_html_e( 'Tarpit (Connection Delay)', 'lots-of-honey' ); ?></strong> &mdash; <?php esc_html_e( 'Artificially delay the response by sleeping the thread, slowly exhausting bot/scanner resources.', 'lots-of-honey' ); ?></span>
								</label><br><br>

								<label class="loh-radio-label">
									<input type="radio" name="loh_mode" value="fake_login" <?php checked( $mode, 'fake_login' ); ?>>
									<span><strong><?php esc_html_e( 'Fake WordPress Login', 'lots-of-honey' ); ?></strong> &mdash; <?php esc_html_e( 'Display a replica wp-login.php that records credential attempts but always fails.', 'lots-of-honey' ); ?></span>
								</label><br><br>

								<label class="loh-radio-label">
									<input type="radio" name="loh_mode" value="fake_404" <?php checked( $mode, 'fake_404' ); ?>>
									<span><strong><?php esc_html_e( 'Fake 404 Page', 'lots-of-honey' ); ?></strong> &mdash; <?php esc_html_e( 'Serve a plain Apache/Nginx looking 404 page to make it seem like the site is empty.', 'lots-of-honey' ); ?></span>
								</label>
							</fieldset>
						</td>
					</tr>
					<tr class="loh-tarpit-row" style="<?php echo 'tarpit' === $mode ? '' : 'display:none;'; ?>">
						<th scope="row"><label for="loh_tarpit_delay"><?php esc_html_e( 'Tarpit Delay (seconds)', 'lots-of-honey' ); ?></label></th>
						<td>
							<input name="loh_tarpit_delay" type="number" id="loh_tarpit_delay" value="<?php echo esc_attr( $delay ); ?>" class="small-text" min="1" max="60" />
							<span class="description"><?php esc_html_e( 'How many seconds to delay the response before completing execution (1-60s).', 'lots-of-honey' ); ?></span>
						</td>
					</tr>
				</table>
			</div>

			<div class="loh-card">
				<h3><?php esc_html_e( 'Global IP Whitelist', 'lots-of-honey' ); ?></h3>
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><label for="loh_ip_whitelist"><?php esc_html_e( 'Whitelisted IP Addresses', 'lots-of-honey' ); ?></label></th>
						<td>
							<textarea name="loh_ip_whitelist" id="loh_ip_whitelist" rows="5" cols="50" class="large-text code" placeholder="192.168.1.1&#10;10.0.0.0/24"><?php echo esc_textarea( $whitelist ); ?></textarea>
							<p class="description"><?php esc_html_e( 'Enter IP addresses or CIDR ranges to bypass honeypot interception (one per line). Your current IP: ', 'lots-of-honey' ); ?><strong><?php echo esc_html( LOH_Interceptor::get_instance()->get_client_ip() ); ?></strong></p>
						</td>
					</tr>
				</table>
			</div>

			<div class="loh-card">
				<h3><?php esc_html_e( 'Vulnerability Probe Patterns', 'lots-of-honey' ); ?></h3>
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><label for="loh_probe_patterns"><?php esc_html_e( 'Probe URL Patterns', 'lots-of-honey' ); ?></label></th>
						<td>
							<?php $probe_patterns = get_site_option( 'loh_probe_patterns', "wp-config.php\n.env\nxmlrpc.php\nphpmyadmin\nsetup.cgi\n.git\n/etc/passwd" ); ?>
							<textarea name="loh_probe_patterns" id="loh_probe_patterns" rows="5" cols="50" class="large-text code"><?php echo esc_textarea( $probe_patterns ); ?></textarea>
							<p class="description"><?php esc_html_e( 'Enter request path patterns or substrings to block and permanently ban network-wide (one per line). If anyone hits these paths on any honeypot site, they are added to the banlist.', 'lots-of-honey' ); ?></p>
						</td>
					</tr>
				</table>
			</div>

			<div class="loh-card">
				<h3><?php esc_html_e( 'Designate Honeypot Sites', 'lots-of-honey' ); ?></h3>
				<p class="description"><?php esc_html_e( 'Select the sites on the network that should act as honeypots. WARNING: Once designated, regular visitors to these sites will be blocked/redirected.', 'lots-of-honey' ); ?></p>
				<table class="wp-list-table widefat fixed striped" style="margin-top: 15px;">
					<thead>
						<tr>
							<td class="manage-column column-cb check-column" style="width: 3em;"><input type="checkbox" id="loh-check-all-sites"></td>
							<th scope="col" class="manage-column"><?php esc_html_e( 'Site Name', 'lots-of-honey' ); ?></th>
							<th scope="col" class="manage-column"><?php esc_html_e( 'Site Domain & Path', 'lots-of-honey' ); ?></th>
							<th scope="col" class="manage-column" style="width: 8em;"><?php esc_html_e( 'Site ID', 'lots-of-honey' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<?php if ( ! empty( $sites ) ) : ?>
							<?php foreach ( $sites as $site ) : ?>
								<?php
								$details = get_blog_details( $site->blog_id );
								$is_main = is_main_site( $site->blog_id );
								?>
								<tr>
									<th scope="row" class="check-column">
										<input type="checkbox" name="loh_honeypot_sites[]" value="<?php echo esc_attr( $site->blog_id ); ?>" <?php checked( in_array( (int) $site->blog_id, $honeypot_sites, true ), true ); ?> <?php disabled( $is_main ); ?>>
									</th>
									<td>
										<strong><?php echo esc_html( $details->blogname ); ?></strong>
										<?php if ( $is_main ) : ?>
											<span class="loh-badge-warning" style="margin-left:5px; font-size:10px;"><?php esc_html_e( 'Main Site (Cannot be honeypot)', 'lots-of-honey' ); ?></span>
										<?php endif; ?>
									</td>
									<td>
										<a href="<?php echo esc_url( $details->siteurl ); ?>" target="_blank"><?php echo esc_html( $details->domain . $details->path ); ?></a>
									</td>
									<td><code><?php echo esc_html( $site->blog_id ); ?></code></td>
								</tr>
							<?php endforeach; ?>
						<?php else : ?>
							<tr>
								<td colspan="4"><?php esc_html_e( 'No network sites found.', 'lots-of-honey' ); ?></td>
							</tr>
						<?php endif; ?>
					</tbody>
				</table>
			</div>

			<p class="submit">
				<input type="submit" name="loh_save_network_settings" id="submit" class="button button-primary button-large" value="<?php esc_attr_e( 'Save Network Settings', 'lots-of-honey' ); ?>">
			</p>
		</form>
		<?php
	}

	/**
	 * Render network banlist management page
	 */
	private function render_network_banlist_tab() {
		$ban_list = get_site_option( 'loh_ban_list', array() );
		if ( ! is_array( $ban_list ) ) {
			$ban_list = array();
		}
		?>
		<div class="loh-card">
			<h3><?php esc_html_e( 'Manually Ban an IP Address', 'lots-of-honey' ); ?></h3>
			<p class="description"><?php esc_html_e( 'Manually add an IP address to the network-wide permanent block list.', 'lots-of-honey' ); ?></p>
			<form method="post" action="" style="margin-top: 15px; display: flex; gap: 10px; align-items: center;">
				<?php wp_nonce_field( 'loh_network_settings_save', 'loh_network_nonce_field' ); ?>
				<input type="text" name="loh_ban_ip_address" class="regular-text code" placeholder="e.g. 192.168.1.100" required style="margin: 0; padding: 6px 10px;">
				<input type="submit" name="loh_add_ban_ip" class="button button-primary" value="<?php esc_attr_e( 'Add to Banlist', 'lots-of-honey' ); ?>" style="margin: 0;">
			</form>
		</div>

		<div class="loh-card">
			<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
				<h3 style="margin: 0;"><?php esc_html_e( 'Network-Wide Banned IPs', 'lots-of-honey' ); ?></h3>
				<a href="?page=lots-of-honey-network&action=export_banlist" class="button button-secondary">
					<span class="dashicons dashicons-download" style="vertical-align: text-bottom; margin-top: 3px;"></span> <?php esc_html_e( 'Export Banlist (.txt)', 'lots-of-honey' ); ?>
				</a>
			</div>

			<table class="wp-list-table widefat fixed striped">
				<thead>
					<tr>
						<th scope="col"><?php esc_html_e( 'IP Address', 'lots-of-honey' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Date & Time Banned', 'lots-of-honey' ); ?></th>
						<th scope="col" style="width: 10em;"><?php esc_html_e( 'Actions', 'lots-of-honey' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<?php if ( ! empty( $ban_list ) ) : ?>
						<?php foreach ( $ban_list as $ip => $timestamp ) : ?>
							<?php
							$unban_url = wp_nonce_url(
								add_query_arg(
									array(
										'action' => 'unban_ip',
										'ip'     => $ip,
									),
									'?page=lots-of-honey-network&tab=banlist'
								),
								'loh_unban_ip_nonce'
							);
							?>
							<tr>
								<td><strong><code><?php echo esc_html( $ip ); ?></code></strong></td>
								<td><?php echo esc_html( date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $timestamp ) ); ?></td>
								<td>
									<a href="<?php echo esc_url( $unban_url ); ?>" class="button button-link delete" style="color: #dc3545; text-decoration: none;">
										<span class="dashicons dashicons-dismiss" style="vertical-align: text-bottom; margin-top: 3px;"></span> <?php esc_html_e( 'Unban IP', 'lots-of-honey' ); ?>
									</a>
								</td>
							</tr>
						<?php endforeach; ?>
					<?php else : ?>
						<tr>
							<td colspan="3"><?php esc_html_e( 'No IP addresses are currently banned.', 'lots-of-honey' ); ?></td>
						</tr>
					<?php endif; ?>
				</tbody>
			</table>
		</div>

		<div class="loh-card">
			<h3><?php esc_html_e( 'Firewall Synchronization Setup (No WP-CLI Required)', 'lots-of-honey' ); ?></h3>
			<p class="description"><?php esc_html_e( 'To block banned IPs at the server level (UFW, iptables, firewalld, or hosts.deny) and protect the entire network with zero overhead, set up a host-level cron job using our included secure script.', 'lots-of-honey' ); ?></p>
			
			<div style="margin-top: 15px; background: #f8fafc; border: 1px solid #e2e8f0; padding: 15px; border-radius: 6px;">
				<h4 style="margin: 0 0 10px 0; font-weight: bold;"><?php esc_html_e( '1. Copy the script to your server:', 'lots-of-honey' ); ?></h4>
				<pre class="code-block" style="margin-bottom: 20px;"><code>sudo cp <?php echo esc_html( LOH_PLUGIN_DIR . 'bin/sync-honey-banlist.sh' ); ?> /usr/local/bin/sync-honey-banlist.sh
sudo chmod +x /usr/local/bin/sync-honey-banlist.sh</code></pre>
				
				<h4 style="margin: 0 0 10px 0; font-weight: bold;"><?php esc_html_e( '2. Configure the script variables:', 'lots-of-honey' ); ?></h4>
				<p class="description" style="margin-bottom: 10px;"><?php esc_html_e( 'Open the script in your editor and customize the variables:', 'lots-of-honey' ); ?></p>
				<pre class="code-block" style="margin-bottom: 20px;"><code>WP_PATH="<?php echo esc_html( ABSPATH ); ?>"
WP_USER="www-data"  # (Or your web server user, e.g. nginx, apache)
FIREWALL_TYPE="ufw" # (Options: ufw, iptables, firewalld, hosts.deny)</code></pre>
				
				<h4 style="margin: 0 0 10px 0; font-weight: bold;"><?php esc_html_e( '3. Add a root cron job:', 'lots-of-honey' ); ?></h4>
				<p class="description" style="margin-bottom: 10px;"><?php esc_html_e( 'Run `sudo crontab -e` and append the following line to run the sync every minute:', 'lots-of-honey' ); ?></p>
				<pre class="code-block" style="margin-bottom: 5px;"><code>* * * * * /usr/local/bin/sync-honey-banlist.sh >/dev/null 2>&1</code></pre>
			</div>
		</div>
		<?php
	}

	/**
	 * Render single-site settings page
	 */
	private function render_site_settings_tab() {
		$enabled = get_option( 'loh_enabled', '1' );
		$mode = get_option( 'loh_mode', 'tarpit' );
		$delay = get_option( 'loh_tarpit_delay', 10 );
		$whitelist = get_option( 'loh_ip_whitelist', '' );
		?>
		<form method="post" action="options.php">
			<?php settings_fields( 'loh_settings_group' ); ?>
			<?php do_settings_sections( 'loh_settings_group' ); ?>

			<div class="loh-card">
				<h3><?php esc_html_e( 'Honeypot Activation', 'lots-of-honey' ); ?></h3>
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><label for="loh_enabled"><?php esc_html_e( 'Enable Honeypot', 'lots-of-honey' ); ?></label></th>
						<td>
							<label class="loh-switch">
								<input type="checkbox" id="loh_enabled" name="loh_enabled" value="1" <?php checked( $enabled, '1' ); ?>>
								<span class="loh-slider"></span>
							</label>
							<p class="description"><?php esc_html_e( 'Toggle whether honeypot traps and blocks are enabled on this site.', 'lots-of-honey' ); ?></p>
						</td>
					</tr>
				</table>
			</div>

			<div class="loh-card">
				<h3><?php esc_html_e( 'Honeypot Trigger Action', 'lots-of-honey' ); ?></h3>
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><?php esc_html_e( 'Interception Mode', 'lots-of-honey' ); ?></th>
						<td>
							<fieldset>
								<label class="loh-radio-label">
									<input type="radio" name="loh_mode" value="block" <?php checked( $mode, 'block' ); ?>>
									<span><strong><?php esc_html_e( 'Block (403 Forbidden)', 'lots-of-honey' ); ?></strong> &mdash; <?php esc_html_e( 'Serve a standard 403 error page to immediately drop connection.', 'lots-of-honey' ); ?></span>
								</label><br><br>

								<label class="loh-radio-label">
									<input type="radio" name="loh_mode" value="tarpit" <?php checked( $mode, 'tarpit' ); ?>>
									<span><strong><?php esc_html_e( 'Tarpit (Connection Delay)', 'lots-of-honey' ); ?></strong> &mdash; <?php esc_html_e( 'Artificially delay the response by sleeping the thread, slowly exhausting bot/scanner resources.', 'lots-of-honey' ); ?></span>
								</label><br><br>

								<label class="loh-radio-label">
									<input type="radio" name="loh_mode" value="fake_login" <?php checked( $mode, 'fake_login' ); ?>>
									<span><strong><?php esc_html_e( 'Fake WordPress Login', 'lots-of-honey' ); ?></strong> &mdash; <?php esc_html_e( 'Display a replica wp-login.php that records credential attempts but always fails.', 'lots-of-honey' ); ?></span>
								</label><br><br>

								<label class="loh-radio-label">
									<input type="radio" name="loh_mode" value="fake_404" <?php checked( $mode, 'fake_404' ); ?>>
									<span><strong><?php esc_html_e( 'Fake 404 Page', 'lots-of-honey' ); ?></strong> &mdash; <?php esc_html_e( 'Serve a plain Apache/Nginx looking 404 page to make it seem like the site is empty.', 'lots-of-honey' ); ?></span>
								</label>
							</fieldset>
						</td>
					</tr>
					<tr class="loh-tarpit-row" style="<?php echo 'tarpit' === $mode ? '' : 'display:none;'; ?>">
						<th scope="row"><label for="loh_tarpit_delay"><?php esc_html_e( 'Tarpit Delay (seconds)', 'lots-of-honey' ); ?></label></th>
						<td>
							<input name="loh_tarpit_delay" type="number" id="loh_tarpit_delay" value="<?php echo esc_attr( $delay ); ?>" class="small-text" min="1" max="60" />
							<span class="description"><?php esc_html_e( 'How many seconds to delay the response before completing execution (1-60s).', 'lots-of-honey' ); ?></span>
						</td>
					</tr>
				</table>
			</div>

			<div class="loh-card">
				<h3><?php esc_html_e( 'IP Whitelist', 'lots-of-honey' ); ?></h3>
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><label for="loh_ip_whitelist"><?php esc_html_e( 'Whitelisted IP Addresses', 'lots-of-honey' ); ?></label></th>
						<td>
							<textarea name="loh_ip_whitelist" id="loh_ip_whitelist" rows="5" cols="50" class="large-text code" placeholder="192.168.1.1&#10;10.0.0.0/24"><?php echo esc_textarea( $whitelist ); ?></textarea>
							<p class="description"><?php esc_html_e( 'Enter IP addresses or CIDR ranges to bypass honeypot interception (one per line). Your current IP: ', 'lots-of-honey' ); ?><strong><?php echo esc_html( LOH_Interceptor::get_instance()->get_client_ip() ); ?></strong></p>
						</td>
					</tr>
				</table>
			</div>

			<?php submit_button( __( 'Save Settings', 'lots-of-honey' ) ); ?>
		</form>
		<?php
	}

	/**
	 * Render Captured Logs
	 *
	 * @param int|null $site_id Site ID filter.
	 */
	private function render_logs_tab( $site_id = null ) {
		$paged = isset( $_GET['paged'] ) ? absint( $_GET['paged'] ) : 1;
		$limit = 25;
		$offset = ( $paged - 1 ) * $limit;

		$logs = LOH_Database::get_logs( $limit, $offset, $site_id );
		$total_logs = LOH_Database::get_logs_count( $site_id );
		$total_pages = ceil( $total_logs / $limit );

		$page_url = is_network_admin() ? 'lots-of-honey-network' : 'lots-of-honey';
		?>
		<div class="loh-log-actions">
			<div class="loh-counter">
				<span class="loh-badge"><?php echo esc_html( $total_logs ); ?></span> <?php esc_html_e( 'total traps recorded.', 'lots-of-honey' ); ?>
			</div>
			<form method="post" action="">
				<?php
				if ( is_network_admin() ) {
					wp_nonce_field( 'loh_network_settings_save', 'loh_network_nonce_field' );
					?>
					<input type="submit" name="loh_clear_all_logs" class="button button-secondary" onclick="return confirm('<?php esc_attr_e( 'Are you sure you want to permanently clear all network logs?', 'lots-of-honey' ); ?>')" value="<?php esc_attr_e( 'Clear All Network Logs', 'lots-of-honey' ); ?>">
					<?php
				} else {
					wp_nonce_field( 'loh_site_settings_save', 'loh_site_nonce_field' );
					?>
					<input type="submit" name="loh_clear_site_logs" class="button button-secondary" onclick="return confirm('<?php esc_attr_e( 'Are you sure you want to permanently clear all logs for this site?', 'lots-of-honey' ); ?>')" value="<?php esc_attr_e( 'Clear Site Logs', 'lots-of-honey' ); ?>">
					<?php
				}
				?>
			</form>
		</div>

		<table class="wp-list-table widefat fixed striped table-view-list loh-logs-table">
			<thead>
				<tr>
					<th scope="col" style="width: 140px;"><?php esc_html_e( 'Timestamp', 'lots-of-honey' ); ?></th>
					<?php if ( is_network_admin() ) : ?>
						<th scope="col" style="width: 120px;"><?php esc_html_e( 'Site', 'lots-of-honey' ); ?></th>
					<?php endif; ?>
					<th scope="col" style="width: 130px;"><?php esc_html_e( 'IP Address', 'lots-of-honey' ); ?></th>
					<th scope="col" style="width: 80px;"><?php esc_html_e( 'Method', 'lots-of-honey' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Request URI', 'lots-of-honey' ); ?></th>
					<th scope="col" style="width: 120px;"><?php esc_html_e( 'Action Taken', 'lots-of-honey' ); ?></th>
					<th scope="col" style="width: 80px; text-align: center;"><?php esc_html_e( 'Details', 'lots-of-honey' ); ?></th>
				</tr>
			</thead>
			<tbody>
				<?php if ( ! empty( $logs ) ) : ?>
					<?php foreach ( $logs as $log ) : ?>
						<?php
						$badge_class = 'loh-badge-secondary';
						if ( 'block' === $log['action_taken'] ) {
							$badge_class = 'loh-badge-danger';
						} elseif ( 'tarpit' === $log['action_taken'] ) {
							$badge_class = 'loh-badge-warning';
						} elseif ( 'fake_login' === $log['action_taken'] ) {
							$badge_class = 'loh-badge-primary';
						}

						$site_name = '';
						if ( is_network_admin() ) {
							$blog_details = get_blog_details( $log['site_id'] );
							$site_name = $blog_details ? $blog_details->blogname : 'ID ' . $log['site_id'];
						}
						?>
						<tr id="loh-log-row-<?php echo esc_attr( $log['id'] ); ?>">
							<td><code><?php echo esc_html( $log['timestamp'] ); ?></code></td>
							<?php if ( is_network_admin() ) : ?>
								<td><strong><?php echo esc_html( $site_name ); ?></strong></td>
							<?php endif; ?>
							<td>
								<a href="https://ipinfo.io/<?php echo esc_attr( $log['ip_address'] ); ?>" target="_blank">
									<code><?php echo esc_html( $log['ip_address'] ); ?></code>
								</a>
							</td>
							<td><code><?php echo esc_html( $log['request_method'] ); ?></code></td>
							<td class="loh-uri-cell" title="<?php echo esc_attr( $log['request_uri'] ); ?>">
								<code><?php echo esc_html( $log['request_uri'] ); ?></code>
							</td>
							<td>
								<span class="<?php echo esc_attr( $badge_class ); ?>">
									<?php echo esc_html( strtoupper( $log['action_taken'] ) ); ?>
								</span>
							</td>
							<td style="text-align: center;">
								<button class="button button-small loh-view-details" data-id="<?php echo esc_attr( $log['id'] ); ?>">
									<span class="dashicons dashicons-visibility" style="vertical-align: middle; margin-top: -2px;"></span>
								</button>
								<div class="loh-details-data" id="loh-details-data-<?php echo esc_attr( $log['id'] ); ?>" style="display:none;">
									<div class="loh-details-section">
										<h4><?php esc_html_e( 'User Agent', 'lots-of-honey' ); ?></h4>
										<p class="code-block"><code><?php echo esc_html( $log['user_agent'] ); ?></code></p>
									</div>
									<div class="loh-details-section">
										<h4><?php esc_html_e( 'Headers', 'lots-of-honey' ); ?></h4>
										<pre class="code-block"><code><?php echo esc_html( print_r( json_decode( $log['headers'], true ), true ) ); ?></code></pre>
									</div>
									<div class="loh-details-section">
										<h4><?php esc_html_e( 'Payload', 'lots-of-honey' ); ?></h4>
										<pre class="code-block"><code><?php echo esc_html( print_r( json_decode( $log['payload'], true ), true ) ); ?></code></pre>
									</div>
								</div>
							</td>
						</tr>
					<?php endforeach; ?>
				<?php else : ?>
					<tr>
						<td colspan="<?php echo is_network_admin() ? 7 : 6; ?>"><?php esc_html_e( 'No traps logged yet. Happy waiting!', 'lots-of-honey' ); ?></td>
					</tr>
				<?php endif; ?>
			</tbody>
		</table>

		<?php if ( $total_pages > 1 ) : ?>
			<div class="tablenav">
				<div class="tablenav-pages">
					<?php
					echo paginate_links( array(
						'base'      => add_query_arg( 'paged', '%#%' ),
						'format'    => '',
						'prev_text' => __( '&laquo; Prev', 'lots-of-honey' ),
						'next_text' => __( 'Next &raquo;', 'lots-of-honey' ),
						'total'     => $total_pages,
						'current'   => $paged,
					) );
					?>
				</div>
			</div>
		<?php endif; ?>

		<!-- Detail Modal Structure -->
		<div id="loh-modal" class="loh-modal" style="display:none;">
			<div class="loh-modal-content">
				<div class="loh-modal-header">
					<h3><?php esc_html_e( 'Trap Entry Details', 'lots-of-honey' ); ?></h3>
					<span class="loh-modal-close">&times;</span>
				</div>
				<div class="loh-modal-body">
					<!-- Dynamically injected -->
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * CSS Styles for premium look
	 */
	private function render_admin_styles() {
		?>
		<style>
			.loh-admin-wrap { max-width: 1200px; margin-top: 20px; }
			.loh-header { display: flex; justify-content: space-between; align-items: center; background: linear-gradient(135deg, #d97706 0%, #f59e0b 100%); color: #fff; padding: 25px 30px; border-radius: 10px; margin-bottom: 20px; box-shadow: 0 4px 15px rgba(217, 119, 6, 0.15); }
			.loh-logo { display: flex; align-items: center; }
			.loh-logo .dashicons { font-size: 36px; width: 36px; height: 36px; margin-right: 15px; }
			.loh-logo h1 { color: #fff; font-size: 24px; font-weight: 700; margin: 0; padding: 0; line-height: 1; text-shadow: 0 2px 4px rgba(0,0,0,0.1); }
			.loh-version { background: rgba(255,255,255,0.2); padding: 5px 12px; border-radius: 20px; font-weight: 600; font-size: 13px; letter-spacing: 0.5px; }
			
			.nav-tab-wrapper { border-bottom: 1px solid #e2e8f0; margin-bottom: 25px; padding-left: 5px; }
			.nav-tab { display: inline-flex; align-items: center; border: none !important; background: transparent; padding: 10px 20px !important; font-size: 14px !important; font-weight: 600 !important; color: #64748b !important; border-bottom: 2px solid transparent !important; margin: 0 5px -1px 0 !important; transition: all 0.2s ease; }
			.nav-tab:hover { color: #d97706 !important; border-bottom: 2px solid #f59e0b !important; background: transparent !important; }
			.nav-tab-active { color: #d97706 !important; border-bottom: 2px solid #d97706 !important; background: transparent !important; }
			.nav-tab .dashicons { margin-right: 6px; font-size: 18px; width: 18px; height: 18px; }

			.loh-card { background: #fff; border-radius: 8px; border: 1px solid #e2e8f0; padding: 25px; margin-bottom: 25px; box-shadow: 0 1px 3px rgba(0,0,0,0.02); transition: transform 0.2s ease, box-shadow 0.2s ease; }
			.loh-card:hover { box-shadow: 0 4px 10px rgba(0,0,0,0.04); }
			.loh-card h3 { font-size: 18px; font-weight: 700; color: #1e293b; margin-top: 0; margin-bottom: 15px; border-left: 4px solid #d97706; padding-left: 10px; }
			
			/* Toggles / Switch */
			.loh-switch { position: relative; display: inline-block; width: 50px; height: 26px; }
			.loh-switch input { opacity: 0; width: 0; height: 0; }
			.loh-slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: #cbd5e1; transition: .3s; border-radius: 34px; }
			.loh-slider:before { position: absolute; content: ""; height: 18px; width: 18px; left: 4px; bottom: 4px; background-color: white; transition: .3s; border-radius: 50%; }
			input:checked + .loh-slider { background-color: #d97706; }
			input:focus + .loh-slider { box-shadow: 0 0 1px #d97706; }
			input:checked + .loh-slider:before { transform: translateX(24px); }

			.loh-radio-label { display: inline-flex; align-items: flex-start; cursor: pointer; }
			.loh-radio-label input { margin-top: 3px !important; margin-right: 10px !important; }
			.loh-radio-label span strong { color: #1e293b; }
			
			.loh-banner { display: flex; align-items: flex-start; padding: 15px 20px; border-radius: 8px; margin-bottom: 25px; }
			.loh-banner-info { background: #eff6ff; border: 1px solid #bfdbfe; color: #1e3a8a; }
			.loh-banner-info .dashicons { font-size: 24px; width: 24px; height: 24px; margin-right: 12px; color: #3b82f6; }
			.loh-banner-info p { margin: 5px 0 0 0; font-size: 13px; color: #1e40af; }

			/* Badges */
			.loh-badge-secondary { background-color: #f1f5f9; color: #475569; padding: 4px 8px; border-radius: 12px; font-size: 11px; font-weight: 700; display: inline-block; }
			.loh-badge-danger { background-color: #fee2e2; color: #991b1b; padding: 4px 8px; border-radius: 12px; font-size: 11px; font-weight: 700; display: inline-block; }
			.loh-badge-warning { background-color: #fef3c7; color: #92400e; padding: 4px 8px; border-radius: 12px; font-size: 11px; font-weight: 700; display: inline-block; }
			.loh-badge-primary { background-color: #f3e8ff; color: #6b21a8; padding: 4px 8px; border-radius: 12px; font-size: 11px; font-weight: 700; display: inline-block; }
			.loh-badge { background: #d97706; color: #fff; padding: 2px 8px; border-radius: 20px; font-size: 12px; font-weight: 700; }

			.loh-log-actions { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }
			.loh-counter { font-size: 14px; color: #475569; font-weight: 600; }

			/* Logs Table */
			.loh-logs-table { border-radius: 8px; border: 1px solid #e2e8f0 !important; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.01); }
			.loh-logs-table th { background: #f8fafc; font-weight: 700 !important; color: #334155; padding: 12px 10px !important; }
			.loh-logs-table td { padding: 12px 10px !important; vertical-align: middle !important; }
			.loh-uri-cell { max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

			/* Modal */
			.loh-modal { position: fixed; z-index: 100000; left: 0; top: 0; width: 100%; height: 100%; overflow: auto; background-color: rgba(15, 23, 42, 0.6); backdrop-filter: blur(4px); display: flex; align-items: center; justify-content: center; }
			.loh-modal-content { background-color: #fff; border-radius: 12px; width: 70%; max-width: 800px; box-shadow: 0 20px 25px -5px rgba(0,0,0,0.1), 0 10px 10px -5px rgba(0,0,0,0.04); overflow: hidden; display: flex; flex-direction: column; max-height: 85vh; animation: lohModalOpen 0.2s cubic-bezier(0.16, 1, 0.3, 1); }
			@keyframes lohModalOpen { from { opacity: 0; transform: scale(0.95) translateY(10px); } to { opacity: 1; transform: scale(1) translateY(0); } }
			.loh-modal-header { display: flex; justify-content: space-between; align-items: center; padding: 15px 25px; border-bottom: 1px solid #f1f5f9; background: #f8fafc; }
			.loh-modal-header h3 { margin: 0; font-size: 16px; font-weight: 700; color: #1e293b; }
			.loh-modal-close { font-size: 28px; font-weight: bold; color: #94a3b8; cursor: pointer; transition: color 0.1s ease; }
			.loh-modal-close:hover { color: #475569; }
			.loh-modal-body { padding: 25px; overflow-y: auto; }
			.loh-details-section { margin-bottom: 25px; }
			.loh-details-section h4 { margin-top: 0; margin-bottom: 10px; font-size: 14px; font-weight: 600; color: #475569; border-bottom: 1px solid #e2e8f0; padding-bottom: 5px; }
			.code-block { background: #0f172a; color: #38bdf8; padding: 15px; border-radius: 6px; overflow-x: auto; font-family: monospace; font-size: 13px; line-height: 1.5; margin: 0; }
			pre.code-block code { color: #f8fafc; }
		</style>
		<?php
	}

	/**
	 * Scripts for Modal functionality and UX interactions
	 */
	private function render_admin_scripts() {
		?>
		<script>
			jQuery(document).ready(function($) {
				// Toggle Tarpit Row based on mode selection
				$('input[name="loh_mode"]').on('change', function() {
					if ($(this).val() === 'tarpit') {
						$('.loh-tarpit-row').fadeIn(200);
					} else {
						$('.loh-tarpit-row').fadeOut(200);
					}
				});

				// Check All Sites toggle
				$('#loh-check-all-sites').on('change', function() {
					var isChecked = $(this).prop('checked');
					$('input[name="loh_honeypot_sites[]"]:not(:disabled)').prop('checked', isChecked);
				});

				// Modal logic
				var $modal = $('#loh-modal');
				var $modalBody = $('.loh-modal-body');

				$('.loh-view-details').on('click', function(e) {
					e.preventDefault();
					var id = $(this).data('id');
					var detailsHtml = $('#loh-details-data-' + id).html();
					$modalBody.html(detailsHtml);
					$modal.css('display', 'flex');
				});

				$('.loh-modal-close').on('click', function() {
					$modal.hide();
					$modalBody.html('');
				});

				$(window).on('click', function(e) {
					if ($(e.target).is($modal)) {
						$modal.hide();
						$modalBody.html('');
					}
				});
			});
		</script>
		<?php
	}
}
