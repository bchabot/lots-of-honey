<?php
/**
 * Plugin Name:       Lots of Honey
 * Plugin URI:        https://github.com/bchabot/lots-of-honey
 * Description:       Converts a designated site on a WordPress Multisite network (or a single site installation) into a highly configurable honeypot to capture, log, and block malicious traffic/bots.
 * Version:           1.0.0
 * Author:            Antigravity
 * Author URI:        https://github.com/bchabot
 * License:           GPLv2 or later
 * Text Domain:       lots-of-honey
 * Requires at least: 5.9
 * Requires PHP:      7.4
 */

// If this file is called directly, abort.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Define plugin-wide constants
 */
define( 'LOH_VERSION', '1.0.0' );
define( 'LOH_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'LOH_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
define( 'LOH_PLUGIN_BASENAME', plugin_basename( __FILE__ ) );

/**
 * Autoload classes or include them
 */
require_once LOH_PLUGIN_DIR . 'includes/class-loh-database.php';
require_once LOH_PLUGIN_DIR . 'includes/class-loh-activator.php';
require_once LOH_PLUGIN_DIR . 'includes/class-loh-deactivator.php';
require_once LOH_PLUGIN_DIR . 'includes/class-loh-interceptor.php';
require_once LOH_PLUGIN_DIR . 'includes/class-loh-admin.php';

/**
 * Main Plugin Class
 */
class Lots_Of_Honey {

	/**
	 * Singleton instance of the class
	 *
	 * @var Lots_Of_Honey
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
		$this->init_hooks();
	}

	/**
	 * Register core hooks
	 */
	private function init_hooks() {
		// Run interceptor as early as possible
		add_action( 'muplugins_loaded', array( $this, 'run_interceptor' ), 1 );
		add_action( 'plugins_loaded', array( $this, 'run_interceptor' ), 1 );

		// Load localization
		add_action( 'init', array( $this, 'load_textdomain' ), 11 );

		// Initialize admin UI
		if ( is_admin() ) {
			LOH_Admin::get_instance();
		}
	}

	/**
	 * Run the Interceptor to catch honeypot requests
	 */
	public function run_interceptor() {
		// Ensure it only runs once per request lifecycle
		static $interceptor_run = false;
		if ( $interceptor_run ) {
			return;
		}
		$interceptor_run = true;

		$interceptor = LOH_Interceptor::get_instance();
		$interceptor->maybe_block_banned_ip();
		$interceptor->maybe_intercept();
	}

	/**
	 * Load translation files
	 */
	public function load_textdomain() {
		load_plugin_textdomain( 'lots-of-honey', false, dirname( LOH_PLUGIN_BASENAME ) . '/languages' );
	}
}

/**
 * Register Activation and Deactivation Hooks
 */
register_activation_hook( __FILE__, 'loh_activate' );
register_deactivation_hook( __FILE__, 'loh_deactivate' );

/**
 * Activation Callback
 *
 * @param bool $network_wide Whether the plugin is network activated.
 */
function loh_activate( $network_wide ) {
	LOH_Activator::activate( $network_wide );
}

/**
 * Deactivation Callback
 *
 * @param bool $network_wide Whether the plugin is network deactivated.
 */
function loh_deactivate( $network_wide ) {
	LOH_Deactivator::deactivate( $network_wide );
}

/**
 * Instantiate the plugin
 */
function run_lots_of_honey() {
	return Lots_Of_Honey::get_instance();
}
run_lots_of_honey();

/**
 * Register custom WP-CLI commands for secure firewall integration
 */
if ( defined( 'WP_CLI' ) && WP_CLI ) {
	class LOH_CLI_Command {
		/**
		 * Prints the active permanent banlist (one IP or CIDR per line).
		 *
		 * ## EXAMPLES
		 *
		 *     wp lots-of-honey banlist
		 */
		public function banlist( $args, $assoc_args ) {
			$is_network = is_multisite();
			$ban_list = $is_network ? get_site_option( 'loh_ban_list', array() ) : get_option( 'loh_ban_list', array() );
			if ( ! is_array( $ban_list ) ) {
				$ban_list = array();
			}
			foreach ( $ban_list as $ip_or_cidr => $time ) {
				WP_CLI::line( $ip_or_cidr );
			}
		}
	}
	WP_CLI::add_command( 'lots-of-honey', 'LOH_CLI_Command' );
}
