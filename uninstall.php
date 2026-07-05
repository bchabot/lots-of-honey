<?php
/**
 * Fired when the plugin is uninstalled.
 *
 * @package Lots_Of_Honey
 */

// If uninstall not called from WordPress, exit.
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

require_once plugin_dir_path( __FILE__ ) . 'includes/class-loh-database.php';

// Drop the logs table
LOH_Database::drop_table();

// Delete options
$options = array(
	'loh_enabled',
	'loh_mode',
	'loh_tarpit_delay',
	'loh_ip_whitelist',
	'loh_honeypot_sites',
);

foreach ( $options as $option ) {
	delete_option( $option );
	if ( is_multisite() ) {
		delete_site_option( $option );
	}
}
