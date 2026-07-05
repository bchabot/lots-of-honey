<?php
/**
 * Fired during plugin activation.
 *
 * @package Lots_Of_Honey
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class LOH_Activator {

	/**
	 * Run the activation routines.
	 *
	 * @param bool $network_wide Whether the plugin is network activated.
	 */
	public static function activate( $network_wide ) {
		// Set up the custom logs database table
		LOH_Database::create_table();

		// Set default options
		$default_options = array(
			'loh_enabled'        => '1',
			'loh_mode'           => 'tarpit',
			'loh_tarpit_delay'   => 10,
			'loh_ip_whitelist'   => '',
			'loh_honeypot_sites' => array(),
		);

		if ( is_multisite() && $network_wide ) {
			foreach ( $default_options as $key => $value ) {
				if ( false === get_site_option( $key ) ) {
					update_site_option( $key, $value );
				}
			}
		} else {
			foreach ( $default_options as $key => $value ) {
				if ( false === get_option( $key ) ) {
					update_option( $key, $value );
				}
			}
		}
	}
}
