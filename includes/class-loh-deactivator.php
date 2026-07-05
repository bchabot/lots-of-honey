<?php
/**
 * Fired during plugin deactivation.
 *
 * @package Lots_Of_Honey
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class LOH_Deactivator {

	/**
	 * Run the deactivation routines.
	 *
	 * @param bool $network_wide Whether the plugin is network deactivated.
	 */
	public static function deactivate( $network_wide ) {
		// Clean up transients or temporary settings if any.
		// We do NOT delete database tables or configuration options here.
		// Database and option cleanup is handled solely in uninstall.php.
	}
}
