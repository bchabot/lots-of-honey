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

		$base_lists = array(
			'general' => array(
				'name'  => 'General Security Scan List',
				'terms' => ".env\n.git/\nsetup.cgi\nconfig.php.bak\nphpinfo.php\n/etc/passwd\nid_rsa\nbackup.sql\ndump.sql\ndb.sql\n_query.php\nshell.php\ncmd.php\ntest.php\nadm.php\nmysql/\nphpmyadmin/\npma/",
			),
			'wordpress' => array(
				'name'  => 'WordPress Honeypot List',
				'terms' => "wp-login.php\nwp-admin/\nxmlrpc.php\nwp-config.php\nwp-content/debug.log\nwp-links-opml.php\nwp-signup.php\nwp-register.php\nwp-mail.php",
			),
			'comprehensive' => array(
				'name'  => 'Comprehensive Scan List',
				'terms' => "joomla/\nadministrator/\nindex.php?option=com_\nwp-content/plugins/revslider/\nwp-content/plugins/duplicator/\nwp-content/plugins/wp-file-manager/\nmain.cgi\ncgi-bin/\ncgi-bin/test.cgi\nsolr/\nactuator/env\nactuator/health\nautodiscover/outlook.xml\n.well-known/security.txt\n/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
			),
		);

		// Set default options
		$default_options = array(
			'loh_enabled'        => '1',
			'loh_mode'           => 'tarpit',
			'loh_tarpit_delay'   => 10,
			'loh_ip_whitelist'   => '',
			'loh_honeypot_sites' => array(),
			'loh_ban_list'       => array(),
			'loh_bannable_lists' => $base_lists,
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
