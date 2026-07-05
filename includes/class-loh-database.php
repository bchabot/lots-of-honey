<?php
/**
 * Database operations for Lots of Honey plugin.
 *
 * @package Lots_Of_Honey
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class LOH_Database {

	/**
	 * Get the table name.
	 * We use base_prefix to have a single unified logs table even in Multisite.
	 *
	 * @return string
	 */
	public static function get_table_name() {
		global $wpdb;
		return $wpdb->base_prefix . 'lots_of_honey_logs';
	}

	/**
	 * Create the custom database table.
	 */
	public static function create_table() {
		global $wpdb;
		$table_name = self::get_table_name();
		$charset_collate = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE {$table_name} (
			id bigint(20) NOT NULL AUTO_INCREMENT,
			site_id bigint(20) NOT NULL,
			timestamp datetime NOT NULL,
			ip_address varchar(45) NOT NULL,
			request_method varchar(10) NOT NULL,
			request_uri text NOT NULL,
			user_agent text NOT NULL,
			headers longtext NOT NULL,
			payload longtext NOT NULL,
			action_taken varchar(50) NOT NULL,
			PRIMARY KEY  (id),
			KEY ip_address (ip_address(45)),
			KEY site_id (site_id)
		) $charset_collate;";

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( $sql );
	}

	/**
	 * Drop the custom database table.
	 */
	public static function drop_table() {
		global $wpdb;
		$table_name = self::get_table_name();
		$wpdb->query( "DROP TABLE IF EXISTS {$table_name}" );
	}

	/**
	 * Insert a log entry.
	 *
	 * @param string $ip           IP address.
	 * @param string $method       HTTP method.
	 * @param string $uri          Request URI.
	 * @param string $user_agent   User agent.
	 * @param array  $headers      HTTP headers.
	 * @param array  $payload      Request payload (POST/GET/etc).
	 * @param string $action_taken Action taken (block, tarpit, etc).
	 * @return int|bool            Inserted log ID or false on failure.
	 */
	public static function insert_log( $ip, $method, $uri, $user_agent, $headers, $payload, $action_taken ) {
		global $wpdb;
		$table_name = self::get_table_name();

		$data = array(
			'site_id'        => get_current_blog_id(),
			'timestamp'      => current_time( 'mysql' ),
			'ip_address'     => sanitize_text_field( $ip ),
			'request_method' => sanitize_text_field( $method ),
			'request_uri'    => esc_url_raw( $uri ),
			'user_agent'     => sanitize_text_field( $user_agent ),
			'headers'        => wp_json_encode( $headers ),
			'payload'        => wp_json_encode( $payload ),
			'action_taken'   => sanitize_text_field( $action_taken ),
		);

		$format = array(
			'%d', // site_id
			'%s', // timestamp
			'%s', // ip_address
			'%s', // request_method
			'%s', // request_uri
			'%s', // user_agent
			'%s', // headers
			'%s', // payload
			'%s', // action_taken
		);

		$inserted = $wpdb->insert( $table_name, $data, $format );

		if ( $inserted ) {
			return $wpdb->insert_id;
		}

		return false;
	}

	/**
	 * Get logs from the database.
	 *
	 * @param int      $limit   Number of records to retrieve.
	 * @param int      $offset  Number of records to skip.
	 * @param int|null $site_id Optional site ID to filter by.
	 * @return array
	 */
	public static function get_logs( $limit = 20, $offset = 0, $site_id = null ) {
		global $wpdb;
		$table_name = self::get_table_name();

		// Check table existence first to avoid queries on unactivated db
		if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table_name ) ) !== $table_name ) {
			return array();
		}

		$query = "SELECT * FROM {$table_name}";
		$args = array();

		if ( null !== $site_id ) {
			$query .= ' WHERE site_id = %d';
			$args[] = $site_id;
		}

		$query .= ' ORDER BY timestamp DESC LIMIT %d OFFSET %d';
		$args[] = $limit;
		$args[] = $offset;

		$prepared_query = $wpdb->prepare( $query, $args );
		return $wpdb->get_results( $prepared_query, ARRAY_A );
	}

	/**
	 * Get total count of logs.
	 *
	 * @param int|null $site_id Optional site ID to filter by.
	 * @return int
	 */
	public static function get_logs_count( $site_id = null ) {
		global $wpdb;
		$table_name = self::get_table_name();

		if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table_name ) ) !== $table_name ) {
			return 0;
		}

		$query = "SELECT COUNT(*) FROM {$table_name}";
		$args = array();

		if ( null !== $site_id ) {
			$query .= ' WHERE site_id = %d';
			$args[] = $site_id;
		}

		if ( empty( $args ) ) {
			return (int) $wpdb->get_var( $query );
		}

		return (int) $wpdb->get_var( $wpdb->prepare( $query, $args ) );
	}

	/**
	 * Clear logs.
	 *
	 * @param int|null $site_id Optional site ID to filter by.
	 * @return bool
	 */
	public static function clear_logs( $site_id = null ) {
		global $wpdb;
		$table_name = self::get_table_name();

		if ( null !== $site_id ) {
			$result = $wpdb->delete( $table_name, array( 'site_id' => $site_id ), array( '%d' ) );
			return false !== $result;
		}

		$result = $wpdb->query( "TRUNCATE TABLE {$table_name}" );
		return false !== $result;
	}
}
