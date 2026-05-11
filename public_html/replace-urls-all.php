<?php
// Temporary script to replace old domain URLs across common WordPress tables.
// Delete this file after use.

define( 'WP_USE_THEMES', false );
require __DIR__ . '/wp-load.php';

$old_domain = 'dicionario.abiquifi.org.br';
$new_domain = 'dicionario.abiquifi.questione.ai';

$replace_pairs = [
	[ 'from' => 'https://' . $old_domain, 'to' => 'https://' . $new_domain ],
	[ 'from' => 'http://' . $old_domain,  'to' => 'https://' . $new_domain ],
	[ 'from' => '//' . $old_domain,       'to' => '//' . $new_domain ],
	[ 'from' => $old_domain,              'to' => $new_domain ],
];

if ( ! function_exists( 'is_serialized' ) ) {
	http_response_code( 500 );
	echo 'WordPress not loaded';
	exit;
}

set_time_limit( 0 );

// Ensure core URLs point to the new domain.
update_option( 'home', 'https://' . $new_domain );
update_option( 'siteurl', 'https://' . $new_domain );

function replace_deep( $data, $replace_pairs, &$count ) {
	if ( is_string( $data ) ) {
		if ( is_serialized( $data ) ) {
			$unserialized = maybe_unserialize( $data );
			$replaced = replace_deep( $unserialized, $replace_pairs, $count );
			return maybe_serialize( $replaced );
		}
		foreach ( $replace_pairs as $pair ) {
			$data = str_replace( $pair['from'], $pair['to'], $data, $repl_count );
			$count += $repl_count;
		}
		return $data;
	}

	if ( is_array( $data ) ) {
		foreach ( $data as $key => $value ) {
			$data[ $key ] = replace_deep( $value, $replace_pairs, $count );
		}
		return $data;
	}

	if ( is_object( $data ) ) {
		foreach ( $data as $key => $value ) {
			$data->$key = replace_deep( $value, $replace_pairs, $count );
		}
		return $data;
	}

	return $data;
}

global $wpdb;
$like = '%' . $wpdb->esc_like( $old_domain ) . '%';

$tables = [
	[
		'table' => $wpdb->posts,
		'pk'    => 'ID',
		'col'   => 'post_content',
	],
	[
		'table' => $wpdb->postmeta,
		'pk'    => 'meta_id',
		'col'   => 'meta_value',
	],
	[
		'table' => $wpdb->options,
		'pk'    => 'option_id',
		'col'   => 'option_value',
	],
];

// Optional tables if present.
if ( ! empty( $wpdb->termmeta ) ) {
	$tables[] = [ 'table' => $wpdb->termmeta, 'pk' => 'meta_id', 'col' => 'meta_value' ];
}
if ( ! empty( $wpdb->usermeta ) ) {
	$tables[] = [ 'table' => $wpdb->usermeta, 'pk' => 'umeta_id', 'col' => 'meta_value' ];
}

$total_rows = 0;
$total_replacements = 0;
$total_updates = 0;

foreach ( $tables as $t ) {
	$rows = $wpdb->get_results(
		$wpdb->prepare(
			"SELECT {$t['pk']} AS pk, {$t['col']} AS val FROM {$t['table']} WHERE {$t['col']} LIKE %s",
			$like
		)
	);

	if ( empty( $rows ) ) {
		continue;
	}

	foreach ( $rows as $row ) {
		$total_rows++;
		$replacement_count = 0;
		$new_val = replace_deep( $row->val, $replace_pairs, $replacement_count );
		$total_replacements += $replacement_count;

		if ( $new_val !== $row->val ) {
			$updated = $wpdb->update(
				$t['table'],
				[ $t['col'] => $new_val ],
				[ $t['pk']  => $row->pk ],
				[ '%s' ],
				[ '%d' ]
			);
			if ( false !== $updated ) {
				$total_updates++;
			}
		}
	}
}

echo sprintf(
	'Done. Rows scanned: %d | Rows updated: %d | Replacements: %d',
	$total_rows,
	$total_updates,
	$total_replacements
);
