<?php
/**
 * Plugin Name: Abiquifi Mailer
 * Description: Configura SMTP e logs de e-mail para Outlook/Microsoft 365.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! function_exists( 'abiquifi_mailer_env' ) ) {
	function abiquifi_mailer_env( $key, $default = '' ) {
		$key = (string) $key;

		if ( '' === $key ) {
			return $default;
		}

		$value = getenv( $key );
		if ( false !== $value && '' !== trim( (string) $value ) ) {
			return trim( (string) $value );
		}

		if ( isset( $_ENV[ $key ] ) && '' !== trim( (string) $_ENV[ $key ] ) ) {
			return trim( (string) $_ENV[ $key ] );
		}

		if ( isset( $_SERVER[ $key ] ) && '' !== trim( (string) $_SERVER[ $key ] ) ) {
			return trim( (string) $_SERVER[ $key ] );
		}

		if ( defined( $key ) ) {
			$value = constant( $key );
			if ( is_scalar( $value ) && '' !== trim( (string) $value ) ) {
				return trim( (string) $value );
			}
		}

		return $default;
	}
}

if ( ! function_exists( 'abiquifi_mailer_log_path' ) ) {
	function abiquifi_mailer_log_path() {
		return WP_CONTENT_DIR . '/uploads/abiquifi-mail.log';
	}
}

if ( ! function_exists( 'abiquifi_mailer_log' ) ) {
	function abiquifi_mailer_log( $message, $context = array(), $force = false ) {
		$enabled = '1' === abiquifi_mailer_env( 'ABIQUIFI_MAIL_LOG', '0' );
		if ( ! $force && ! $enabled ) {
			return;
		}

		$payload = array(
			'timestamp' => gmdate( 'c' ),
			'message'   => (string) $message,
			'context'   => is_array( $context ) ? $context : array(),
		);

		$line = wp_json_encode( $payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );
		if ( ! is_string( $line ) ) {
			return;
		}

		error_log( $line . PHP_EOL, 3, abiquifi_mailer_log_path() );
	}
}

add_filter(
	'wp_mail_from',
	static function ( $from_email ) {
		$sender = sanitize_email( abiquifi_mailer_env( 'ABIQUIFI_MAIL_FROM_EMAIL', 'marketing@abiquifi.org.br' ) );
		return '' !== $sender && is_email( $sender ) ? $sender : $from_email;
	}
);

add_filter(
	'wp_mail_from_name',
	static function ( $from_name ) {
		$name = abiquifi_mailer_env( 'ABIQUIFI_MAIL_FROM_NAME', 'Fabricamos | Abiquifi' );
		return '' !== $name ? $name : $from_name;
	}
);

add_action(
	'phpmailer_init',
	static function ( $phpmailer ) {
		$host = abiquifi_mailer_env( 'ABIQUIFI_SMTP_HOST', '' );
		if ( '' === $host ) {
			return;
		}

		$port        = (int) abiquifi_mailer_env( 'ABIQUIFI_SMTP_PORT', '587' );
		$username    = abiquifi_mailer_env( 'ABIQUIFI_SMTP_USER', '' );
		$password    = abiquifi_mailer_env( 'ABIQUIFI_SMTP_PASS', '' );
		$encryption  = strtolower( abiquifi_mailer_env( 'ABIQUIFI_SMTP_ENCRYPTION', 'tls' ) );
		$from_email  = sanitize_email( abiquifi_mailer_env( 'ABIQUIFI_MAIL_FROM_EMAIL', 'marketing@abiquifi.org.br' ) );
		$from_name   = abiquifi_mailer_env( 'ABIQUIFI_MAIL_FROM_NAME', 'Fabricamos | Abiquifi' );

		$phpmailer->isSMTP();
		$phpmailer->Host        = $host;
		$phpmailer->Port        = $port > 0 ? $port : 587;
		$phpmailer->SMTPAuth    = '' !== $username;
		$phpmailer->Username    = $username;
		$phpmailer->Password    = $password;
		$phpmailer->Timeout     = 20;
		$phpmailer->CharSet     = 'UTF-8';
		$phpmailer->SMTPAutoTLS = true;

		if ( 'ssl' === $encryption ) {
			$phpmailer->SMTPSecure = 'ssl';
		} else {
			$phpmailer->SMTPSecure = 'tls';
		}

		if ( '' !== $from_email && is_email( $from_email ) ) {
			$phpmailer->setFrom( $from_email, $from_name, false );
		}

		abiquifi_mailer_log(
			'SMTP configurado para envio.',
			array(
				'host'       => $host,
				'port'       => $phpmailer->Port,
				'encryption' => $phpmailer->SMTPSecure,
				'from_email' => $from_email,
			)
		);
	},
	5
);

add_action(
	'wp_mail_failed',
	static function ( $error ) {
		if ( ! is_wp_error( $error ) ) {
			return;
		}

		$data = $error->get_error_data();
		if ( ! is_array( $data ) ) {
			$data = array();
		}

		unset( $data['phpmailer'] );

		abiquifi_mailer_log(
			'Falha ao enviar e-mail.',
			array(
				'code'    => $error->get_error_code(),
				'message' => $error->get_error_message(),
				'data'    => $data,
			),
			true
		);
	}
);

add_action(
	'wp_mail_succeeded',
	static function ( $mail_data ) {
		if ( ! is_array( $mail_data ) ) {
			return;
		}

		abiquifi_mailer_log(
			'E-mail enviado com sucesso.',
			array(
				'to'      => isset( $mail_data['to'] ) ? (array) $mail_data['to'] : array(),
				'subject' => isset( $mail_data['subject'] ) ? (string) $mail_data['subject'] : '',
			)
		);
	}
);
