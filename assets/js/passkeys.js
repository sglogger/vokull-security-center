/**
 * Passkeys — the browser half of the WebAuthn exchange.
 *
 * Everything this file does is plumbing. The interesting decisions were all
 * made on the server: which credentials may answer, whether the authenticator
 * must verify the user, how long the challenge lives. Here we only translate
 * between the base64url that travels in JSON and the ArrayBuffers the
 * credentials API insists on, then put the result into a hidden field and let
 * the ordinary form submission carry it back.
 *
 * That last part is deliberate. The response rides the same form, the same
 * nonce and the same rate limiter as a typed code, so a passkey adds no new
 * endpoint to the site and no new way in.
 *
 * @package WPSecurityCenter
 */

( function () {
	'use strict';

	var l10n = window.wpsecPasskeyL10n || {};

	function text( key, fallback ) {
		return typeof l10n[ key ] === 'string' ? l10n[ key ] : fallback;
	}

	function supported() {
		return !! ( window.PublicKeyCredential && navigator.credentials && navigator.credentials.create );
	}

	// -------------------------------------------------------------------------
	// base64url <-> ArrayBuffer
	// -------------------------------------------------------------------------

	function decode( value ) {
		var padded = value.replace( /-/g, '+' ).replace( /_/g, '/' );

		while ( padded.length % 4 ) {
			padded += '=';
		}

		var binary = window.atob( padded );
		var bytes  = new Uint8Array( binary.length );

		for ( var i = 0; i < binary.length; i++ ) {
			bytes[ i ] = binary.charCodeAt( i );
		}

		return bytes.buffer;
	}

	function encode( buffer ) {
		var bytes  = new Uint8Array( buffer );
		var binary = '';

		for ( var i = 0; i < bytes.byteLength; i++ ) {
			binary += String.fromCharCode( bytes[ i ] );
		}

		return window.btoa( binary ).replace( /\+/g, '-' ).replace( /\//g, '_' ).replace( /=+$/, '' );
	}

	/**
	 * The credentials API takes ArrayBuffers where JSON can only carry strings,
	 * so the few fields that are really binary are converted back by name.
	 */
	function prepare( options ) {
		var key = options.publicKey;

		key.challenge = decode( key.challenge );

		if ( key.user && key.user.id ) {
			key.user.id = decode( key.user.id );
		}

		[ 'excludeCredentials', 'allowCredentials' ].forEach( function ( list ) {
			if ( Array.isArray( key[ list ] ) ) {
				key[ list ] = key[ list ].map( function ( item ) {
					item.id = decode( item.id );
					return item;
				} );
			}
		} );

		return options;
	}

	function serialise( credential ) {
		var response = credential.response;
		var out      = {
			id: credential.id,
			rawId: encode( credential.rawId ),
			type: credential.type,
			response: {
				clientDataJSON: encode( response.clientDataJSON )
			}
		};

		if ( response.attestationObject ) {
			out.response.attestationObject = encode( response.attestationObject );

			if ( typeof response.getTransports === 'function' ) {
				try {
					out.response.transports = response.getTransports();
				} catch ( e ) {
					out.response.transports = [];
				}
			}
		}

		if ( response.authenticatorData ) {
			out.response.authenticatorData = encode( response.authenticatorData );
			out.response.signature         = encode( response.signature );
			out.response.userHandle        = response.userHandle ? encode( response.userHandle ) : null;
		}

		return out;
	}

	// -------------------------------------------------------------------------
	// Feedback
	// -------------------------------------------------------------------------

	function say( trigger, message ) {
		var box = document.getElementById( trigger.getAttribute( 'data-wpsec-message' ) || '' );

		if ( box ) {
			box.textContent = message;
			box.hidden      = ! message;
			return;
		}

		if ( message ) {
			window.alert( message );
		}
	}

	/**
	 * A cancelled prompt is not an error worth shouting about — the user closed
	 * the sheet, which is a decision, not a failure. Anything else gets said
	 * out loud, because a silent nothing is the worst possible answer here.
	 */
	function explain( error ) {
		if ( error && ( error.name === 'NotAllowedError' || error.name === 'AbortError' ) ) {
			return '';
		}

		if ( error && error.name === 'InvalidStateError' ) {
			return text( 'alreadyRegistered', 'This device already has a passkey for this account.' );
		}

		return text( 'failed', 'The passkey could not be used. Try again, or use another method.' );
	}

	function busy( trigger, state ) {
		trigger.disabled = state;
		trigger.classList.toggle( 'wpsec-passkey-busy', state );
	}

	// -------------------------------------------------------------------------
	// The three flows
	// -------------------------------------------------------------------------

	/**
	 * Registration and second-factor verification both end the same way: the
	 * serialised credential goes into a hidden field and the form it belongs to
	 * is submitted normally.
	 */
	function runInline( trigger ) {
		var mode    = trigger.getAttribute( 'data-wpsec-passkey' );
		var field   = document.getElementById( trigger.getAttribute( 'data-wpsec-field' ) );
		var form    = trigger.form || ( field && field.form );
		var options = prepare( JSON.parse( trigger.getAttribute( 'data-wpsec-options' ) ) );

		if ( ! field || ! form ) {
			return Promise.resolve();
		}

		busy( trigger, true );
		say( trigger, '' );

		var request = 'register' === mode
			? navigator.credentials.create( options )
			: navigator.credentials.get( options );

		return request.then( function ( credential ) {
			field.value = JSON.stringify( serialise( credential ) );
			form.submit();
		} ).catch( function ( error ) {
			busy( trigger, false );
			say( trigger, explain( error ) );
		} );
	}

	/**
	 * A passwordless sign-in has nobody to attach a form to yet, so the
	 * challenge is fetched first and the assertion posted back to the same
	 * wp-login.php action. Still no separate API: it is a form post that
	 * answers in JSON.
	 */
	function runPasswordless( trigger, conditional ) {
		var endpoint = trigger.getAttribute( 'data-wpsec-endpoint' );
		var redirect = trigger.getAttribute( 'data-wpsec-redirect' ) || '';

		if ( ! endpoint ) {
			return Promise.resolve();
		}

		if ( ! conditional ) {
			busy( trigger, true );
			say( trigger, '' );
		}

		var body = new window.FormData();
		body.append( 'wpsec_pk_op', 'start' );

		return window.fetch( endpoint, {
			method: 'POST',
			credentials: 'same-origin',
			body: body
		} ).then( function ( response ) {
			return response.json();
		} ).then( function ( data ) {
			if ( ! data || ! data.options ) {
				throw new Error( 'no options' );
			}

			var options = prepare( data.options );

			// Conditional mediation is the browser offering the passkey from
			// inside the username field's autofill list instead of throwing a
			// modal at somebody who never asked for one.
			if ( conditional ) {
				options.mediation = 'conditional';
			}

			return navigator.credentials.get( options ).then( function ( credential ) {
				var finish   = new window.FormData();
				var remember = document.getElementById( 'rememberme' );

				finish.append( 'wpsec_pk_op', 'finish' );
				finish.append( 'wpsec_pk_ticket', data.ticket );
				finish.append( 'wpsec_pk_response', JSON.stringify( serialise( credential ) ) );
				finish.append( 'redirect_to', redirect );

				if ( remember && remember.checked ) {
					finish.append( 'rememberme', 'forever' );
				}

				return window.fetch( endpoint, {
					method: 'POST',
					credentials: 'same-origin',
					body: finish
				} ).then( function ( response ) {
					return response.json();
				} );
			} );
		} ).then( function ( result ) {
			if ( result && result.redirect ) {
				window.location.assign( result.redirect );
				return;
			}

			busy( trigger, false );
			say( trigger, ( result && result.message ) || text( 'failed', 'The passkey could not be used.' ) );
		} ).catch( function ( error ) {
			busy( trigger, false );

			if ( ! conditional ) {
				say( trigger, explain( error ) );
			}
		} );
	}

	// -------------------------------------------------------------------------
	// Wiring
	// -------------------------------------------------------------------------

	function start() {
		var triggers = document.querySelectorAll( '[data-wpsec-passkey]' );

		if ( ! triggers.length ) {
			return;
		}

		if ( ! supported() ) {
			Array.prototype.forEach.call( triggers, function ( trigger ) {
				var holder = trigger.closest( '.wpsec-passkey-block' ) || trigger;
				holder.hidden = true;
			} );

			return;
		}

		Array.prototype.forEach.call( triggers, function ( trigger ) {
			var mode = trigger.getAttribute( 'data-wpsec-passkey' );

			trigger.addEventListener( 'click', function ( event ) {
				event.preventDefault();

				if ( 'passwordless' === mode ) {
					runPasswordless( trigger, false );
				} else {
					runInline( trigger );
				}
			} );

			if ( 'passwordless' === mode ) {
				offerAutofill( trigger );
			}
		} );
	}

	/**
	 * Offer the passkey from the username field, where a browser that has one
	 * will show it without anybody having to know the button exists.
	 */
	function offerAutofill( trigger ) {
		if ( typeof window.PublicKeyCredential.isConditionalMediationAvailable !== 'function' ) {
			return;
		}

		window.PublicKeyCredential.isConditionalMediationAvailable().then( function ( available ) {
			if ( ! available ) {
				return;
			}

			var field = document.getElementById( 'user_login' );

			if ( field ) {
				field.setAttribute( 'autocomplete', 'username webauthn' );
			}

			runPasswordless( trigger, true );
		} ).catch( function () {} );
	}

	if ( document.readyState === 'loading' ) {
		document.addEventListener( 'DOMContentLoaded', start );
	} else {
		start();
	}
}() );
