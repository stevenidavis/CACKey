#! /usr/bin/env tclsh

if {[info exists ::env(SSH_AGENT_LIB_PATH)]} {
	lappend auto_path {*}$::env(SSH_AGENT_LIB_PATH)
}

if {[info exists ::env(SSH_AGENT_PKCS11_MODULE)]} {
	set ::pkcs11ModuleFilename $::env(SSH_AGENT_PKCS11_MODULE)
} else {
	set ::pkcs11ModuleFilename /home/rkeene/tmp/cackey/build/tcl/softokn3-pkcs11.so
}

package require duktape 0.7
package require tuapi
package require pki 0.6
package require pki::pkcs11 0.9.9

## HACK: Fix up older versions of "pki" to include the raw certificate
##       this is needed
apply {{} {
	set procToUpdate ::pki::x509::parse_cert
	if {![string match "*set ret(raw)*" [info body $procToUpdate]]} {
		set body [info body $procToUpdate]
		set body [string map {
			"::asn::asnGetSequence cert_seq wholething"
			"set ret(raw) $cert_seq; binary scan $ret(raw) H* ret(raw); ::asn::asnGetSequence cert_seq wholething"
		} $body]
		proc $procToUpdate [info args $procToUpdate] $body
	}
}}

proc pkcs11ModuleHandle {} {
	if {![info exists ::pkcs11ModuleHandle]} {
		set ::pkcs11ModuleHandle [::pki::pkcs11::loadmodule $::pkcs11ModuleFilename]
	}
	return $::pkcs11ModuleHandle
}

proc pkcs11ModuleUnload {handle} {
	if {[info exists ::pkcs11ModuleHandle] && $handle eq $::pkcs11ModuleHandle} {
		unset ::pkcs11ModuleHandle
	}
	::pki::pkcs11::unloadmodule $handle
}

proc addRSAToJS {jsHandle} {
	::duktape::tcl-function $jsHandle __parseCert json {cert} {
		set cert [binary decode hex $cert]
		if {[catch {
			set cert [::pki::x509::parse_cert $cert]
		}]} {
			return ""
		}

		set e [format %llx [dict get $cert e]]
		set n [format %llx [dict get $cert n]]
		if {[string length $e] % 2 != 0} {
			set e "0$e"
		}
		if {[string length $n] % 2 != 0} {
			set n "0$n"
		}
		if {[string length $n] % 4 == 0} {
			set n "00$n"
		}

		set retval "\{
			\"publicKey\": \{
				\"type\":\"[string toupper [dict get $cert type]]\",
				\"e\":\"$e\",
				\"n\":\"$n\"
			\},
			\"subject\": \"[dict get $cert subject]\",
			\"issuer\": \"[dict get $cert issuer]\",
			\"serial\": \"[dict get $cert serial_number]\"
		\}"

		return $retval
	}

	::duktape::tcl-function $jsHandle __crypto_subtle_digest bytearray {hash data} {
		switch -exact -- $hash {
			"SHA-256" {
				package require sha256
				return [::sha2::sha256 -- $data]
			}
			"SHA-1" {
				package require sha1
				return [::sha1::sha1 -- $data]
			}
			default {
				error "Hash not supported: $hash"
			}
		}
	}

	::duktape::eval $jsHandle {
		crypto.subtle.digest.internal = __crypto_subtle_digest;
		delete __crypto_subtle_digest;
	}

	::duktape::eval $jsHandle {
		function X509() {
			this.hex = "";
			this.readCertHex = function(string) {
				this.hex = string;
			};
			this.computeCertData = function() {
				if (this.certData) {
					return;
				}
				this.certData = X509.parseCert(this.hex);
				this.certData.publicKey.n = Duktape.dec('hex', this.certData.publicKey.n);
				this.certData.publicKey.e = Duktape.dec('hex', this.certData.publicKey.e);
			}
			this.getPublicKey = function() {
				this.computeCertData();
				return(this.certData.publicKey);
			};
			this.getSubjectString = function() {
				this.computeCertData();
				return(this.certData.subject);
			};
			this.getExtSubjectAltName2 = function() {
				return([]);
			}
		}
		X509.parseCert = __parseCert;
		delete __parseCert;
	}
}

proc readFile {fileName} {
	if {![info exists ::readFile($fileName)]} {
		catch {
			set fd [open $fileName]
			set ::readFile($fileName) [read $fd]
		}
		catch {
			close $fd
		}
	}

	return $::readFile($fileName)
}

proc initSSHAgent {} {
	set jsHandle [::duktape::init -safe true]

	::duktape::tcl-function $jsHandle __puts {args} {
		if {[llength $args] ni {1 2}} {
			return -code error "wrong # args: puts ?{stderr|stdout}? message"
		}
		if {[llength $args] == 2} {
			set chan [lindex $args 0]
			if {$chan ni {stdout stderr}} {
				return -code error "Only stderr and stdout allowed"
			}
		}
		puts {*}$args
	}

	::duktape::eval $jsHandle {
		runtime = {};
		runtime.puts = __puts;
		runtime.stderr = "stderr";
		delete __puts;
	}

	::duktape::eval $jsHandle {var goog = {DEBUG: false};}
	::duktape::eval $jsHandle [readFile chrome-emu.js]
	addRSAToJS $jsHandle
	::duktape::eval $jsHandle [readFile ssh-agent-noasync.js]
	::duktape::eval $jsHandle {cackeySSHAgentFeatures.enabled = true;}
	::duktape::eval $jsHandle {cackeySSHAgentFeatures.includeCerts = false;}
	::duktape::eval $jsHandle {cackeySSHAgentFeatures.legacy = false;}
	::duktape::eval $jsHandle {
		function connection(callback) {
			this.sender = {
				id: "pnhechapfaindjhompbnflcldabbghjo"
			};
			this.onMessage = {
				listeners: [],
				addListener: function(callback) {
					this.listeners.push(callback);
				}
			};
			this.postMessage = function(message) {
				return(callback(this, message));
			};
			this.send = function(message) {
				this.onMessage.listeners.forEach(function(listener) {
					listener(message);
				});
			};
		}

		function handleDataFromAgent(socket, data) {
			if (!data || !data.type || !data.data) {
				return;
			}

			if (data.type != "auth-agent@openssh.com") {
				return;
			}

			writeFramed(socket.handle, data.data);
		}

		function handleDataFromSocket(socket, data) {
			socket.send({
				type: "auth-agent@openssh.com",
				data: Array.from(data)
			});
		}

		function writeFramed(sock, data) {
			var buffer;
			var idx;

			buffer = new Buffer(data.length);
			for (idx = 0; idx < data.length; idx++) {
				buffer[idx] = data[idx];
			}
			return(writeFramedBuffer(sock, buffer));
		}

		function cackeyListCertificates() {
			var certs;
			var certObjs;

			certObjs = [];
			certs = cackeyListCertificatesBare();
			certs.forEach(function(cert) {
				certObjs.push({
					certificate: new Uint8Array(cert),
					supportedHashes: ['SHA1', 'SHA256', 'SHA512', 'MD5_SHA1']
				});
			});

			return(certObjs);
		}

		function cackeySignMessage(request) {
			var retval;
			var digest, digestHeader;

			/*
			 * XXX:TODO: Pull this out of cackey.js into a common.js
			 */
			switch (request.hash) {
				case "SHA1":
					digestHeader = new Uint8Array([0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14]);
					break;
				case "SHA256":
					digestHeader = new Uint8Array([0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20]);
					break;
				case "SHA512":
					digestHeader = new Uint8Array([0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40]);
					break;
				case "MD5_SHA1":
				case "RAW":
					digestHeader = new Uint8Array();
					break;
				default:
					console.error("[cackey] Asked to sign a message with a hash we do not support: " + request.hash);
					return(null);
			}

			digest = Array.from(digestHeader);
			digest = digest.concat(Array.from(request.digest));
			digest = new Buffer(digest);

			retval = cackeySignBare(request.certificate, digest);

			return(retval);
		}
	}

	::duktape::tcl-function $jsHandle writeFramedBuffer {sock message} {
		set dataLen [string length $message]
		set dataLen [binary format I $dataLen]
		puts -nonewline $sock "${dataLen}${message}"
		flush $sock

		return ""
	}

	::duktape::tcl-function $jsHandle readFramed bytearray {sock} {
		catch {
			set dataLen [read $sock 4]
		}
		if {![info exists dataLen] || [string length $dataLen] != 4} {
			close $sock
			return
		}

		binary scan $dataLen I dataLen

		set data [read $sock $dataLen]

		return $data
	}


	::duktape::tcl-function $jsHandle cackeySignBare bytearray {cert message} {
		set handle [pkcs11ModuleHandle]
		set certInfo [listCerts $handle $cert]
		if {![dict exists $certInfo pkcs11_slotid]} {
			pkcs11ModuleUnload $handle
			return -code error "Unable to find certificate to sign with"
		}

		set slotId [dict get $certInfo pkcs11_slotid]
		set data [::pki::sign $message $certInfo raw]

		return $data
	}

	::duktape::tcl-function $jsHandle cackeyListCertificatesBare {arraylist bytearray} {} {
		set handle [pkcs11ModuleHandle]
		return [listCerts $handle]
	}

	return $jsHandle
}

proc listCerts {handle {match ""}} {
	set certs [list]

	set slots [::pki::pkcs11::listslots $handle]
	foreach slotInfo $slots {
		set slotId [lindex $slotInfo 0]
		set slotLabel [lindex $slotInfo 1]
		set slotFlags [lindex $slotInfo 2]

		set slotCerts [::pki::pkcs11::listcerts $handle $slotId]
		foreach keyList $slotCerts {
			set cert [dict get $keyList raw]
			set cert [binary decode hex $cert]
			if {$match eq $cert} {
				return $keyList
			}
			lappend certs $cert
		}
	}

	if {$match ne ""} {
		return [list]
	}

	return $certs
}

proc handleData {sock jsHandle} {
	if {[catch {
		::duktape::eval $jsHandle {handleDataFromSocket(socket, readFramed(socket.handle));}
	}]} {
		puts stderr "ERROR: $::errorInfo"
		close $sock
	}
}

proc incomingConnection {sock args} {
	if {[catch {
		if {![info exists ::jsHandle]} {
			set ::jsHandle [initSSHAgent]
		}
		set jsHandle $::jsHandle

		::duktape::eval $jsHandle {var socket = new connection(handleDataFromAgent);}
		::duktape::eval $jsHandle "socket.handle = \"$sock\";"
		::duktape::eval $jsHandle {chrome.runtime.externalConnect(socket);}

		fconfigure $sock -translation binary -encoding binary -blocking true
		fileevent $sock readable [list handleData $sock $jsHandle]
	}]} {
		puts stderr "ERROR: $::errorInfo"
		close $sock
	}
}

::tuapi::syscall::socket_unix -server incomingConnection "./agent"

vwait forever
