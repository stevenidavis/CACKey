/*
 * CACKey SSH Agent for ChromeOS
 */

cackeySSHAgentApprovedApps = [
	"pnhechapfaindjhompbnflcldabbghjo",
	"okddffdblfhhnmhodogpojmfkjmhinfp"
];

/*
 * XXX:TODO: Expose UI for this
 */
cackeySSHAgentFeatures = {
	enabled: false,
	includeKeys: true,
	includeCerts: true,
	legacy: false
};

/*
 * Feature support checking
 */
function cackeySSHAgentGetSSHKeyTypes() {
	var types = [];

	if (cackeySSHAgentFeatures.includeKeys) {
		types.push("ssh");
	}

	if (cackeySSHAgentFeatures.includeCerts) {
		types.push("x509v3-ssh");

		if (cackeySSHAgentFeatures.legacy) {
			types.push("x509v3-sign");
		}
	}

	return(types);
}

async function cackeySSHAgentGetCertificates() {
	var certs;

	if (!cackeySSHAgentFeatures.enabled) {
		return([]);
	}

	certs = await cackeyListCertificates();

	return(certs);
}

/*
 * SSH Element Encoding/Decoding
 */
function cackeySSHAgentEncodeInt(uint32) {
	var result;

	result = [
		(uint32 >> 24) & 0xff,
		(uint32 >> 16) & 0xff,
		(uint32 >>  8) & 0xff,
		 uint32        & 0xff
	];

	return(result);
}

function cackeySSHAgentDecodeInt(input) {
	var result;

	result = 0;
	result |= (input[0] << 24);
	result |= (input[1] << 16);
	result |= (input[2] << 8);
	result |=  input[3];

	return({
		value: result,
		output: input.slice(4)
	});
}

function cackeySSHAgentEncodeBigInt(bigInt) {
	var result = [];

	switch (typeof(bigInt)) {
		case "number":
			while (bigInt) {
				result.push(bigInt & 0xff);
				bigInt = bigInt >> 8;
			}
			result.reverse();
			break;
		case "object":
			if (bigInt.toByteArray) {
				result = Array.from(new Uint8Array(bigInt.toByteArray()));
			} else {
				result = Array.from(bigInt);
			}
			break;
	}

	result = cackeySSHAgentEncodeLV(result);

	return(result);
}

function cackeySSHAgentEncodeLV(input) {
	var result;

	result = cackeySSHAgentEncodeInt(input.length);
	result = result.concat(input);

	return(result);
}

function cackeySSHAgentDecodeLV(input) {
	var result, info;

	info = cackeySSHAgentDecodeInt(input);
	if (info.value >= input.length) {
		throw(new Error("Invalid data"));
	}

	input = info.output;

	result = input.slice(0, info.value);

	return({
		value: result,
		output: input.slice(info.value)
	});
}

function cackeySSHAgentEncodeArray(input) {
	var result;

	result = cackeySSHAgentEncodeInt(input.length);
	input.forEach(function(element) {
		result = result.concat(cackeySSHAgentEncodeLV(element));
	});

	return(result);
}

function cackeySSHAgentDecodeArray(input) {
	var items, info;
	var itemCount;

	info = cackeySSHAgentDecodeInt(input);
	input = info.output;
	itemCount = info.value;

	items = [];
	while (itemCount > 0) {
		itemCount--;

		info = cackeySSHAgentDecodeLV(input);
		input = info.output;
		items.push(info.value);
	}

	return({
		value: items,
		output: input
	});
}


function cackeySSHAgentEncodeToUTF8Array(str) {
	var utf8 = [];

	if (typeof(str) === "string") {
		str = str.split("").map(function(c) {
			return(c.charCodeAt(0));
		});
	}

	for (var i = 0; i < str.length; i++) {
		var charcode = str[i];

		if (charcode < 0x80) {
			utf8.push(charcode);
		} else if (charcode < 0x800) {
			utf8.push(0xc0 | (charcode >> 6), 
			          0x80 | (charcode & 0x3f));
		} else if (charcode < 0xd800 || charcode >= 0xe000) {
			utf8.push(0xe0 | (charcode >> 12), 
			          0x80 | ((charcode >> 6) & 0x3f), 
			          0x80 | (charcode & 0x3f));
		} else {
			// surrogate pair
			i++;
			// UTF-16 encodes 0x10000-0x10FFFF by
			// subtracting 0x10000 and splitting the
			// 20 bits of 0x0-0xFFFFF into two halves
			charcode = 0x10000 + (((charcode & 0x3ff) << 10)
			           | (str[i] & 0x3ff));

			utf8.push(0xf0 | (charcode >>18), 
			          0x80 | ((charcode >> 12) & 0x3f), 
			          0x80 | ((charcode >> 6) & 0x3f), 
			          0x80 | (charcode & 0x3f));
		}
	}

	return utf8;
}

function cackeySSHAgentDecodeFromUTF8Array(inputArray) {
	var hexString;
	var output;

	hexString = cackeySSHAgentEncodeBinaryToHex(inputArray, "%");

	output = decodeURIComponent(hexString)

	return(output);
}

function cackeySSHAgentEncodeString(string) {
	var result;

	result = cackeySSHAgentEncodeLV(cackeySSHAgentEncodeToUTF8Array(string));

	return(result);
}

function cackeySSHAgentDecodeString(input) {
	var output;

	output = cackeySSHAgentDecodeLV(input);
	output.value = cackeySSHAgentDecodeFromUTF8Array(output.value);

	return(output);
}

function cackeySSHAgentEncodeBinaryToHex(binaryString, prefix) {
	var buffer;

	if (!prefix) {
		prefix = "";
	}

	switch (typeof(binaryString)) {
		case "string":
			buffer = binaryString.split("").map(function(c) {
				return(prefix + c.charCodeAt(0).toString(16).padStart(2, '0'));
			}).join("");
			break;
		default:
			buffer = [];
			new Uint8Array(binaryString).map(function(c) {
				buffer.push(prefix + c.toString(16).padStart(2, '0'));
			});
			buffer = buffer.join("");
			break;
	}

	return(buffer);
}

function cackeySSHAgentEncodeCertToKeyAndID(cert, sshKeyType) {
	var result = null, resultKey = null;
	var certObj, certBytes;
	var publicKey;

	certObj = new X509;
	if (!certObj) {
		return(result);
	}

	certBytes = Array.from(new Uint8Array(cert));

	certObj.readCertHex(cackeySSHAgentEncodeBinaryToHex(certBytes));

	publicKey = certObj.getPublicKey();

	switch (sshKeyType) {
		case "ssh":
			switch (publicKey.type) {
				case "RSA":
					resultKey = cackeySSHAgentEncodeString("ssh-rsa");
					resultKey = resultKey.concat(cackeySSHAgentEncodeBigInt(publicKey.e));
					resultKey = resultKey.concat(cackeySSHAgentEncodeBigInt(publicKey.n));
					break;
				default:
					console.log("[cackeySSH] Unsupported public key type:", sshKeyType, "/", publicKey.type, "-- ignoring.");
					break;
			}
			break;
		case "x509v3-sign":
			resultKey = certBytes;
			break;
		case "x509v3-ssh":
			switch (publicKey.type) {
				case "RSA":
					resultKey = cackeySSHAgentEncodeString("x509v3-ssh-rsa");

					/*
					 * Array of certificates
					 */
					resultKey = resultKey.concat(cackeySSHAgentEncodeArray([
						certBytes
					]));

					/*
					 * Array of OCSP responses
					 */
					resultKey = resultKey.concat(cackeySSHAgentEncodeArray([]));
					break;
				default:
					console.log("[cackeySSH] Unsupported public key type:", sshKeyType, "/", publicKey.type, "-- ignoring.");
					break;
			}
			break;
		default:
			console.log("[cackeySSH] Unsupported SSH key type:", sshKeyType, "-- ignoring.");
			break;
	}

	if (resultKey) {
		var certLabel;
		var certSAN;
		var ignoreException;

		/*
		 * Set a default label
		 */
		certLabel = certObj.getSubjectString();

		/*
		 * Try to find a better label from the certificate's
		 * Subject Alternative Name (SAN) extensions
		 */
		try {
			certSAN = certObj.getExtSubjectAltName2();
			certSAN.forEach(function(itemPair) {
				var itemType, itemValue;

				itemType = itemPair[0];
				itemValue = itemPair[1];

				if (itemType === "MAIL") {
					certLabel = itemValue;
				}
			});
		} catch (ignoreException) {
		}

		result = {
			label: certLabel,
			publicKeyType: publicKey.type,
			sshKeyType: sshKeyType,
			key: resultKey
		};
	}

	return(result);
}

function cackeySSHAgentDecodeCert(requestArray) {
	var type;
	var decodeError;
	var publicKeyType, publicKeyBlob;
	var output;

	try {
		type = cackeySSHAgentDecodeString(requestArray);
	} catch (decodeError) {
		/*
		 * x509v3-sign-rsa requests are un-prefixed :-(
		 */
		type = {}
		type.value = requestArray;
		type.output = [];
	}

	/* It might be an x509v3-sign-rsa, which is unprefixed -- try to guess */
	if (type.value[0] == 0x30) {
		type = "x509v3-sign-rsa";
	} else {
		requestArray = type.output;
		type = type.value;
	}

	switch (type) {
		case "ssh-rsa":
		case "x509v3-sign-rsa":
			publicKeyType = "RSA";
			publicKeyBlob = requestArray;
			break;
		case "x509v3-ssh-rsa":
			publicKeyType = "RSA";
			publicKeyBlob = cackeySSHAgentDecodeArray(requestArray).value[0];
			break;
	}

	output = {
		publicKeyType: publicKeyType,
		publicKeyBlob: publicKeyBlob
	};

	return(output);
}

function cackeySSHAgentCompareRequestAndKey(key1, key2) {
	var ignoredError;

	try {
		key1 = cackeySSHAgentDecodeCert(key1);
		key2 = cackeySSHAgentDecodeCert(key2);
	} catch (ignoredError) {
		return(false);
	}

	if (key1.publicKeyType !== key2.publicKeyType) {
		return(false);
	}

	if (key1.publicKeyBlob.join(",") === key2.publicKeyBlob.join(",")) {
		return(true);
	}

	return(false);
}

/*
 * Command Handlers
 */
async function cackeySSHAgentCommandRequestIdentity(request) {
	var response;
	var certs = [];
	var keys = [];

	/*
	 * Get a list of certificates
	 */
	certs = await cackeySSHAgentGetCertificates();

	/*
	 * Convert each certificate to an SSH key blob
	 */
	cackeySSHAgentGetSSHKeyTypes().forEach(function(sshKeyType) {
		certs.forEach(function(cert) {
			var key;

			key = cackeySSHAgentEncodeCertToKeyAndID(cert.certificate, sshKeyType);

			if (key) {
				keys.push(key);
			}
		});
	});

	/*
	 * Encode response
	 */
	response = [];

	response.push(cackeySSHAgentMessage.SSH_AGENT_IDENTITIES_ANSWER);
	response = response.concat(cackeySSHAgentEncodeInt(keys.length));
	keys.forEach(function(key) {
		response = response.concat(cackeySSHAgentEncodeLV(key.key));
		response = response.concat(cackeySSHAgentEncodeString(key.label));
	});

	return(response);
}

async function cackeySSHAgentCommandSignRequest(request) {
	var keyInfo, data, flags;
	var certs, certToUse, certToUseType;
	var hashMethod, signedData, signedDataHeader, signRequest;
	var decryptedData, decryptRequest;
	var operation, response;
	var flagMeaning = {
		SSH_AGENT_RSA_SHA2_256: 2,
		SSH_AGENT_RSA_SHA2_512: 4,
		SSH_AGENT_RSA_RAW:      0x40000000,
		SSH_AGENT_RSA_DECRYPT:  0x80000000
	};

	/*
	 * Default mode is signing
	 */
	operation = "sign";

	/*
	 * Strip off the command
	 */
	request = request.slice(1);

	/*
	 * Get certificate to sign using
	 */
	keyInfo = cackeySSHAgentDecodeLV(request);
	request = keyInfo.output;
	keyInfo = keyInfo.value;

	/*
	 * Get the data to sign
	 */
	data = cackeySSHAgentDecodeLV(request);
	request = data.output;
	data = data.value;

	/*
	 * Get the flags
	 */
	flags = cackeySSHAgentDecodeInt(request);
	request = flags.output;
	flags = flags.value;

	/*
	 * Find the certificate that matches the requested key
	 */
	certs = await cackeySSHAgentGetCertificates();
	certToUse = null;
	cackeySSHAgentGetSSHKeyTypes().forEach(function(sshKeyType) {
		certs.forEach(function(cert) {
			var key;

			if (certToUse) {
				return;
			}

			key = cackeySSHAgentEncodeCertToKeyAndID(cert.certificate, sshKeyType);

			if (cackeySSHAgentCompareRequestAndKey(key.key, keyInfo)) {
				certToUse = cert;
				certToUseType = key.publicKeyType;
			}
		});
	});

	/*
	 * If no certificate is found, return an error
	 */
	if (!certToUse) {
		console.info("[cackeySSH] Unable to find a certificate to match the requested key:", keyInfo);

		return(null);
	}

	/*
	 * Perform hashing of the data as specified by the flags
	 */
	switch (certToUseType) {
		case "RSA":
			if ((flags & flagMeaning.SSH_AGENT_RSA_SHA2_512) == flagMeaning.SSH_AGENT_RSA_SHA2_512) {
				hashMethod = "SHA512";
				data = await crypto.subtle.digest("SHA-512", new Uint8Array(data));
			} else if ((flags & flagMeaning.SSH_AGENT_RSA_SHA2_256) == flagMeaning.SSH_AGENT_RSA_SHA2_256) {
				hashMethod = "SHA256";
				data = await crypto.subtle.digest("SHA-256", new Uint8Array(data));
			} else if (flags == (flagMeaning.SSH_AGENT_RSA_RAW | flagMeaning.SSH_AGENT_RSA_DECRYPT)) {
				operation = "decrypt";
				data = new Uint8Array(data);
			} else if (flags == flagMeaning.SSH_AGENT_RSA_RAW) {
				hashMethod = "RAW";
				data = new Uint8Array(data);
			} else if (flags == 0) {
				hashMethod = "SHA1";
				data = await crypto.subtle.digest("SHA-1", new Uint8Array(data));
			} else {
				console.info("[cackeySSH] Sign request with flags set to", flags, "which is unsupported, failing the request.");

				return(null);
			}

			switch (hashMethod) {
				case "RAW":
					signedDataHeader = cackeySSHAgentEncodeString("rsa");
					break;
				case "SHA1":
					signedDataHeader = cackeySSHAgentEncodeString("ssh-rsa");
					break;
				case "SHA256":
					signedDataHeader = cackeySSHAgentEncodeString("rsa-sha2-256");
					break;
				case "SHA512":
					signedDataHeader = cackeySSHAgentEncodeString("rsa-sha2-512");
					break;
				default:
					console.info("[cackeySSH] Unsupported hashing method for RSA:", hashMethod, "failing the request.");

					return(null);
					break;
			}
			break;
		default:
			console.info("[cackeySSH] Unsupported public key type:", certToUseType, "failing the request.");

			return(null);
			break;
	}

	/*
	 * Sign or decrypt the data
	 */
	switch (operation) {
		case "sign":
			signRequest = {
				hash: hashMethod,
				certificate: certToUse.certificate,
				digest: new Uint8Array(data)
			};

			if (goog.DEBUG) {
				console.log("[cackeySSH] Requesting CACKey sign message:", signRequest);
			}

			signedData = await cackeySignMessage(signRequest);
			signedData = Array.from(new Uint8Array(signedData));
			break;
		case "decrypt":
			/* XXX:TODO: Incomplete ! */
			decryptRequest = {
				data: data
			}
			break;
	}

	/*
	 * Encode signature
	 */
	signedData = signedDataHeader.concat(cackeySSHAgentEncodeLV(signedData));

	/*
	 * Encode response
	 */
	response = [];

	response.push(cackeySSHAgentMessage.SSH_AGENT_SIGN_RESPONSE);
	response = response.concat(cackeySSHAgentEncodeLV(signedData));

	return(response);
}

/*
 * Session handling
 */
async function cackeySSHAgentHandleMessage(socket, request) {
	var sshRequestID, sshRequest, response, sshResponse;
	var sshHandlerError;
	var postMessageException;

	if (!request.type || request.type !== "auth-agent@openssh.com") {
		return;
	}

	if (!request.data || request.data.length < 1) {
		return;
	}

	sshRequestID = request.data[0];
	sshRequest = {};
	if (sshRequestID < cackeySSHAgentCommands.length) {
		sshRequest = cackeySSHAgentCommands[sshRequestID];
	}

	response = null;
	if (!sshRequest.name) {
		if (goog.DEBUG) {
			console.log("[cackeySSH] Unsupported request: ", request, "; from: ", socket.sender.id);
		}
	} else {
		if (goog.DEBUG) {
			console.log("[cackeySSH] Request: ", sshRequest.name, "; from: ", socket.sender.id);
		}

		try {
			response = await sshRequest.handler(request.data);
		} catch (sshHandlerError) {
			response = null;

			console.error("[cackeySSH] Request:", sshRequest.name, "(", request, ") ERROR:", sshHandlerError);
		}
	}

	if (!response) {
		response = [cackeySSHAgentMessage.SSH_AGENT_FAILURE];
	}

	sshResponse = {
		type: "auth-agent@openssh.com",
		data: response
	};

	if (goog.DEBUG) {
		console.log("[cackeySSH] Response: ", sshResponse);
	}

	try {
		socket.postMessage(sshResponse);
	} catch (postMessageException) {
		if (goog.DEBUG) {
			console.log("[cackeySSH] Failed to send response", postMessageException);
		}
	}

	return;
}

function cackeySSHAgentAcceptConnection(socket) {
	if (!socket) {
		return;
	}

	/*
	 * Only accept connections from approved apps
	 */
	if (!socket.sender || !socket.sender.id || cackeySSHAgentApprovedApps.indexOf(socket.sender.id) == -1) {
		console.log("[cackeySSH] Ignoring unapproved app: ", socket.sender);

		return;
	}

	console.log("[cackeySSH] Accepted connection from: ", socket.sender.id);
	socket.onMessage.addListener(function(request) {
		cackeySSHAgentHandleMessage(socket, request);
	});
}

function cackeySSHAgentInit() {
	chrome.runtime.onConnectExternal.addListener(cackeySSHAgentAcceptConnection);
}

function cackeySSHAgentUninit() {
	chrome.runtime.onConnectExternal.removeListener(cackeySSHAgentAcceptConnection);
}

cackeySSHAgentCommands = [
	{ /* 0: Not implemented */ },
	{ /* 1: Not implemented */ },
	{ /* 2: Not implemented */ },
	{ /* 3: Not implemented */ },
	{ /* 4: Not implemented */ },
	{ /* 5: Not implemented */ },
	{ /* 6: Not implemented */ },
	{ /* 7: Not implemented */ },
	{ /* 8: Not implemented */ },
	{ /* 9: Not implemented */ },
	{ /* 10: Not implemented */ },
	{
		name: "requestIdentities",
		handler: cackeySSHAgentCommandRequestIdentity
	},
	{ /* 12: Not implemented */ },
	{
		name: "signRequest",
		handler: cackeySSHAgentCommandSignRequest
	},
	{ /* 14: Not implemented */ },
	{ /* 15: Not implemented */ },
	{ /* 16: Not implemented */ },
	{ /* 17: Not implemented */ },
	{ /* 18: Not implemented */ },
	{ /* 19: Not implemented */ },
	{ /* 20: Not implemented */ },
	{ /* 21: Not implemented */ },
	{ /* 22: Not implemented */ },
	{ /* 23: Not implemented */ },
	{ /* 24: Not implemented */ },
	{ /* 25: Not implemented */ },
	{ /* 26: Not implemented */ },
	{ /* 27: Not implemented */ },
	{ /* 28: Not implemented */ }
];

cackeySSHAgentMessage = {
	SSH_AGENT_FAILURE: 5,
	SSH_AGENT_SUCCESS: 6,
	SSH_AGENT_EXTENSION_FAILURE: 28,
	SSH_AGENT_IDENTITIES_ANSWER: 12,
	SSH_AGENT_SIGN_RESPONSE: 14
};

cackeySSHAgentInit();
