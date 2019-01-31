/*
 * CACKey SSH Agent for ChromeOS
 */

cackeySSHAgentApprovedApps = [
	"pnhechapfaindjhompbnflcldabbghjo"
];

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
			result = [];
			new Uint8Array(bigInt.toByteArray()).forEach(function(e) {
				result.push(e);
			});
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

function cackeySSHAgentEncodeString(string) {
	var result;

	result = cackeySSHAgentEncodeLV(cackeySSHAgentEncodeToUTF8Array(string));

	return(result);
}

function cackeySSHAgentEncodeBinaryToHex(binaryString) {
	var buffer;

	switch (typeof(binaryString)) {
		case "string":
			buffer = binaryString.split("").map(function(c) {
				return(c.charCodeAt(0).toString(16).padStart(2, '0'));
			}).join("");
			break;
		default:
			buffer = [];
			new Uint8Array(binaryString).map(function(c) {
				buffer.push(c.toString(16).padStart(2, '0'));
			});
			buffer = buffer.join("");
			break;
	}

	return(buffer);
}

function cackeySSHAgentEncodeCertToKeyAndID(cert) {
	var result = null, resultKey = null;
	var certObj;
	var publicKey;

	certObj = new X509;
	if (!certObj) {
		return(result);
	}

	certObj.readCertHex(cackeySSHAgentEncodeBinaryToHex(cert));

	publicKey = certObj.getPublicKey();

	switch (publicKey.type) {
		case "RSA":
			resultKey = cackeySSHAgentEncodeString("ssh-rsa");
			resultKey = resultKey.concat(cackeySSHAgentEncodeBigInt(publicKey.e));
			resultKey = resultKey.concat(cackeySSHAgentEncodeBigInt(publicKey.n));
			break;
		default:
			console.log("[cackeySSH] Unsupported public key type:", publicKey.type, "-- ignoring.");
	}

	if (resultKey) {
		result = {
			id: certObj.getSubjectString(),
			key: resultKey
		};
	}

	return(result);
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
	certs = await cackeyListCertificates();

	/*
	 * Convert each certificate to an SSH key blob
	 */
	certs.forEach(function(cert) {
		var key;

		key = cackeySSHAgentEncodeCertToKeyAndID(cert.certificate);

		if (key) {
			keys.push(key);
		}
	});

	/*
	 * Encode response
	 */
	response = [];

	response.push(cackeySSHAgentMessage.SSH_AGENT_IDENTITIES_ANSWER);
	response = response.concat(cackeySSHAgentEncodeInt(keys.length));
	keys.forEach(function(key) {
		response = response.concat(cackeySSHAgentEncodeLV(key.key));
		response = response.concat(cackeySSHAgentEncodeString("CACKey: " + key.id));
	});

	return(response);
}

async function cackeySSHAgentCommandSignRequest(request) {
	var keyInfo, data, flags;
	var certs, certToUse;
	var hashMethod, signedData, signedDataHeader, signRequest;
	var response;
	var flagMeaning = {
		SSH_AGENT_RSA_SHA2_256: 2,
		SSH_AGENT_RSA_SHA2_512: 4
	};

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
	certs = await cackeyListCertificates();
	certToUse = null;
	certs.forEach(function(cert) {
		var key;

		key = cackeySSHAgentEncodeCertToKeyAndID(cert.certificate);

		if (key.key.join() == keyInfo.join()) {
			certToUse = cert;
		}
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
	if ((flags & flagMeaning.SSH_AGENT_RSA_SHA2_512) == flagMeaning.SSH_AGENT_RSA_SHA2_512) {
		hashMethod = "SHA512";
		data = await crypto.subtle.digest("SHA-512", new Uint8Array(data));
	} else if ((flags & flagMeaning.SSH_AGENT_RSA_SHA2_256) == flagMeaning.SSH_AGENT_RSA_SHA2_256) {
		hashMethod = "SHA256";
		data = await crypto.subtle.digest("SHA-256", new Uint8Array(data));
	} else if (flags == 0) {
		hashMethod = "SHA1";
		data = await crypto.subtle.digest("SHA-1", new Uint8Array(data));
	} else {
		console.info("[cackeySSH] Sign request with flags set to", flags, "which is unsupported, failing the request.");

		return(null);
	}

	/*
	 * Sign the data
	 */
	signRequest = {
		hash: hashMethod,
		digest: new Uint8Array(data)
	};
	signedData = await cackeySignMessage(signRequest);
	signedData = Array.from(new Uint8Array(signedData));

	/*
	 * Encode signature
	 */
	switch (hashMethod) {
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
			signedDataHeader = [];
			break;
	}
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

	socket.postMessage(sshResponse);

	return;
}

function cackeySSHAgentAcceptConnection(socket) {
	if (!socket) {
		return;
	}

	/*
	 * Only accept connections from approved apps
	 */
	if (!socket.sender || !socket.sender.id || !cackeySSHAgentApprovedApps.includes(socket.sender.id)) {
		console.log("[cackeySSH] Disconnecting unapproved app: ", socket.sender);

		socket.disconnect();

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