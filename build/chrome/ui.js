var globalCerts = null;

function displayCerts(htmlObject, certs) {
	var html = "";
	var idx;
	var cert, certTitle;
	var certObj;
	var ignoredException;

	if (certs.length == 0) {
		htmlObject.innerHTML = "<b>No certificates found</b>";

		return;
	}

	certObj = new X509;

	html += "<ol type=\"1\">";

	for (idx = 0; idx < certs.length; idx++) {
		cert = certs[idx];

		certObj.readCertHex(BAtohex(new Uint8Array(cert.certificate)));

		certTitle = certObj.getSubjectString();
		try {
			certObj.getExtSubjectAltName2().forEach(function(itemPair) {
				var itemName, itemValue;

				itemName = itemPair[0];
				itemValue = itemPair[1];

				if (itemName === "MAIL") {
					certTitle = itemValue;
				}
			});
		} catch (ignoredException) {};

		html += "\t<li>";
		html += "\t\t" + certTitle;
		html += "\t\t<ol type=\"a\">";
		html += "\t\t\t<li>Serial Number: " + certObj.getSerialNumberHex() + "</li>";
		try {
			html += "\t\t\t<li>Usage: " + certObj.getExtKeyUsageString() + "</li>";
		} catch (ignoredException) {};
		html += "\t\t</ol>";
		html += "\t</li>";
	}

	html += "</ol>";

	delete certObj;

	htmlObject.innerHTML = html;

	return;
}

function updateCertificates(htmlObject) {
	var html = "";

	if (globalCerts == null) {
		htmlObject.innerHTML = "<i>Updating...</i>";
	} else {
		displayCerts(htmlObject, globalCerts);
	}

	parentWindow.cackeyListCertificates(function(certs) {
		/*
		 * If there is an error then we are invoked with no certs
		 * parameter at all, fake one.
		 */
		if (!certs) {
			certs = [];
		}

		globalCerts = certs;

		displayCerts(htmlObject, certs);

		return;
	});

	return;
}

function updateCertificateProvider(htmlObject) {
	var resultHTML;

	if (chrome.certificateProvider) {
		resultHTML = "Yes (ChromeOS)";
	} else {
		resultHTML = "<b>No, informational only.</b>";
	}

	htmlObject.innerHTML = resultHTML;

	return;
}

function updateSmartcardReaders(htmlObject) {
	parentWindow.cackeyListReaders(function(readers) {
		var idx;
		var reader;
		var resultHTML;

		if (!readers) {
			readers = [];
		}

		resultHTML = "Count: " + readers.length;

		if (readers.length > 0) {
			resultHTML += "<br>";

			resultHTML += "<ol type=\"1\">";
			for (idx = 0; idx < readers.length; idx++) {
				reader = readers[idx];

				resultHTML += "<li>" + reader.readerName.trim() + ", card inserted: " + (reader.cardInserted ? "yes" : "no") + "</li>";
			}

			resultHTML += "</ol>";
		} else {
			resultHTML += " (is the Smartcard Manager Application working?)";
		}

		htmlObject.innerHTML = resultHTML;

		return;
	});

	return;
}

function clearStatusInfo() {
	document.getElementById('certificates').innerHTML = '<i>Loading...</i>';
	document.getElementById('smartcard_readers').innerHTML = '<i>Loading...</i>';
	document.getElementById('certificate_provider').innerHTML = '<i>Loading...</i>';
	document.getElementById('pin_caching_timeout').value = '';
	document.getElementById('ssh_agent_enabled').checked = false;
	document.getElementById('ssh_agent_keys').checked = false;
	document.getElementById('ssh_agent_certs').checked = false;
	document.getElementById('ssh_agent_certs_legacy').checked = false;
}

function loadStatusInfo() {
	updateCertificates(document.getElementById('certificates'));
	updateSmartcardReaders(document.getElementById('smartcard_readers'));
	updateCertificateProvider(document.getElementById('certificate_provider'));
	// updateOptions(getOptions());
}

setTimeout(function() {
	loadStatusInfo();

	document.getElementById('reload').onclick = function() {
		clearStatusInfo();
		setTimeout(function() {
			loadStatusInfo();
		}, 1);
	};
	
	return;
}, 1);
