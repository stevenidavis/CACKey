function backendNameToObject(name) {
	var backend;

	switch (name) {
		case "local":
			backend = chrome.storage.local;
			break;
		case "sync":
			backend = chrome.storage.sync;
			break;
		default:
			throw(new Error("Invalid backend selected:" + name));
			break;
	}

	return(backend);
}

function optionValue(optionName, optionValue) {
	var backend;
	var retrievePromise;

	switch (optionName) {
		case "backend":
			backend = backendNameToObject("local");
			break;
		default:
			backend = backendNameToObject(optionValue("backend"));
			break;
	}

	/*
	 * If a value has been specified, set the parameter -- otherwise retrieve
	 */
	if (optionValue) {
		var setObject = {};
		var previousBackendName, previousBackend;

		/*
		 * If we are changing the backend, migrate settings
		 */
		if (optionName === "backend") {
			previousBackendName = optionValue("backend");
			if (previousBackendName !== optionValue) {
				previousBackend = backendNameToObject(previousBackendName);
			}
		}

		setObject[optionName] = optionValue;

		backend.set(setObject);

		return;
	} else {
		
	}
}
