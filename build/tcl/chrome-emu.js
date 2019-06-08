
console = {
	log: function() {
		/* XXX:TODO: Logging */
	}
}
chrome = {
	runtime: {
		connectCallbacks: [],
		onConnectExternal: {
			addListener: function(callback) {
				if (!callback) {
					return;
				}

				chrome.runtime.connectCallbacks.push(callback)
			},
			removeListener: function(callback) {
				var idx;
				idx = chrome.runtime.connectCallbacks.indexOf(callback);
				if (idx == -1) {
					return;
				}

				chrome.runtime.connectCallbacks.splice(idx, 1);
			}
		}
	}
}
