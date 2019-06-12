console = {};
console._formatArgs = function(argInfo) {
	var idx, outArray;
	var arg;

	idx = 0;
	outArray = [];
	for (idx = 0; idx < argInfo.length; idx++) {
		arg = argInfo[idx];
		if (typeof(arg) === 'string' || typeof(arg) === 'number') {
			outArray.push(arg);
		} else if (typeof(arg) === 'undefined') {
			outArray.push("<undefined>");
		} else if (arg === null) {
			outArray.push("<null>");
		} else {
			outArray.push(JSON.stringify(arg));
		}
	}
	return(outArray.join(' '));
}
console.log = function() {
	runtime.puts("CON> " + console._formatArgs(arguments));
}
console.error = function(message) {
	runtime.puts(runtime.stderr, "ERR> " + console._formatArgs(arguments));
	return;
}
console.debug = function(message) {
	runtime.puts(runtime.stderr, "DBG> " + console._formatArgs(arguments));
	return;
}

if (!Array.from) {
	Array.from = function(source) {
		var result, idx;
		result = new Array(source.length);
		for (idx = 0; idx < source.length; idx++) {
			result[idx] = source[idx];
		}
		return(result);
	}
}

if (!Array.prototype.slice) {
	Array.prototype.slice = function(start) {
		var result, idx, outIdx;
		result = [];
		outIdx = 0;
		for (idx = start; idx < this.length; idx++) {
			result[outIdx] = this[idx];
			outIdx++;
		}
		return(result);
	}
}

if (!String.prototype.padStart) {
	String.prototype.padStart = function(len, char) {
		if (this.length >= len) {
			return(this);
		}

		return((char + this).padStart(len, char))
	}
}

if (!RegExp.prototype.compile) {
	RegExp.prototype.compile = function() {
		return;
	};
}

if (!Uint8Array.prototype.forEach) {
	Uint8Array.prototype.forEach = function(callback) {
		var idx;
		for (idx = 0; idx < this.length; idx++) {
			callback(this[idx]);
		}
	}
}

if (!Uint8Array.prototype.map) {
	Uint8Array.prototype.map = function(callback) {
		var result, idx;
		result = [];

		for (idx = 0; idx < this.length; idx++) {
			result.push(callback(this[idx]));
		}

		return(result);
	}
}

navigator = {
	userAgent: ""
};

crypto = {
	subtle: {
		digest: function(hash, data) {
			var bufferData;
			bufferData = new Buffer(data);
			return(crypto.subtle.digest.internal(hash, bufferData));
		}
	}
};

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
};

chrome.runtime.externalConnect = function(data) {
	chrome.runtime.connectCallbacks.forEach(function(callback) {
		callback(data);
	});
};
