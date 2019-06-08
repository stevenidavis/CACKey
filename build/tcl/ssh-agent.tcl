#! /home/rkeene/tmp/cackey/build/tcl/tclkit

package require duktape
package require tuapi

proc initSSHAgent {} {
	if {[info exists ::jsHandle]} {
		return
	}

	set chromeEmuJS [read [open chrome-emu.js]]
	set sshAgentJS [read [open ssh-agent-noasync.js]]

	set ::jsHandle [::duktape::init]

	::duktape::eval $::jsHandle $chromeEmuJS
	::duktape::eval $::jsHandle $sshAgentJS

	puts [::duktape::eval $::jsHandle {
		chrome.runtime.connectCallbacks[0]({
			sender: {
				id: "pnhechapfaindjhompbnflcldabbghjo"
			},
			onMessage: {
				addListener: function() {
					/* XXX:TODO */
				}
			}
		})
	}]
}

initSSHAgent
