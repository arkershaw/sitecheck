var system = require('system');

if (system.args.length === 1) {
	console.log('No address specified');
	phantom.exit(1);
}

var page = require('webpage').create();

page.onConsoleMessage = function (msg) {
	console.log(msg);
};

page.onNavigationRequested = function(url, type, willNavigate, main) {
	if (url !== system.args[1])
		console.log(url);
};

page.open(system.args[1], function(status) {
	if (status !== 'success') {
		console.log('Failed to load the address');
		phantom.exit(1);
	}
	else {
		var e = page.evaluate(function() {
			return [].map.call(document.getElementsByTagName("*"), function(e) { return { tagName: e.tagName, offsetLeft: e.offsetLeft, offsetTop: e.offsetTop }});
		});
		var l = e.length;
		for (var i = l; i--;) {
			page.sendEvent('click', e[i].offsetLeft, e[i].offsetTop);
		}

		phantom.exit();
	}
});

