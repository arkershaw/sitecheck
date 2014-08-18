var system = require('system');

if (system.args.length === 1) {
	console.log('No address specified');
	phantom.exit(1);
}

var url = system.args[1];
var content = system.stdin.read();
var page = require('webpage').create();

page.onConsoleMessage = function (msg) {
	console.log(msg);
};

/*
page.onResourceRequested = function(request) {
	console.log('Resource: ' + JSON.stringify(request, undefined, 4));
};
*/

page.onNavigationRequested = function(url, type, willNavigate, main) {
	if (url !== system.args[1])
		console.log(url);
};

page.onLoadFinished = function(status) {
	page.navigationLocked = true;

	var e = page.evaluate(function() {
		return [].map.call(document.getElementsByTagName("*"), function(e) { return { tagName: e.tagName, offsetLeft: e.offsetLeft, offsetTop: e.offsetTop }});
	});

	var l = e.length;

	for (var i = l; i--;) {
		page.sendEvent('click', e[i].offsetLeft, e[i].offsetTop);
	}

	//phantom.exit();
};

page.setContent(content, url);

