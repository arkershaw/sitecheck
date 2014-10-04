var system = require('system');

if (system.args.length === 1) {
	console.log('No address specified');
	phantom.exit(1);
}

var url = system.args[1];
var content = system.stdin.read();
var page = require('webpage').create();
var results = {};

page.viewportSize = {
  width: 1280,
  height: 1024
};

page.onConsoleMessage = function (msg) {
	console.log(msg);
};

/*
page.onResourceRequested = function(request) {
	console.log('Resource: ' + JSON.stringify(request, undefined, 4));
};
*/

page.onNavigationRequested = function(url, type, willNavigate, main) {
	if (url !== system.args[1]) {
		if (results[url])
			results[url]++;
		else
			results[url] = 1;
	}
};

page.onLoadFinished = function(status) {
	page.navigationLocked = true;

	var e = page.evaluate(function() {
		return [].map.call(document.getElementsByTagName("*"), function(e) { return { tagName: e.tagName, offsetLeft: e.offsetLeft, offsetTop: e.offsetTop }});
	});

	var d = page.evaluate(function() {
		var html = document.getElementsByTagName('html')[0];
		var body = document.getElementsByTagName('body')[0];
		var w = Math.max(body.scrollWidth, body.offsetWidth, html.clientWidth, html.scrollWidth, html.offsetWidth);
		var h = Math.max(body.scrollHeight, body.offsetHeight, html.clientHeight, html.scrollHeight, html.offsetHeight);
		return { width: w, height: h };
	});

	//sendEvent('click') will not currently work if point is outside viewport
	//https://github.com/ariya/phantomjs/issues/10302
	page.viewportSize = {
		width: d.width,
		height: d.height
	};

	var l = e.length;
	for (var i = l; i--;) {
		page.sendEvent('click', e[i].offsetLeft, e[i].offsetTop);
	}

	for (k in results)
		console.log(k);

	phantom.exit();
};

page.setContent(content, url);

