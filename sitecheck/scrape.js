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

	var l = e.length;
	for (var i = l; i--;) {
		if (
			e[i].offsetTop < page.scrollPosition.top ||
			e[i].offsetTop > page.scrollPosition.top + page.viewportSize.height ||
			e[i].offsetLeft < page.scrollPosition.left ||
			e[i].offsetLeft > page.scrollPosition.left + page.viewportSize.width
			) {
			page.scrollPosition = {
			  top: e[i].offsetTop - 10,
			  left: e[i].offsetLeft - 10
			};
		}

		page.sendEvent('click', e[i].offsetLeft, e[i].offsetTop);
	}

	count = 0;
	for (k in results) {
		count++;
		console.log(k);
	}

	console.log(count);

	phantom.exit();
};

page.setContent(content, url);

