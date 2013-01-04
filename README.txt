Copyright 2009-2013 Andrew Kershaw
Licensed under the GNU Affero General Public License v3 (see "LICENSE.txt" file).

Dependencies:

	Python 3

	*pyenchant does not currently work with Python 3.3 although Python 3.2 works fine.

	HTML Tidy, pytidylib (validation, accessibility)
	Enchant, pyenchant (spelling)
	dnspython3, pyOpenSSL (domain check)

	*The version of pytidylib in PyPI is not yet updated for Python 3 so easy_install or pip will not install the required version. The source is available here:

	https://github.com/countergram/pytidylib/

	Using VirtualEnv is recommended due to the development status of these dependencies. Alternatively, on Linux they can be symlinked into the site-packages directory rather than installed.

Installation:

	Windows:

		Download and install the following:
		Python 3: http://www.python.org/download/

		pyenchant (if spellcheck is required): http://www.rfk.id.au/software/pyenchant/download.html (the Windows installer includes the Enchant library)
		pytidylib (if validation or accessibility are required): http://countergram.com/open-source/pytidylib

		The version of pyopenssl from PyPI should work fine - pip is the best way to install this. Altrenatively: http://pypi.python.org/pypi/pyOpenSSL/

		To install pytidylib and sitecheck, download and extract each archive then open a command window in the same directory as the extracted files and type:

		setup.py install

		You will also need the HTML Tidy library. Instructions are available here:

		http://countergram.com/open-source/pytidylib/docs/index.html

		Alternatively, download a binary from here and place it somewhere on your path:

		HTML Tidy: http://tidy.sourceforge.net/#binaries

	Linux:

		Packages for dependencies should be available from your distribution's package manager or installable via pip or the links above. Install all dependencies and then extract the archive and run:

		./setup.py install

Usage:

	Windows:

		C:\Python32\Scripts\runsitecheck.py -d http://www.domain-goes-here C:\path\to\output

	Linux:

		runsitecheck.py -d http://www.domain-goes-here /path/to/output

	To specify the default page, use the -p switch:

		runsitecheck.py -d http://www.domain-goes-here -p home.html /path/to/output

	See "configuration" below for running repeated tests against the same domain.

While running:

	Ctrl+c will prompt for abort or suspend.

	To resume a suspended job or use an existing configuration file, run the script with the path to an existing output directory:

		runsitecheck.py /path/to/output

Modules:

	Persister -> Downloads site files to disk for further analysis. Disabled by default.

	InboundLinks -> Checks URLs in the search result listings from the Google and Bing search engines. Disabled by default.

	RegexMatch -> Checks for regular expression match in headers and content. To search for headers which don't match a regular expression, prefix the name with ^ and to search for content which doesn't match, prefix with _

	Validator -> Lists validation errors. Disabled by default.

	Accessibility -> Outputs selected accessibility warnings (those that can be automatically tested). Disabled by default.

	MetaData -> Checks for missing/empty/duplicate meta title, description and keywords.

	StatusLog -> Logs any 4xx and 5xx responses. Also checks outbound links.

	Security -> Attempts basic SQL injection and XSS attacks on get and post parameters. Disabled by default.

	Comments -> Logs the content of any HTML comments found.

	Spelling -> Spellcheck using Enchant. Custom dictionary words are in the file "dict.txt". Disabled by default.

	Spider -> If this module is disabled, only a single page will be analysed. Scans all files under the domain/path as well as testing targets of external links.

	Readability -> Calculates the Flesch Reading Ease score and logs it if it is below the specified threshold.

	DuplicateContent -> Checks for the same response with different URLs.

	DomainCheck -> Gets important domain information including expiry date, SSL certificate expiry date, reverse DNS etc. Uses a whois proxy with a limit of 50 hits per day. Disabled by default.

	Authenticate -> Issues requests to authenticate with the target site before spidering beings. If specified, logout requests will be executed after spidering ends. Disabled by default.

	RequestList -> Define a list of requests manually which are executed in sequence. Disabled by default.

	RequiredPages -> Creates a list of required URLs which are logged if they are not found on the site. Disabled by default.

	InsecureContent -> Logs insecure content referenced from secure pages.

Configuration:

	Configuration for the spider and individual modules can be found in "config.py".

	For site-specific configuration, copy config.py to the output directory specified on the command line. The domain and path properties can be specified in the config file and subsequently omitted from the command line (as with resuming a suspended job above). This config file will be used instead of the default. The custom dictionary file for the spelling module (dict.txt) can also be overridden by copying to the same location.
