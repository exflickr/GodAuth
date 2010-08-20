package GodAuthConfig;

our $LogFile		= '/usr/local/wwwGodAuth/auth_log.txt';
our $CookieName		= 'ga';
our $CookieSecret	= '07a8789e03e21147e09b69f21cd38a8b';
our $FailCookieOld      = 'http://auth.myapp.com/login/?fail=old';
our $FailCookieFuture   = 'http://auth.myapp.com/login/?fail=future';
our $FailCookieInvalid  = 'http://auth.myapp.com/login/?fail=invalid';
our $FailNotOnList      = 'http://auth.myapp.com/status/?fail=notonlist';
our $FailNeedsAuth      = 'http://auth.myapp.com/login/';
our $FailConfig         = 'http://auth.myapp.com/?fail=unknownconfig';


#
# the first matching rule is used, so put sub-folders before
# the root!
#

our $PermMap = [


	#
	# URLs with no auth
	#

	{
		url     => qr!^www\.myapp\.com/!,
		who     => 'all',
	},


	#
	# URLs that require a role
	#

	{
		url     => qr!^dev\.myapp\.com/!,
		who     => 'role:staff',
	},


	#
	# URLs only for certain users
	#

	{
		url     => qr!^debug\.myapp\.com/!,
		who     => 'cal',
	},


	#
	# combinations are fine too
	#

	{
		url     => qr!^debug2\.myapp\.com/!,
		who     => ['role:devel', 'cal', 'myles'],
	},


	#
	# anyone with a valid auth token
	#

	{
		url     => qr!^debug2\.myapp\.com/!,
		who     => 'authed',
	},

];
