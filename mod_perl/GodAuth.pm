package GodAuth;

use warnings;
use strict;

use GodAuthConfig;
use Apache2::RequestRec ();
use Apache2::Connection;
use Apache2::Const -compile => qw(OK REDIRECT REMOTE_NOLOOKUP FORBIDDEN);
use APR::Table;
use Digest::SHA1 qw(sha1_hex);
use MIME::Base64;
use Data::Dumper;

use Sys::Hostname;

our $last_reload_time = time();
our $reload_timeout = 60; # per apache process!

$| = 1;

##############################################################################################################

sub handler {

	#
	# get URL
	#

	my $r = shift;

	my $domain = $r->headers_in->{'Host'} || 'UNKNOWN-HOST';
	my $path = $r->unparsed_uri;

	$ENV{GodAuth_User} = '';

	my $url = $domain . $path;
	my $log = "$$ URL : $url";


	#########################################################
	#
	# reload the config?
	#

	if (time() - $GodAuth::last_reload_time > $GodAuth::reload_timeout){

		&GodAuth::reload_config();
		$GodAuth::last_reload_time = time();
	}

	
	#########################################################
	#
	# 1) check we have a cookie secret
	#
	if (!$GodAuthConfig::CookieSecret){
		$GodAuthConfig::CookieSecret = 'nottherightsecret';
	}	


	#########################################################
	#
	# 1) determine if we need to perform access control for this url
	#

	my $allow = 'none';

	for my $obj (@{$GodAuthConfig::PermMap}){

		if ($url =~ $obj->{url}){

			$allow = $obj->{who};
			last;
		}
	}

	$log .= " $allow";

	
	#########################################################
	#
	# 2) we might need auth - see if we have a valid cookie
	#

	my $cookie_is_valid = 0;
	my $cookie_user = '?';
	my $cookie_roles = '_';

	my $cookie_is_old = 0;
	my $cookie_age = 0;
	my $cookie_is_future = 0;

	my $cookies = &parse_cookie_jar($r->headers_in->{'Cookie'});

	my $cookie = $cookies->{$GodAuthConfig::CookieName};

	if ($cookie){

		my ($user, $roles, $ts, $hmac) = split '-', $cookie, 4;

		my $ua = $r->headers_in->{'User-Agent'};
		
		if ($ua =~ /AppleWebKit/) {
			$ua = "StupidAppleWebkitHacksGRRR";
		}
		$ua =~ s/ FirePHP\/\d+\.\d+//;

		my $raw = "$user-$roles-$ts-$ua";

		#&xlog("COOKIE: $cookie $raw\n");

		my $hmac2 = sha1_hex( $GodAuthConfig::CookieSecret . $raw );

		if ($hmac eq $hmac2){

			#
			# check that our cookie isn't too old
			#

			$cookie_age = time() - $ts;
			$ENV{GodAuth_Cookie_Age} = $cookie_age;

			if ($ts < time() - 8 * 60 * 60 && $user !~ /\:/){

				#
				# cookie is old (only for non-alpha users
				#

				$cookie_is_old = 1;
				$cookie_age = time() - $ts;

				$log .= " (bad cookie ts $ts - it's too old - $cookie_age seconds)";

			}elsif ($ts > time() + 5 * 60){

				#
				# cookie starts in the future - wtf
				#

				$cookie_is_future = 1;

				$log .= " (bad cookie ts $ts - it starts in the future)";

			}else{

				$cookie_is_valid = 1;
				$cookie_user = $user;
				$cookie_roles = $roles;

				$r->headers_in->set('GodAuth-User', $cookie_user);
				$r->headers_in->set('GodAuth-Roles', $cookie_roles);

				$ENV{GodAuth_User} = $cookie_user;
				$ENV{GodAuth_Roles} = $cookie_roles;

				$r->notes->add("GodAuth_User" => $cookie_user);
				$r->notes->add("GodAuth_Roles" => $cookie_roles);

				$log .= " (cookie: $cookie_user $cookie_roles)";
			}
		}else{
			$log .= " (bad cookie hmac [$GodAuthConfig::CookieSecret$user-$ts-$ua] -> $hmac2 vs $hmac)";
		}
	}else{
		$log .= " (no cookie)";
	}

	&xlog($log."\n");


	#########################################################
	#
	# 3) exit now if we got an 'all'
	#

	if (ref $allow ne 'ARRAY'){
		if ($allow eq 'all'){

			return Apache2::Const::OK;
		}
	}


	#########################################################
	#
	# 4) if we don't have a valid cookie, redirect to the auther
	#

	if (!$cookie){
		return &redir($r, $url, $GodAuthConfig::FailNeedsAuth);
	}

	if ($cookie_is_old){
		return &redir($r, $url, $GodAuthConfig::FailCookieOld);
	}

	if ($cookie_is_future){
		return &redir($r, $url, $GodAuthConfig::FailCookieFuture);
	}

	if (!$cookie_is_valid){
		return &redir($r, $url, $GodAuthConfig::FailCookieInvalid);
	}


	#########################################################
	#
	# 5) exit now for authed
	#

	if (ref $allow ne 'ARRAY'){
		if ($allow eq 'authed'){

			return Apache2::Const::OK;
		}
	}


	#########################################################
	#
	# 5) now we need to match usernames and/or roles
	#

	# get arrayref of allowed roles
	unless (ref $allow eq 'ARRAY'){
		$allow = [$allow];
	}

	# get arrayref of our roles
	my $matches = [$cookie_user];
	for my $role(split /,/, $cookie_roles){
		if ($role ne '_'){
			push @{$matches}, 'role:'.$role;
		}
	}


	for my $a (@{$allow}){
		for my $b (@{$matches}){

			if ($a eq $b){
				return Apache2::Const::OK;
			}
		}
	}


	#
	# send the user to the not-on-list page
	#

	return &redir($r, $url, $GodAuthConfig::FailNotOnList);
}

##############################################################################################################

sub redir {
	my ($r, $ref, $url) = @_;

	$ref = &urlencode('http://'.$ref);
	$url .= ($url =~ /\?/) ? "&ref=$ref" : "?ref=$ref";

	$r->headers_out->set('Location', $url);
	return Apache2::Const::REDIRECT;
}

##############################################################################################################

sub xlog {
	return unless $GodAuthConfig::LogFile;
	open F, '>>'.$GodAuthConfig::LogFile;
	print F $_[0];
	close F;
}

##############################################################################################################

sub parse_cookie_jar {
	my ($jar) = @_;

	return {} unless defined $jar;

	my @bits = split /;\s*/, $jar;
	my $out = {};
	for my $bit (@bits){
		my ($k, $v) = split '=', $bit, 2;
		$k = &urldecode($k);
		$v = &urldecode($v);
		$out->{$k} = $v;
	}
	return $out;
}

##############################################################################################################

sub urldecode {
	$_[0] =~ s!\+! !g;
	$_[0] =~ s/%([a-fA-F0-9]{2,2})/chr(hex($1))/eg;
	return $_[0];
}

sub urlencode {
	$_[0] =~ s!([^a-zA-Z0-9-_ ])! sprintf('%%%02x', ord $1) !gex;
	$_[0] =~ s! !+!g;
	return $_[0];
}

##############################################################################################################

sub reload_config {
	open F, "/usr/local/wwwGodAuth/GodAuthConfig.pm";
	my $data = '';
	while (<F>){
		$data .= $_;
	}
	close F;
	eval $data;
}

##############################################################################################################

1;

