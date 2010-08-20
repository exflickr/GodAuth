GodAuth
=======

A system for handling single-signon authentication across multiple web apps under apache.


Design
------

You create a simple signin system that take your user's authentication credentials (username, password, whatever)
and compares it to your user database. It then mints a signed cookie containing the username and a list of 'roles'.
A mod_perl layer then checks this cookie for every request, allowing or denying it based on a set of rules where
different URL regexps require different users or roles. It then exposes the username and roles of the authenticated
user to the underlying applications via environment variables and request headers.

Because it sits in the Apache layer, you can use it to control access to multiple applications - svn browsers, wikis, 
bug trackers, database admin tools, deploy tools, monitoring, pastebins, logs, etc.


Installation
------------

1. Copy all the files in the <code>mod_perl</code> folder to somewhere on your server that Apache can read from.
2. Adjust values in <code>GodAuthConfig.pm</code> to match your setup.
3. Modify the path in <code>GodAuthInit.pl</code>.
4. Modify the config path at the bottom of <code>GodAuth.pm</code>.
5. Modify the path in <code>god_auth.conf</code>.
6. Symlink <code>god_auth.conf</code> into <code>/etc/httpd/conf.d</code> (or your local equivalent).

Patches to make this less path-edity are welcome. Setting an environment variable in <code>GodAuthInit.pl</code> 
is probably a good approach.

1. Setup the login webapp.
2. But it's not done yet...
