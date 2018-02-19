# sighte - simple webkit-based browser

sighte is a simple Web browser using the WebKit2 layout engine, the
JavascriptCore evaluation library, and GTK3+ as main GUI.

Originally this had been an experiment designed for research into
cybernetic and wearable technologies, but at this time it is primarily a
sort of minimalism-inspired browser; no fancy GUI, no tabs, etc.

The code itself is based off of a fork of the surf browser created by the
team at surf.suckless.org, which they implemented in Webkit1 and GTK2,
using dmenu as a way to interact with X11.

The sighte GUI code is a rewrite that relies on GTK3 and glibc for instead
of the suckless libraries / binaries. This derives a bit from the suckless
philosophy, but this browser is still quite lean and minimal when compared
to other popular choices.

On the backend side, the WebKit engine code has been replaced with newer
Webkit2 functionality, which required a considerable rewrite of much of the
original forked code.

In theory, you could use this browser as a replacement for a more mainstream
browser (e.g. Firefox / Chrome) at this time. However, certain threaded
performance aspects are lacking, since some non-HTTPS sites (esp. non-standard
wikis) tend to just dump dozens or even hundreds of GET requests or the like.

Perhaps one day additional performance features will be added, but for now
it is still fairly usable even in its current form.

Consider reading the *Basic Usage Instructions* at a minimum to get the hang
of using this browser.


# Requirements

The browser itself was designed around a standard Debian Linux environment,
wherein the following packages are required:

* glib-2
* libgtk-3-0
* libgtk-3-dev
* libwebkit2gtk-4.0-37
* libwebkit2gtk-4.0-dev
* meson

This browser has also been tested on Ubuntu and Archlinux successfully.

For different distros of the Linux, the package names might vary. Feel free
to contact me if your distro needs other packages and I will make note of it
in future versions of this readme.

In order to make building on as many distros as simple as possible, this
repo contains a Meson script that should attempt to autolocate as many of
these packages as possible, assuming they are installed on your system.

As a final recourse, I recommend examining the Meson file for more details if
you are unable to get sighte to properly compile.


# Installation

The philosophy of this browser extends towards minimalism, and thus is
directed at more expert users.

Start by running make to see if it will compile. Obtain any needed packages
via the package manager of your distro. Edit the Makefile to adjust the
respective Webkit2 / GTK3 requirements to their proper places.

Afterwards enter the following command to build and install sighte (if
necessary as root):

```
make install
```

# Running sighte

sighte [-DfFgGiImMpPsSvx] [-a cookiepolicies] [-c cookiefile]
       [-r scriptfile] [-t stylefile] [-z zoomlevel] [URI]

See the manpage for further options.


# Basic Usage Instructions

By default, the browser opens to the home page specified in config.h

* Ctrl-w opens a new window.

* Ctrl-g will navigate the user to the given URL.

* Ctrl-h returns the user back to the home page.

* Ctrl-f allows you to search for text.

* Ctrl-/ does the same as the above.

* Ctrl-n takes you to the next find result.

* Ctrl-N takes you to the previous find result.

See the man page for more information.


# Authors

This was forked and adapted to Webkit2 by Robert Bisewski at Ibis
Cybernetics. For more information, contact:

* Website -> www.ibiscybernetics.com

* Email -> contact@ibiscybernetics.com

The original authors of the surf web browser were the suckless.org
community. For more information, consider contacting them at:

* Website -> surf.suckless.org
