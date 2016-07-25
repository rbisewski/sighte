#
# sighte - simple webkit-based browser
#

sighte is a simple Web browser using the WebKit2 layout engine, the
JavascriptCore evaluation library, and GTK3+ as main GUI.

Originally this had been an experiment designed for research into
cybernetic and wearable technologies, but at this time it is primarily a
sort of overly simplistic browser with not much functionality.

The code itself is based off of a fork of the surf browser created by the
team at surf.suckless.org, which they implemented in Webkit1 and GTK2,
using dmenu as a way to interact with X11. This project borrows from their
original design and parts of their code base.

Parts of it are still broken from the transition to Wekbit2 and GTK3+ which
are *quite* a bit different. It is not recommended to use this browser as a
replacement for a more mainstream browser (e.g. Firefox / Chrome) at this
time.

Perhaps one day it will be completed, but for now it is still fairly usable
even in its current form.


#
# Requirements
#

Specifically, the following packages are required:

* gtk-3
* glib-2
* webkit2-gtk-4

Recommend examining the Makefile for more details if you are unable to get
sighte to properly compile.


#
# Installation
#

Edit the Makefile to adjust the respective Webkit2 / GTK3 requirements to
their proper places.

Afterwards enter the following command to build and install sighte (if
necessary as root):

    make clean install

#
# Running sighte
#

sighte [-DfFgGiImMpPsSvx] [-a cookiepolicies] [-c cookiefile]
       [-r scriptfile] [-t stylefile] [-z zoomlevel] [URI]

See the manpage for further options.

#
# Author
#

The original authors of the surf web browser were the suckless.org
community. For more information, consider contacting them at:

* Website -> surf.suckless.org

This was forked and adapted to Webkit2 by Robert Bisewski at Ibis
Cybernetics. For more information, contact:

* Website -> www.ibiscybernetics.com

* Email -> contact@ibiscybernetics.com
