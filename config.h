//! config.h
/*
 *  Description: The purpose of this file is to serve as a kind of
 *               easy-to-adjust configuration.
 */

// Variable to control debug mode
static bool debug_mode  = false;

// User agent of browser.
static char *useragent  = "Mozilla/5.0 (X11; U; Unix; en-US) "
                          "AppleWebKit/537.15 (KHTML, like Gecko) "
                          "Chrome/53.0.2785.89 Safari/537.15 Sighte/"VERSION;

// Default page title
static const char *default_page_title = "sighte Browser";

// Default home page.
static const char *default_home_page = "https://start.duckduckgo.com";

// JS Script variables
static const char *scriptfile = "~/.sighte/script.js";
static char *styledir         = "~/.sighte/styles/";
static char *cachefolder      = "~/.sighte/cache/";

// Start the browser in a normal, non-fullscreen fashion.
static bool runinfullscreen = false;

// Zoom related variables
static unsigned int defaultfontsize = 12; 
static double zoomlevel = 1.0;

// Cookie variables 
//
// A: accept all
// a: accept nothing
// @: accept all except third party
//
static char *cookiefile     = "~/.sighte/cookies.txt";
static char *cookiepolicies = "Aa@"; 

// Certificate variables
static char *cafile       = "/etc/ssl/certs/ca-certificates.crt";
static bool strictssl     = false; // Use this to accept / refuse untrusted
                                   // SSL connections
static time_t sessiontime = 3600;

// Webkit default features
static bool enablespatialbrowsing = true;
static bool enablediskcache       = false;
static int  diskcachebytes        = 5 * 1024 * 1024;
static bool enableplugins         = true;
static bool enablescripts         = true;
static bool enablestyle           = true;
static bool loadimages            = true;
static bool allowgeolocation      = true;

//! Macro to handle downloads via xterm+curl.
/*!
 * @param    string   URI where the file to download is located.
 * @param    string   referring URI base location.
 *
 * @return   string   commandline arguments to hand-off to a forked process.
 */
#define CURL(d,r) { \
    .v = (char *[]){ "/usr/bin/xterm", "-e", \
         "/usr/bin/curl", "-L", "-J", "-O", "--user-agent", useragent, \
         "--referer", r, "-b", cookiefile, "-c", cookiefile, d, NULL \
    } \
}

// List of styles to be stored into the given filename.
//
// Note: the functions using these array look for the first match and then
//       stop check the remainder.
//
static SiteStyle styles[] = {
	/* regexp               file in $styledir */
	{ ".*",                 "default.css" },
};

// Hot Keys
//
// Binds certain key strokes to give functions, via an array. The elements
// themselves are defined as such.
//
// {Modifier, Keyval, Function, Arg}
//
// NOTE: When using anything other an GDK_CONTROL_MASK / GDK_SHIFT_MASK, consider
//       wiping the key input with CLEANMASK() for safety reasons; GNOME and
//       MATE and other WMs might be utilizing GTK as well during the same
//       session.
//
static Key keys[] = {

    /* Printer Options */    
    { GDK_CONTROL_MASK|GDK_SHIFT_MASK,  GDK_KEY_r,             reload,              { .b = true } },
    { GDK_CONTROL_MASK,                 GDK_KEY_r,             reload,              { .b = false } },

    /* Printer Options */    
    { GDK_CONTROL_MASK|GDK_SHIFT_MASK,  GDK_KEY_p,             print,               { 0 } },
   
    /* Copy & Paste to Clipboard */ 
    { GDK_CONTROL_MASK,                 GDK_KEY_p,             clipboard,           { .b = true } },
    { GDK_CONTROL_MASK,                 GDK_KEY_y,             clipboard,           { .b = false } },

    /* Zoom Out */    
    { GDK_CONTROL_MASK,                 GDK_KEY_z,             zoom,                { .i = -1 } },
    
    /* Zoom In */    
    { GDK_CONTROL_MASK|GDK_SHIFT_MASK,  GDK_KEY_z,             zoom,                { .i = +1 } },
   
    /* Goto Next Page */ 
    { GDK_CONTROL_MASK,                 GDK_KEY_greater,       navigate,            { .i = +1 } },
    
    /* Goto Previous Page */ 
    { GDK_CONTROL_MASK,                 GDK_KEY_less,          navigate,            { .i = -1 } },
    
    /* Goto Home Page */ 
    { GDK_CONTROL_MASK,                 GDK_KEY_h,             navigate,            { .i = 0 } },
   
    /* Toggle Fullscreen Mode */ 
    { 0,                                GDK_KEY_F11,           fullscreen,          { 0 } },

    /* Halt Page Load */ 
    { 0,                                GDK_KEY_Escape,        stop,                { 0 } },

    /* Open Inspector */
    { GDK_CONTROL_MASK,                 GDK_KEY_o,             inspector,           { 0 } },
   
    /* Goto another URL */ 
    { GDK_CONTROL_MASK,                 GDK_KEY_g,             opendialog,          { .i = DIALOG_ACTION_GO } },

    /* Find Given Text Content on Page */ 
    { GDK_CONTROL_MASK,                 GDK_KEY_f,             opendialog,          { .i = DIALOG_ACTION_FIND } },
    { GDK_CONTROL_MASK,                 GDK_KEY_slash,         opendialog,          { .i = DIALOG_ACTION_FIND } },
   
    /* Find Next / Previous Query */ 
    { GDK_CONTROL_MASK,                 GDK_KEY_n,             find,                { .b = true } },
    { GDK_CONTROL_MASK|GDK_SHIFT_MASK,  GDK_KEY_n,             find,                { .b = false } },
   
    /* Caret Browsing */ 
    { GDK_CONTROL_MASK|GDK_SHIFT_MASK,  GDK_KEY_c,             toggle,              { .v = "enable-caret-browsing" } },
    
    /* Enable / disable Images */ 
    { GDK_CONTROL_MASK|GDK_SHIFT_MASK,  GDK_KEY_i,             toggle,              { .v = "auto-load-images" } },
    
    /* Enable / disable Javascript */ 
    { GDK_CONTROL_MASK|GDK_SHIFT_MASK,  GDK_KEY_s,             toggle,              { .v = "enable-scripts" } },
    
    /* Enable / disable Browser Plugins */ 
    { GDK_CONTROL_MASK|GDK_SHIFT_MASK,  GDK_KEY_v,             toggle,              { .v = "enable-plugins" } },

    /* Toggle Cookie Policy */ 
    { GDK_CONTROL_MASK|GDK_SHIFT_MASK,  GDK_KEY_a,             togglecookiepolicy,  { 0 } },
    
    /* Toggle Style Policy */ 
    { GDK_CONTROL_MASK|GDK_SHIFT_MASK,  GDK_KEY_m,             togglestyle,         { 0 } },
    
    /* Toggle Geolocation Policy */ 
    { GDK_CONTROL_MASK|GDK_SHIFT_MASK,  GDK_KEY_g,             togglegeolocation,   { 0 } },
};

//
// Button Definitions
//
static Button buttons[] = {
    /* Click        Event mask             Button  Function        Argument */
    { ClkLink,      0,                     2,      linkopenembed,  { 0 } },
    { ClkLink,      GDK_CONTROL_MASK,      2,      linkopen,       { 0 } },
    { ClkLink,      GDK_CONTROL_MASK,      1,      linkopen,       { 0 } },
    { ClkAny,       0,                     8,      navigate,       { .i = -1 } },
    { ClkAny,       0,                     9,      navigate,       { .i = +1 } },
};