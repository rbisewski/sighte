//! config.h
/*
 *  Description: The purpose of this file is to serve as a kind of
 *               easy-to-adjust configuration.
 */

// Where to store cache data for a given browser session
#define CACHE_DATA_PATH "~/.cache/sighte"

// Variable to control debug mode
static bool debug_mode  = false;

// User agent of browser.
static char *useragent  = "Mozilla/5.0 (X11; Linux x86_64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/59.0.3071.115 Safari/537.36 "
                          "Sighte/"VERSION;
// Default page title
static const char *default_page_title = "sighte Browser";

// Default starting size
static const int browser_window_starting_height = 1280;
static const int browser_window_starting_width  = 768;

// Default home page.
static const char *default_home_page = "https://start.duckduckgo.com";

// JS Script variables
static const char *scriptfile = CACHE_DATA_PATH"/script.js";
static char *styledir         = CACHE_DATA_PATH"/styles/";
static char *cachefolder      = CACHE_DATA_PATH"/cache/";

// Start the browser in a normal, non-fullscreen fashion.
static bool runinfullscreen = false;

// Embedded device mode, which disables hardware-accelerated 2D/3D features
// for slow or power-constrained boards.
static bool embedded_device_mode = false;

// Zoom related variables
static unsigned int defaultfontsize = 12; 
static double zoomlevel = 1.0;

// Cookie variables 
//
// A: accept all
// a: accept nothing
// @: accept all except third party
//
static char *cookiefile     = CACHE_DATA_PATH"/cookies.txt";
static char *cookiepolicies = "Aa@"; 

// Downloaded files location
static char *downloads_location = "~/";

// Certificate variables
static char *cafile       = "/etc/ssl/certs/ca-certificates.crt";
static bool strictssl     = true; // Use this to accept / refuse untrusted
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

// List of styles to be stored into the given filename.
//
// Specifically, they are of the format:
//
// { regexp,  filename-in-style-dir,  regex_t }
//
// Note: the functions using these array look for the first match and then
//       stop check the remainder.
//
static SiteStyle styles[] = {{ ".*", "default.css", 0 }};

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

    /* Open New Window */
    { GDK_CONTROL_MASK,                 GDK_KEY_w,             linkopen,            { 0 } },

    /* Refresh Current Page */
    { GDK_CONTROL_MASK|GDK_SHIFT_MASK,  GDK_KEY_r,             reload,              { .b = true } },
    { GDK_CONTROL_MASK,                 GDK_KEY_r,             reload,              { .b = false } },

    /* Printer Options */    
    { GDK_CONTROL_MASK|GDK_SHIFT_MASK,  GDK_KEY_p,             print,               { 0 } },

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
    { ClkAny,       0,                     8,      navigate,       { .i = -1 } },
    { ClkAny,       0,                     9,      navigate,       { .i = +1 } },
};
