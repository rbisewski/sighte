//! sighte.h
/*
 * Description: Stores the function definitions and some helpful macros.
 */
#ifndef __SIGHTE_H__
#define __SIGHTE_H__

// Standard C includes
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

// Standard POSIX includes
#include <pwd.h>
#include <regex.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

// External library includes
#include <gtk/gtk.h>
#include <gdk/gdkx.h>
#include <gdk/gdkkeysyms.h>
#include <webkit2/webkit2.h>
#include <JavaScriptCore/JavaScript.h>

// Argument evaluation macros.
#define EARGF(x) ((argv[1] == NULL)? ((x), abort(), (char *)0) :\
		 (argc--, argv++, argv[0]))

// Key and Button related macros.
#define LENGTH(x)         (sizeof(x) / sizeof(x[0]))
#define CLEANMASK(mask)   (mask & (GDK_CONTROL_MASK|GDK_SHIFT_MASK))

// Soup and Cookie related macros.
#define COOKIEJAR_TYPE    (cookiejar_get_type ())
#define COOKIEJAR(obj)    (G_TYPE_CHECK_INSTANCE_CAST ((obj), COOKIEJAR_TYPE, CookieJar))

// Define the dialog action values.
#define DIALOG_ACTION_NONE 0
#define DIALOG_ACTION_GO   1
#define DIALOG_ACTION_FIND 2

// Define the Webkit click contexts.
#define ClkDoc   WEBKIT_HIT_TEST_RESULT_CONTEXT_DOCUMENT
#define ClkLink  WEBKIT_HIT_TEST_RESULT_CONTEXT_LINK
#define ClkImg   WEBKIT_HIT_TEST_RESULT_CONTEXT_IMAGE
#define ClkMedia WEBKIT_HIT_TEST_RESULT_CONTEXT_MEDIA
#define ClkSel   WEBKIT_HIT_TEST_RESULT_CONTEXT_SELECTION
#define ClkEdit  WEBKIT_HIT_TEST_RESULT_CONTEXT_EDITABLE
#define ClkAny   ClkDoc | ClkLink | ClkImg | ClkMedia | ClkSel | ClkEdit

// Argument object
typedef union Arg Arg;
union Arg {
    bool b;
    gint i;
    const void *v;
};

// Client object
typedef struct Client {

    // Interactive on-screen widgets
    GtkWidget *win;
    GtkWidget *pane;
    GtkWidget *download_location_label;
    GtkWidget *dialog;

    // Essential WebKit objects.
    WebKitWebView *view;
    WebKitWebContext *web_context;
    WebKitWebInspector *inspector;
    WebKitHitTestResult *hit_test_result;

    // Current page <title> value.
    char *title;

    // Current hyperlink being hovered-over.
    char *linkhover;

    // Latest text that was searched for.
    char *text_to_search_for;

    // Load progress, as a percentage.
    int progress;

    // Stores a pointer to the next client child.
    struct Client *next;
    
    // Stores the latest dialog action.
    int dialog_action;

    // Variables to store current modes.
    bool zoomed;
    bool fullscreen;
    bool isinspecting;
    bool sslfailed;

} Client;

// Key object
typedef struct {
    guint mod;
    guint keyval;
    void (*func)(Client *c, const Arg *arg);
    const Arg arg;
} Key;

// Button object
typedef struct {
    unsigned int click;
    unsigned int mask;
    guint button;
    void (*func)(Client *c, const Arg *arg);
    const Arg arg;
} Button;

// CookieJar object
typedef struct {
    SoupCookieJarText parent_instance;
    int lock;
} CookieJar;

// CookieJarClass class
typedef struct {
    SoupCookieJarTextClass parent_class;
} CookieJarClass;

// Treat the cookie jar as a kind of text-soup for storing cookie data.
G_DEFINE_TYPE(CookieJar, cookiejar, SOUP_TYPE_COOKIE_JAR_TEXT)

// User-defined site styles.
typedef struct {
    char *regex;
    char *style;
    regex_t re;
} SiteStyle;

//! Debug message printing fucntion.
/*!
 * @param   string   debug message
 *
 * @return  none
 *
 * SIDE EFFECTS: Dumps string message to stdout.
 */
void print_debug(const char*);

//! Group an accel (keystroke) to the intended Client. 
/*!
 * @param    Client  the object we wish to add our accel group to.
 *
 * @return   none
 */
void registerkeystroke(Client*);

//! Handle our pre-request phase URI requests
/*!
 * @param   WebKitWebView       contents of open window
 * @param   WebKitURIRequest    internet/intranet location requested
 * @param   WebKitURIResponse   response from out request       
 * @param   Client              intended recipient       
 *
 * @return  none
 */
void prerequest(WebKitWebView*, WebKitWebResource*, WebKitURIRequest *,
  Client*);

//! Assemble file path as a string
/*!
 * @param   string  original file path
 *
 * @return  string  POSIX file path location
 */
char* buildfile(const char*);

//! Attempt to convert any relative paths to real paths
/*!
 * @param   string  intended file path
 *
 * @return  string  POSIX file path location
 */
char* buildpath(const char*);

//! Check if the button push was released.
/*
 * @param   WebKitWebView   originating web view 
 * @param   GdkEventButton  button causing the event
 * @param   Client          current client 
 *
 * @return  bool            true  --> event completed successfully
 *                          false --> propagate event further
 */
bool input_listener(WebKitWebView*, GdkEventButton*, Client*);

//! Utility function to wipe away our globals.
/*!
 * @return  none
 */
void cleanup(void);

//! Adjust cookies file of the browser.
/*
 * @param   SoupCookieJar  cookies file
 * @param   SoupCookie     original cookie
 * @param   SoupCookie     new cookie
 *
 * @return  none
 */
void cookiejar_changed(SoupCookieJar*, SoupCookie*, SoupCookie*);

//! Setup our cookie struct so that it behaves like a C++ object with
//! essential callbacks.
/*
 * @param   CookieJarClass   the cookie jar used by this browser.
 *
 * @return  none
 */
void cookiejar_class_init(CookieJarClass*);

//! finalize and close the cookie jar via callback.
/*
 * @param   gobject   the cookie jar itself
 *
 * @return  none
 */
void cookiejar_finalize(GObject*);

//! Initialize and open a lock on the cookie jar via callback.
/*
 * @param   CookieJar  the cookie jar itself
 *
 * @return  none
 */
void cookiejar_init(CookieJar*);

//! Assemble our new cookie jar file, based on the given policy. 
/*
 * @param   string                     cookie jar filename
 * @param   bool                       whether or not our file is read only
 * @param   SoupCookieJarAcceptPolicy  browser cookie policy
 *
 * @return  SoupCookieJar              newly generated cookie jar
 */
SoupCookieJar* cookiejar_new(const char*, bool, SoupCookieJarAcceptPolicy);

//! Set a property of a cookie inside of our cookie jar.
/*!
 * @param   GObject        the cookie jar itself
 * @param   unsigned int   property ID
 * @param   GValue         value of the property being set
 * @param   GParamSpec     glib specifications parameter
 *
 * @return  none
 */
void cookiejar_set_property(GObject*, unsigned int, const GValue*,
  GParamSpec*);

//! Check our current cookies policy to determine how we want to handle
//! incoming cookies.
/*!
 * @return  SoupCookieJarAcceptPolicy  how we want to handle cookies.
 */
SoupCookieJarAcceptPolicy cookiepolicy_get(void);

//! Set the current cookies policy to determine the method to handle incoming
//! browser cookies.
/*!
 * @param   SoupCookieJarAcceptPolicy   what to do with the cookies
 *
 * @return  char                        how we want to handle cookies
 */
char cookiepolicy_set(const SoupCookieJarAcceptPolicy);

//! Attempt to execute the intended javascript code.
/*!
 * @param   Client   current client 
 *
 * @return  none
 */
void runscript(Client*);

//! Controls the internal cut / paste functionality of the browser.
/*!
 * @param   Client   the current client
 * @param   Arg      given list of arguments
 *
 * @return  none
 */ 
void clipboard(Client*, const Arg*);

//! Copy a string from source to destination. 
/*!
 * @param   string*   pointer to a string
 * @param   string    original content
 *  
 * @return  
 */
char* assign_to_str(char**, const char*);

//! Creates a new window and returns the view point. 
/*!
 * @param    WebKitWebView            pointer to the window view pane
 * @param    WebKitNavigationAction   navigation action data
 * @param    Client                   current client
 *
 * @return   WebKitWebView            new view window
 */
WebKitWebView* createwindow(WebKitWebView*, WebKitNavigationAction*, Client*);

//! Determine whether or not we can download based on the given MIME.
/*!
 * @param    WebKitWebView          current window view
 * @param    WebKitPolicyDecision   web policy result
 *
 * @return   bool                   whether or not to allow the download.
 */
bool determine_if_download(WebKitWebView*, WebKitPolicyDecision*);

//! Determine whether or not to open a new window. 
/*!
 * @param    WebKitWebView              window view
 * @param    WebKitPolicyDecision       policy for handling requests
 * @param    WebKitPolicyDecisionType   policy for handling requests
 * @param    Client                     current client
 * 
 * @return   bool                       false --> pass along event
 *                                      true  --> event completed  
 */
bool decidepolicy(WebKitWebView*, WebKitPolicyDecision *,
  WebKitPolicyDecisionType, Client*);

//! Destroy any memory and structs associated with a given Client object.
/*
 * @param   GtkWidget   widget that holds the window object
 * @param   Client      current client
 *
 * @return  none
 */
void destroyclient(GtkWidget*, Client*);

//! Terminate the program with a given error message to stderr.
/*!
 * @param    string   error message to stderr
 * @param    ...
 *
 * @return   none
 */
void terminate(const char *, ...);

//! Find the chosen set of text.
/*!
 * @param    Client    current client
 * @param    Arg       given argument
 *
 * @return   none
 */
void find(Client*, const Arg*);

//! Enable / disable fullscreen mode.
/*!
 * @param    Client   current client
 *
 * @return   none
 */
void fullscreen(Client*, const Arg*);

//! Determine whether to allow or deny a given Geo request.
/*!
 * @param    WebKitWebView                        window view
 * @param    WebKitGeolocationPermissionRequest   geo policy decision
 * @param    Client                               current client
 *
 * @return   none
 */
bool geopolicyrequested(WebKitWebView*, WebKitGeolocationPermissionRequest*,
  Client*);

//! Extract the requested URI using WebKit.
/*!
 * @param   Client   current client
 *
 * @return  string   URI
 */
char* geturi(Client*);

//! Grab or assemble the relevant style files.
/*!
 * @param   string   URI location
 *
 * @return  none 
 */
const char* getstyle(const char*);

//! Set the style of the requested URI
/*!
 * @param   Client   current client
 * @param   string   CSS style filename
 *
 * @return  none
 */
void setstyle(Client*, const char*);

//! Initialize the download request to grab the intended file.
/*! 
 * @param    WebKitWebView    given window view
 * @param    WebKitDownload   newly created instance used for downloading
 * @param    Client           current client
 *
 * @return   bool             only false since we want to return zero.
 */
bool initdownload(WebKitWebView*, WebKitDownload*, Client*);

//! Opens / closes the element and script inspector.
/*!
 * @param   Client   current client
 * @param   Arg      list of arguments
 *
 * @return  none
 */
void inspector(Client*, const Arg*);

//! Register an action once a key has been pressed.
/*!
 * @param   GtkAccelGroup     key click group
 * @param   GObject           callback pointer 
 * @param   unsigned int      keyboard key pressed
 * @param   GdkModifierType   if the <alt>, <ctrl>, <shift>, etc was pressed
 * @param   Client            current client
 *
 * @return  bool  whether or not a key press was registered.
 */
bool keypress(GtkAccelGroup*, GObject*, unsigned int, GdkModifierType,
  Client*);

//! Callback for mouse-target-changed, displaying the URI into a window title.
/*!
 * @param   WebKitWebView         window view
 * @param   WebKitHitTestResult   result of hovering over a hyperlink
 * @param   unsigned int          callback modifiers
 * @param   Client                current client
 *
 * @return  none
 */
void mousetargetchanged(WebKitWebView*, WebKitHitTestResult*, unsigned int,
  Client*);

//! Callback for when the "load-failed" signal is given to the browser.
/*!
 * @param    WebKitWebView    given web view
 * @param    WebKitLoadEvent  load event
 * @param    string           URI that failed to load
 * @param    GError           GTK error object with further details
 * @param    Client           current client
 *
 * @return   bool             if cancel   --> true
 *                            if continue --> false
 */
bool load_failed_callback(WebKitWebView*, WebKitLoadEvent, char*, GError*,
  Client*);

//! Adjust the Xwindow title based on whether or not the page is loading
/*!
 * @param    WebKitWebView    given web view
 * @param    WebKitLoadEvent  load event
 * @param    Client           current client
 *
 * @return   none
 */
void loadstatuschange(WebKitWebView*, WebKitLoadEvent*, Client*);

//! Loads the given URI
/*!
 * @param  Client  the current client
 * @param  Arg     given set of arguments
 *
 * @return  none
 */
void loaduri(Client*, const Arg*);

//! Navigate our client to the intended location, whether backwards to the
//! previous page or forwards to the new page.
/*!
 * @param  Client  the current client
 * @param  Arg     new list of evaluated arguments
 */
void navigate(Client*, const Arg*);

//! Initialize a new browser client.
/*!
 * @return  Client   new instance of the browser client.
 */
Client* newclient(void);

//! Opens a new window that uses the settings of the previous window.
/*
 * @param    Client   current client
 *
 * @return   none
 */
void newwindow(Client*);

//! Load the context menu after a left-click on the browser window.
/*!
 * @param   WebKitWebView         given web view
 * @param   WebKitContextMenu     left-click menu object
 * @param   WebKitHitTestResult   pointer to the clicked target
 * @param   GdkEvent              triggering event 
 * @param   Client                current client
 *
 * @return  bool                  always false as per the callback usage
 */
bool contextmenu(WebKitWebView*, WebKitContextMenu*, WebKitHitTestResult*,
  GdkEvent*, Client*);

//! Paste an URI from the clipboard of the browser.
/*!
 * @param    GtkClipboard   Process clipboard.
 * @param    string         Clipboard text.
 * @param    gpointer       Pointer to the client.
 *
 * @return   none
 */
void pasteuri(GtkClipboard*, const char*, gpointer);

//! Callback for when a webview is given a "print" signal.
/*!
 * @param   WebKitWebView          current webview
 * @param   WebKitPrintOperation   given printer operation
 * @param   Arg                    given list of arguments
 *
 * @return  bool     if cancel   --> true
 *                   if continue --> false
 */
bool print_callback(WebKitWebView*, WebKitPrintOperation*, const Arg*);

//! Tells WebKit a print key command was give, so pop-up the print-menu.
/*!
 * @param    Client   current client
 * @param    Arg      given list of arguments
 *
 * @return   none
 */
void print(Client*, const Arg*);

//! If the web page loading process has changed, update the title.
/*!
 * @param    WebKitWebView   given web view
 * @param    GParamSpec      given params
 * @param    Client          current Client
 *
 * @return   none
 */
void progresschange(WebKitWebView*, GParamSpec*, Client*);

//! Open a new link in a new window
/*!
 * @param    Client   current client
 * @param    Arg      given arguments
 *
 * @return   none
 */
void linkopen(Client*, const Arg*);

//! Reload the current page
/*!
 * @param   Client   current client
 * @param   Arg      given list of arguments
 *
 * @return  none
 */
void reload(Client*, const Arg*);

//! Initialize basic browser functionality.
/*!
 * @return   none
 */
void setup(void);

//! Send the kill signal to one of our child processes.
/*!
 * @return  none
 */
void sigchld();

//! Spawn a child process, useful for new windows or downloads.
/*!
 * @param   Arg      given list of arguments
 *
 * @return  none
 */
void spawn(const Arg*);

//! Open / close a browser dialog for undertaking certain actions.
/*!
 * @param   Client   current client
 * @param   Arg      given list of arguments
 *
 * @return  none
 */
void opendialog(Client*, const Arg*);

//! Callback to handle any keypresses that occur on a dialog.
/*!
 * @param   GtkWidget    dialog receiving the keypress
 * @param   GdkEventKey  event caused by keypress
 * @param   Client       current client
 *
 * @return  bool         true, since that tells the callback to stop.
 */
bool handle_dialog_keypress(GtkWidget*, GdkEventKey*, Client*);

//! Call to stop loading a given page.
/*
 * @param   Client   current client
 * @return  Arg      given arguments
 *
 * @return  none
 */
void stop(Client*, const Arg*);

//! Change the title of our browser to the current site title.
/*
 * @param    WebKitWebView   main web view of our browser
 * @param    GParamSpec      useful for the gcallback
 * @param    Client          current client
 *
 * @return   none
 */
void titlechange(WebKitWebView*, GParamSpec*, Client*);

//! A quick version of the above, useful for hovering over links.
/*!
 * @param   *void    unimportant
 * @param   *void    unimportant
 * @param   Client   current client
 *
 * @return  none
 */
void titlechangeleave(void*, void*, Client*);

//! Flip the setting of a give gObject.
/*!
 * @param    Client   current client
 * @param    Arg      given argument
 *
 * @return   none
 */
void toggle(Client *c, const Arg *arg);

//! Switch the current cookies policy to the next one.
/*!
 * @param    Client   current client
 * @param    Arg      given argument
 *
 * @return   none
 */
void togglecookiepolicy(Client*, const Arg*);

//! Switch geolocation off or on.
/*!
 * @param    Client   current client
 * @param    Arg      given arguments
 *
 * @return   none
 */
void togglegeolocation(Client*, const Arg*);

//! Toggle CSS styles on or off.
/*!
 * @param    Client   current client
 * @param    Arg      given list of arguments 
 * 
 * @return   none
 */
void togglestyle(Client*, const Arg*);

//! Alter the title of our browser window to align with current page or link.
/*!
 * @param   Client   current client
 *
 * @return  none
 */
void updatetitle(Client*);

//! Print out our usage information. 
/*!
 *  @return  none
 */
void usage(void);

//! Callback for when a webview is given a "web-process-crashed" signal.
/*!
 * @param   WebKitWebView          current webview
 * @param   Arg                    given list of arguments
 *
 * @return  bool     if cancel   --> true
 *                   if continue --> false
 */
bool web_process_crashed_callback(WebKitWebView*, const Arg*);

//! Adjust the current zoom level. 
/*!
 * @param   Client   current client 
 * @param   Arg      given list of arguments.
 * 
 * @return  none
 */
void zoom(Client*, const Arg*);

#endif
