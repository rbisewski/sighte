//! sighte.c
/*
 * Description: The main crux of the sighte browser is ran here.
 */

// Includes
#include "sighte.h"

// Global Variables
char *argv0;
static SoupSession *default_soup_session;
static Display *dpy;
static Window win;
static Client *clients = NULL;
static bool showxid = FALSE;
static bool usingproxy = 0;
static GTlsDatabase *tlsdb;
static int policysel = 0;
static char *stylefile = NULL;
static SoupCache *diskcache = NULL;

// Attach the configuration file.
#include "config.h"

//! Debug message printing fucntion.
/*!
 * @param   string   debug message
 *
 * @return  none
 *
 * SIDE EFFECTS: Dumps string message to stdout.
 */
void print_debug(const char* message)
{
    // Input validation
    if (!message) {
        return;
    }

    // Dump debug message to stdout if debug mode is on.
    if (debug_mode) {
        printf("%s\n", message);
    }

    // Simply leave here.
    return;
}

//! Group an accel (keystroke) to the intended Client. 
/*!
 * @param    Client  the object we wish to add our accel group to.
 *
 * @return   none
 */
void registerkeystroke(Client *c)
{
    // Input validation
    if (!c) {
        return;
    }

    // Variable declaration
    int i = 0;
    GClosure *closure;
    GtkAccelGroup *group = gtk_accel_group_new();
 
    // Sanity check, make sure this got an accel group.
    if (!group) {
        return;
    }
 
    // Cycle through each of the elements in our keys 
    for (i = 0; i < LENGTH(keys); i++) {

        // Assigned a potential connection for our GTK closure object.
        closure = g_cclosure_new(G_CALLBACK(keypress),
                                 c,
                                 (GClosureNotify) destroyclient);

        // If we couldn't get a closure, move on to the next.
        if (!closure) {
            continue;
        }

        // Connect each of keys to a new accel closure. 
        gtk_accel_group_connect(group,
                                keys[i].keyval,
                                keys[i].mod,
                                0,
                                closure);
    }

    // Finally, append the accel group to our GTK window.
    gtk_window_add_accel_group(GTK_WINDOW(c->win), group);

    // Tell the end user that the closure assignments are complete.
    print_debug("registerkeystroke() --> The client has now been assigned "
                "the relevant closures.");

    // Done here...
    return;
}

//! Handle our pre-request phase URI requests
/*!
 * @param   WebKitWebView       contents of open window
 * @param   WebKitURIRequest    internet/intranet location requested
 * @param   WebKitURIResponse   response from out request       
 * @param   Client              intended recipient       
 *
 * @return  none
 */
void prerequest(WebKitWebView *w, WebKitWebResource *r,
  WebKitURIRequest *req, Client *c)
{
    // Input validation
    if (!w || !r || !req || !c) {
        return;
    }

    // Variable declaration 
    int i = 0;
    
    // Attempt to grab the requested URI (as a string).
    char *uri = (char *) webkit_uri_request_get_uri(req);
    char *quoted_uri = NULL;

    // Sanity check, end here if we got a blank string.
    if (strlen(uri) < 1) {
        print_debug("prerequest() --> Invalid or blank URI request. "
                    "Halting request...");
        return;
    }

    // Debug mode, tell the end-user that a signal was detected.
    print_debug("prerequest() --> resource-load-started signal detected. "
                "It requested the following URI:");
    print_debug(uri);

    // If this browser was given an HTTP request for a .ico file, then
    // no need to waste time handling it specially since the browser
    // does not currently render them due to the current minimalist GUI.
    if (g_str_has_suffix(uri, ".ico")) {

        // Tell the end-user this request was halted.
        print_debug("prerequest() --> An icon was pre-requested. "
                    "Delaying request until page load complete.");

        // Consider the event complete.
        return;
    }


    // Attempt to crush the silly use of m3u8 playlists that can mangle
    // certain video calls.
    if (g_str_has_suffix(uri, ".m3u8")) {

        // Tell the end-user this request was halted.
        print_debug("prerequest() --> A m3u8 playlist was requested. "
                    "Halting request...");

        // Consider the event complete.
        return;
    }

    // Prequesting JS scripts can sometimes cause the browser to get confused,
    // as a result they need to be blocked until the remain of the page has
    // been loaded.
    if (g_str_has_suffix(uri, ".js")) {

        // Tell the end-user this request was halted.
        print_debug("prerequest() --> A JS script was pre-requested. "
                    "Delaying request until page load complete.");

        // Consider the event complete.
        return;
    }

    // Sanity check, if we got a normal URI or intranet request, we can
    // simply terminate here.
    if (g_str_has_prefix(uri, "http://")
      || g_str_has_prefix(uri, "https://")
      || g_str_has_prefix(uri, "about:")
      || g_str_has_prefix(uri, "file://")
      || g_str_has_prefix(uri, "data:")
      || g_str_has_prefix(uri, "blob:")) {

        // Consider the event complete.
        return;
    }

    // Sanity check, make sure every string character element is
    // actually printable ASCII (e.g. not \EOF or the like).
    for (i = 0; i < strlen(uri); i++) {

        // If it's not printable...
        if (!g_ascii_isprint(uri[i])) {

            // Consider the event complete.
            return;
        }
    }

    // Quote the request URI to prevent horrible accidents.
    print_debug("prerequest() --> Preparing to quote the requested URI.");
    quoted_uri = g_shell_quote(uri);

    // Sanity check, make sure this returned a value.
    if (!quoted_uri || strlen(quoted_uri) < 1) {
        print_debug("prerequest() --> Unable to quote the requested URI!");
        return;
    }

    // Clear the original uri away since the quoted version of it is
    // what will be used at this point.
    free(uri);

    // If debug mode, show the end-user what the quoted URI looks like
    // from a string point-of-view.
    print_debug("prerequest() --> The quoted URI is as follows:");
    print_debug(quoted_uri);

    // Send the signal to stop loading in *this* window.
    webkit_web_view_stop_loading(w);

    // Assemble the arguments we need.
    Arg arg = { .v = (char *[]){"/bin/sh",
                                "-c",
                                "xdg-open",
                                quoted_uri,
                                NULL}};

    // Afterwards free the temporary string 
    if (quoted_uri) {
        free(quoted_uri);
    }

    // Tell the end user that the closure assignments are complete.
    print_debug("prerequest() --> Attempt to spawn a new instance.");

    // Fork another instance using the given arguments.
    spawn(c, &arg);
}

//! Assemble file path as a string, and create it with permission 0600 if
//! it currently doesn't exist.
//!
//! SIDE EFFECT: After calling this function, consider freeing it any
//!              string it generates since g_build_filename() does a calloc
//!              to assign the required memory.
/*!
 * @param     string    original file path
 *
 * @return    string    POSIX file path location
 */
char* buildfile(const char *path)
{
    // Input validation
    if (!path) {
        return NULL;
    }

    // Variable declaration
    char *fpath = NULL;
    FILE *f;

    // Assemble our filepath string.  
    fpath = g_build_filename(buildpath(g_path_get_dirname(path)),
                             g_path_get_basename(path),
                             NULL);

    // Sanity check, make sure we could actually allocate sufficient
    // memory for this file path string.
    if (!fpath) {
        terminate("Insufficient memory for path: %s\n", path);
    }

    // Attempt to open-append our file.
    if (!(f = fopen(fpath, "a"))) {
        free(fpath);
        terminate("Could not open file: %s\n", fpath);
    }

    // Set the file so that only the pid owner can read/write to it.
    if (chmod(fpath, 0600) != 0) {
        fclose(f);
        terminate("Unable to alter permissions of file: %s\n", fpath);
    }

    // Close our file.
    fclose(f);

    // Finally, we can return our file path location.
    return fpath;
}

//! Attempt to convert any relative paths to real paths
/*!
 * @param   string  intended file path
 *
 * @return  string  POSIX file path location
 */
char* buildpath(const char *path)
{
    // Input validation
    if (!path || strlen(path) < 1) {
        return NULL;
    }

    // Variable declaration
    struct passwd *pw;
    char *tmp_path = NULL;
    char *name     = NULL;
    char *p        = NULL;
    char *fpath    = NULL;

    // If our path is ~ or ~ plus some directory, then we need to account
    // for this by adjusting based on the username, which we from our
    // password file.
    if (path[0] == '~' && (path[1] == '/' || path[1] == '\0')) {

        // Grab the path after ~
        p = (char *)&path[1];

        // Attempt to grab the password file user id data.
        pw = getpwuid(getuid());

        // Sanity check, make sure this is actually a real user who has valid creds.
        if (!pw || !pw->pw_dir) {
            terminate("Insufficient permissions to build the following "
                      "directory location: %s\n", path);
        }

        // Go ahead and build the pathu using the above pieces.
        tmp_path = g_build_filename(pw->pw_dir, p, NULL);

    // For all other cases of the ~ location... 
    } else if (path[0] == '~') {

        // Take into account any errant '/' characters, as POSIX says they
        // are completely valid, hence this logic.
        if ((p = strchr(path, '/'))) {
            name = strndup(&path[1], --p - path);

        // Otherwise our string is clean, so just do a straight dump.
        } else {
            name = strdup(&path[1]);
        }

        // Sanity check, make sure we actually got a username.
        if (!name) {
            terminate("Insufficient memory for home path: %s.\n", path);
        }

        // Attempt to grab the current password directory.
        if (!(pw = getpwnam(name))) {
            free(name);
            terminate("Unable to get user %s home directory: %s.\n", name, path);
        }

        // Clean away our name memory. 
        free(name);

        // Attempt to assemble our path.
        tmp_path = g_build_filename(pw->pw_dir, p, NULL);
    }

    // Otherwise this function was given a non ~ path, so simply copy into
    // our temp variable.
    if (!tmp_path) {
        tmp_path = strdup(path);
    }

    // If our directory doesn't exist, then we have to make the intended
    // location, since we will likely need to store cookies / scripts for
    // modern webpages.
    //
    // g_mkdir_with_parents returns 0 if the dir was created or pre-exists,
    // and will return a -1 if an error occurs.
    //
    if (g_mkdir_with_parents(tmp_path, 0700) < 0) {
        terminate("Could not access directory: %s\n", tmp_path);
    }

    // Grab our real path and clean away our memory.
    fpath = realpath(tmp_path, NULL);
    free(tmp_path);

    // Finally return our real path.
    return fpath;
}

//! Check if the button push was released.
/*
 * @param   WebKitWebView   originating web view 
 * @param   GdkEventButton  button causing the event
 * @param   Client          current client 
 *
 * @return  bool            true  --> event completed successfully
 *                          false --> propagate event further
 */
bool input_listener(WebKitWebView *web, GdkEventButton *e, Client *c)
{
    // Input validation.
    if (!web) {
        return false;
    }

    // Variable declaration
    unsigned int i = 0;
    unsigned int context = 0;
    Arg arg;

    // Sanity check, make sure that this event actually got an event hit.
    if (!c->hit_test_result) {
        return false;
    }

    // Attempt to grab the context from current hit test of the client.
    context = webkit_hit_test_result_get_context(c->hit_test_result);

    // Sanity check, make sure we actually got a hit test result context.
    if (!context) {
        return false;
    }

    // Retrieve the URI of the link...
    if (webkit_hit_test_result_context_is_link(c->hit_test_result)) {
        arg.v = (void*)webkit_hit_test_result_get_link_uri(c->hit_test_result);

    // ...or the URI of image...
    } else if (webkit_hit_test_result_context_is_image(c->hit_test_result)) {
        arg.v = (void*)webkit_hit_test_result_get_image_uri(c->hit_test_result);
    
    // ...or the URI of the media request.
    } else if (webkit_hit_test_result_context_is_media(c->hit_test_result)) {
        arg.v = (void*)webkit_hit_test_result_get_media_uri(c->hit_test_result);
    }

    // Sanity check, make sure we got back a link.
    if (!&arg.v) {
        return false;
    }

    // Cycle thru all possible button actions... 
    for (i = 0; i < LENGTH(buttons); i++) {

        // If our event exists, seems sane, and has an assigned action, then
        // we need to go ahead and enact it.
        if (buttons[i].click && e->button == buttons[i].button
          && CLEANMASK(e->state) == CLEANMASK(buttons[i].mask)
          && buttons[i].func) {

            // If it appears all we have is a normal navigation, just go
            // ahead since our button is mostly empty anyway.
            if (buttons[i].click == ClkLink && buttons[i].arg.i == 0) {
                buttons[i].func(c, &arg);

            // Otherwise just go ahead and use our button's arguments instead. 
            } else {
                buttons[i].func(c, &buttons[i].arg);
            }

            // Since we found it, we can go ahead and return true.
            return true;
        }
    }

    // Since nothing important happened, we can simply return false.
    return false;
}

//! Utility function to wipe away our globals.
/*!
 * @return  none
 */
void cleanup(void)
{
    // Clean up cached disk files used for Soup.
    if (diskcache) {
        soup_cache_flush(diskcache);
        soup_cache_dump(diskcache);
    }

    // Destruct all existing client objects.
    while (clients) {
        destroyclient(NULL, clients);
    }

    // Given a style file? Better take care of the mess.
    if (stylefile) {
        free(stylefile);
    }

    // Using a cookie file? Clean it up.
    if (cookiefile) {
        free(cookiefile);
    }

    // All the cleanup is now completed.
    return;
}

//! Adjust cookies file of the browser.
/*
 * @param   SoupCookieJar  cookies file
 * @param   SoupCookie     original cookie
 * @param   SoupCookie     new cookie
 *
 * @return  none
 */
void cookiejar_changed(SoupCookieJar *self, SoupCookie *old_cookie,
  SoupCookie *new_cookie)
{
    // Input validation.
    if (!self || !old_cookie || !new_cookie) {
        return;
    }

    // Establish a file lock on our cookie jar. Probably not a good idea to
    // let multiple request processes access the file at once since bad
    // things can happen to the file. Plus might as well be safe if we can.
    flock(COOKIEJAR(self)->lock, LOCK_EX); 

    // If we have a valid cookie that isn't set to expire, then assign it
    // an expiry time, since cookies should not last forever.
    if (!new_cookie->expires && sessiontime) {
        soup_cookie_set_expires(new_cookie,
                                soup_date_new_from_now(sessiontime));
    }

    // Adjust our cookie as per the new cookie data.
    SOUP_COOKIE_JAR_CLASS(cookiejar_parent_class)->changed(self,
                                                           old_cookie,
                                                           new_cookie);

    // Release the file lock on our cookie jar.
    flock(COOKIEJAR(self)->lock, LOCK_UN); 

    // Otherwise everything went fine, so simply return here.
    return;
}

//! Setup our cookie struct so that it behaves like a C++ object with
//! essential callbacks.
/*
 * @param   CookieJarClass   the cookie jar used by this browser.
 *
 * @return  none
 */
void cookiejar_class_init(CookieJarClass *jar)
{
    // Set the function that will run whenever a cookie has changed. 
    SOUP_COOKIE_JAR_CLASS(jar)->changed = cookiejar_changed;

    // Set the function that will retrieve cookie properties.
    G_OBJECT_CLASS(jar)->get_property =
        G_OBJECT_CLASS(cookiejar_parent_class)->get_property;

    // Set the function that will assign cookie properties.
    G_OBJECT_CLASS(jar)->set_property = cookiejar_set_property;

    // Set the function used to finalize our cookies file.
    G_OBJECT_CLASS(jar)->finalize = cookiejar_finalize;

    // Allow overriding the cookie filename.
    g_object_class_override_property(G_OBJECT_CLASS(jar), 1, "filename");

    // Finally having finished setting the cookie, go ahead and leave.
    return;
}

//! finalize and close the cookie jar via callback.
/*
 * @param   gobject   the cookie jar itself
 *
 * @return  none
 */
void cookiejar_finalize(GObject *self)
{
    // Remove the lock on the cookie jar.
    close(COOKIEJAR(self)->lock);

    // Finalize our cookie jar since we have completed the write to it.
    G_OBJECT_CLASS(cookiejar_parent_class)->finalize(self);

    // Return once this is finished.
    return;
}

//! Initialize and open a lock on the cookie jar via callback.
/*
 * @param   CookieJar  the cookie jar itself
 *
 * @return  none
 */
void cookiejar_init(CookieJar *self)
{
    // Open a lock on our cookie jar.
    self->lock = open(cookiefile, 0);

    // Return once this is finished.
    return;
}

//! Assemble our new cookie jar file, based on the given policy. 
/*
 * @param   string                     cookie jar filename
 * @param   bool                       whether or not our file is read only
 * @param   SoupCookieJarAcceptPolicy  browser cookie policy
 *
 * @return  SoupCookieJar              newly generated cookie jar
 */
SoupCookieJar* cookiejar_new(const char *filename, bool read_only,
  SoupCookieJarAcceptPolicy policy)
{
    // Return our new cookie jar object.
    return g_object_new(COOKIEJAR_TYPE,
                        SOUP_COOKIE_JAR_TEXT_FILENAME,
                        filename,
                        SOUP_COOKIE_JAR_READ_ONLY,
                        read_only,
                        SOUP_COOKIE_JAR_ACCEPT_POLICY,
                        policy,
                        NULL);
}

//! Set a property of a cookie inside of our cookie jar.
/*!
 * @param   GObject        the cookie jar itself
 * @param   unsigned int   property ID
 * @param   GValue         value of the property being set
 * @param   GParamSpec     glib specifications parameter
 *
 * @return  none
 */
void cookiejar_set_property(GObject *self, unsigned int prop_id,
  const GValue *value, GParamSpec *pspec)
{
    // Place a shared lock on our cookie jar file. 
    flock(COOKIEJAR(self)->lock, LOCK_SH);

    // Define the intended property in the cookie file.
    G_OBJECT_CLASS(cookiejar_parent_class)->set_property(self,
                                                         prop_id,
                                                         value,
                                                         pspec);
    // Remove the shared lock on our cookie jar file. 
    flock(COOKIEJAR(self)->lock, LOCK_UN);

    // Return from here.
    return;
}

//! Check our current cookies policy to determine how we want to handle
//! incoming cookies.
/*
 * @return  SoupCookieJarAcceptPolicy  how we want to handle cookies.
 */
SoupCookieJarAcceptPolicy cookiepolicy_get(void)
{
    // Switch thru our list of possible policies...
    switch (cookiepolicies[policysel]) {

    // Never accept cookies.
    case 'a':
        return SOUP_COOKIE_JAR_ACCEPT_NEVER;
    
    // Never accept 3rd party cookies.
    case '@':
        return SOUP_COOKIE_JAR_ACCEPT_NO_THIRD_PARTY;
    
    // Our default option...
    case 'A':
    default:
        break;
    }

    // ...which is simply to always accept cookies.
    return SOUP_COOKIE_JAR_ACCEPT_ALWAYS;
}

//! Set the current cookies policy to determine the method to handle incoming
//! browser cookies.
/*!
 * @param   SoupCookieJarAcceptPolicy   what to do with the cookies
 *
 * @return  char                        how we want to handle cookies
 */
char cookiepolicy_set(const SoupCookieJarAcceptPolicy ep)
{
    // Determine which policy...
    switch (ep) {

    // Never accept cookies.
    case SOUP_COOKIE_JAR_ACCEPT_NEVER:
        return 'a';

    // Never accept 3rd party cookies.
    case SOUP_COOKIE_JAR_ACCEPT_NO_THIRD_PARTY:
        return '@';

    // Always accept cookies.
    case SOUP_COOKIE_JAR_ACCEPT_ALWAYS:
    default:
        break;
    }

    // Since all cookies are accepted, go ahead and return.
    return 'A';
}

//! Attempt to execute the intended javascript code.
/*!
 * @param   Client   current client 
 *
 * @return  none
 */
void runscript(Client *c)
{  
    // Input validation
    if (!c) {
        return;
    }

    // Variable declaration
    char *script = NULL;
    JSValueRef js_exception = NULL;

    // Sanity check, make sure this has a user-defined script file to append
    // various code for certain JS functionality.
    if (!scriptfile) {
        print_debug("runscript() --> No base user script file detected.");
        return;
    }

    // Attempt to grab our file contents, and dump it to script.
    if (!g_file_get_contents(scriptfile, &script, NULL, NULL)) {
        print_debug("runscript() --> Unable to grab the contents of the "
                    "following file:");
        print_debug(scriptfile);
        return;
    }

    // Further sanity check, if the script ended up being null, go ahead
    // and leave this JS handling routine.
    if (!script) {
        print_debug("runscript() --> JS file is blank. Ignoring...");
        return;
    }

    // Convert the script values into a JS-safe string.
    JSStringRef js_str = JSStringCreateWithUTF8CString(script);

    // Sanity check, make sure this returned a valid reference.
    if (!js_str) {
        free(script);
        return;
    }

    // Dump the script file into a JS-safe string.
    JSStringRef js_str_file = JSStringCreateWithUTF8CString(scriptfile);

    // Sanity check, make sure this returned a valid reference.
    if (!js_str_file) {
        print_debug("runscript() --> Unable to JS stringify the following "
                    "file:");
        print_debug(scriptfile);
        free(script);
        return;
    }

    // Grab the global JS context, since the JS being executed needs to be
    // accomplished in the given window view.
    JSObjectRef js_obj = JSContextGetGlobalObject(
      webkit_web_view_get_javascript_global_context(c->view));

    // Sanity check, make sure this returned a valid reference.
    if (!js_obj) {
        print_debug("runscript() --> Unable to grab primary JS global "
                    "context.");
        free(script);
        return;
    }

    // Grab the client-wide Javascript context
    JSGlobalContextRef js_view_global
      = webkit_web_view_get_javascript_global_context(c->view);

    // Sanity check, make sure this actually got one...
    if (!js_view_global) {
        print_debug("runscript() --> Unable to grab secondary JS global "
                    "context.");
        free(script);
        return;
    }

    // Attempt to evaluate the script syntax, since very nasty scripts can
    // potentially cause all sorts of pain to the end-user.
    if (!JSCheckScriptSyntax(js_view_global, js_str, js_str_file, 0,
      &js_exception)) {
        print_debug("runscript() --> Invalid JS syntax detected.");
        free(script);
        return;
    }

    // Using our JS location and content data, go ahead and make an
    // attempt at evaluating the given script.
    JSEvaluateScript(js_view_global, js_str, js_obj, js_str_file, 0, &js_exception);

    // Free up all of the current utilized memory.
    free(script);

    // Having evaluted our script, we can simply return here.
    return;
}

//! Controls the internal cut / paste functionality of the browser.
/*!
 * @param   Client   the current client
 * @param   Arg      given list of arguments
 *
 * @return  none
 */ 
void clipboard(Client *c, const Arg *arg)
{
    // If we have a paste, then dump our text into a given field.
    if (*(bool *)arg) {
        gtk_clipboard_request_text(gtk_clipboard_get(GDK_SELECTION_PRIMARY),
          pasteuri, c);
        return;
    }

    // Otherwise we are copying text from a given element.
    gtk_clipboard_set_text(gtk_clipboard_get(GDK_SELECTION_PRIMARY),
      c->linkhover ? c->linkhover : geturi(c), -1);

    // All is won.
    return;
}

//! Copy a string from source to destination. 
/*!
 * @param   string*   pointer to a string
 * @param   string    original content
 *  
 * @return  string*   same as **dest
 */
char* assign_to_str(char **dest, const char *src)
{
    // Input validation.
    if (!src) {
        return NULL;
    }

    // Attempt a string dupe of the source string.
    char *tmp = strdup(src);

    // If we have a destination string, blast it away and then store the
    // new string in its address.
    if (dest && *dest) {
        free(*dest);
        *dest = tmp;
    }

    // Finally return our copied string.
    return tmp;
}

//! Creates a new window and returns the view point. 
/*!
 * @param    WebKitWebView            pointer to the window view pane
 * @param    WebKitNavigationAction   navigation action data
 * @param    Client                   current client
 *
 * @return   WebKitWebView            new view window
 */
WebKitWebView* createwindow(WebKitWebView *v, WebKitNavigationAction *nav,
  Client *c)
{
    // Input validation, make sure this has a valid client.
    if (!c) {
        return NULL;
    }

    // Variable declaration.
    WebKitURIRequest* request = NULL;
    const char* uri           = NULL;

    // If a navigation action was passed along, attempt to grab that URI.
    if (nav) {
        request = webkit_navigation_action_get_request(nav);
    }

    // Sanity check, make sure this actually got a request.
    if (request) {

        // If so, attempt to grab the pointer to the URI string.
        uri = webkit_uri_request_get_uri(request);
    }

    // In the event a URI was given, attempt to use it.
    if (uri && strlen(uri) > 0) {
        c->linkhover = assign_to_str(&c->linkhover, uri);
    }

    // Spawn a new window instance, which should try to utilize the internal
    // "linkhover" string as a URI to navigate itself to.
    newwindow(c);

    // Tell WebKit that the window creation action is completed by returning
    // NULL, which finalized the callback.
    return NULL;
}

//! Determine whether or not we can download based on the given MIME.
/*!
 * @param    WebKitWebView          current window view
 * @param    WebKitPolicyDecision   web policy result
 * @param    Client                 current client
 *
 * @return   bool                   whether or not to allow the download.
 */
bool determine_if_download(WebKitWebView *v, WebKitPolicyDecision *p, Client *c)
{
    // Input validation
    if (!v || !p) {
         return false;
    }

    // Variable declaration.
    SoupMessageHeadersIter *iter = NULL;
    const char *name  = NULL;
    const char *value = NULL;

    // Pull out the server's response to this browser's policy decision.
    WebKitResponsePolicyDecision *rpd = (WebKitResponsePolicyDecision*) p;

    // Grab the MIME-type from the HTTP response headers.
    const char *mime_type
      = webkit_uri_response_get_mime_type(
      webkit_response_policy_decision_get_response(rpd));

    // Grab the remainder of the headers.
    SoupMessageHeaders *smh = webkit_uri_response_get_http_headers(
      webkit_response_policy_decision_get_response(rpd));

    // If no MIME-type was given, end here.
    if (!rpd || !mime_type || strlen(mime_type) < 1) {

        // Debug mode, tell the end-user this response gave a blank or
        // invalid MIME-type.
        print_debug("determine_if_download() --> Blank or invalid MIME-type "
                    "response detected.");

        // Consider the callback event complete.
        return true;
    }

    // If we *cannot* show the MIME type in a standard HTML manner, then
    // probably this a file to download. In that case, attempt to make a
    // policy decision on the download in question.
    if (!webkit_response_policy_decision_is_mime_type_supported(rpd)) {

        // Debug mode, tell the end-user that this request contains a
        // MIME-type which suggests it is not HTML.
        print_debug("determine_if_download() --> Non-HTML MIME-type "
                    "request detected.");

        // Make a policy decision for download in question.
        webkit_policy_decision_download(p);

        // Consider the event completed. 
        return true;
    }

    // Debug mode; this code attempt to print out all of the HTTP(S) response
    // headers given.
    if (debug_mode) {

        // If attempting to use the Soup to get the HTTP/S response header,
        // but it has been set to NULL, then probably something else is going
        // on here, so return true to continue the signal.
        if (!smh) {
            print_debug("determine_if_download() --> Improper or null "
                        "SoupMessageHeaders present.");
            print_debug("determine_if_download() --> Terminating callback.");
            return true;
        }

        // Assign a chunk of memory for the SoupMessageHeadersIter struct.
        iter = (SoupMessageHeadersIter*) calloc(1,
          sizeof(SoupMessageHeadersIter));

        // Attempt to initialize the SoupMessageHeadersIter struct so that this
        // can iterate thru all of the HTTP(S) headers.
        soup_message_headers_iter_init(iter, smh);

        // Sanity check, make sure this could initialize the iterator.
        if (!iter) {
            print_debug("determine_if_download() --> Unable to allocate "
                        "memory for SoupMessageHeaders iterator structure!");
            print_debug("determine_if_download() --> Terminating callback.");
            return true;
        }

        // With the iterator initialized, attempt to iterate thru this
        // mess-o-headers.
        print_debug("\n===== HTTP/S Response Headers =====");
        while (soup_message_headers_iter_next(iter, &name, &value)) {
            print_debug(name);
            print_debug("\n");
            print_debug(value);
            print_debug("------");
        }
        print_debug("======== Headers End Here =========\n");

        // Attempt to free the memory used by SoupMesageHeadersIter structure.
        free(iter);
    }

    // Attempt to clear memory used by the SoupMessageHeaders structure.
    if (smh) {
        soup_message_headers_clear(smh);
    }

    // Otherwise the MIME type is compatible with this browser view, in which
    // case it is likely a page of some sort. Ergo, elect to use it.
    webkit_policy_decision_use(p);

    // Having handled all possible cases, this request can terminate here.
    return true;
}

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
bool decidepolicy(WebKitWebView *view, WebKitPolicyDecision *p,
  WebKitPolicyDecisionType t, Client *c)
{
    // Input validation
    if (!p || !t) {
        return false;
    }

    // Variable declaration
    WebKitNavigationAction *n;
    WebKitURIRequest *r;

    // If the policy being tested is for a response of some sort, then pass
    // it along to a function that will determine whether or not this is a
    // download response.
    if (t == WEBKIT_POLICY_DECISION_TYPE_RESPONSE) {
        print_debug("decidepolicy() --> Policy decision request resembles a "
                    "possible download.");
        return determine_if_download(view,p,c); 
    } 

    // Right now this function only handles navigation via links, so check
    // to ensure that the asserts the correct type.
    if (t != WEBKIT_POLICY_DECISION_TYPE_NAVIGATION_ACTION) {

        // Tell the end-user, in debug mode, that this does not appear to be
        // a navigation request.
        print_debug("decidepolicy() --> Policy decision request is not a "
                    "HTTP/HTTPS navigation response.");

        // Since it is not, the event is propagated further. The good news is
        // that the rest of the default policy decision handlers for WebKit2
        // are decent enough that I *think* it ought be safe to let it slide...
        return false;
    }

    // Attempt to grab the navigation action.
    n = webkit_navigation_policy_decision_get_navigation_action(
      (WebKitNavigationPolicyDecision*) p);

    // Sanity check, if we couldn't get a navigation action, go ahead and
    // propagate this further hoping some other signal handler will get the
    // correct type of policy decision.
    if (!n) {
        print_debug("decidepolicy() --> Policy decision request is a null"
                    "HTTP/HTTPS navigation response.");
        print_debug("decidepolicy() --> Terminating due to null response.");
        return false;
    }

    // If our browser was directed somewhere for reasons that involve
    // anything *not* link related, then we can simply skip this logic.
    if (webkit_navigation_action_get_navigation_type(n)
        != WEBKIT_NAVIGATION_TYPE_LINK_CLICKED) {
        return false;
    }

    // Otherwise we got a link, so ignore the normal policy.
    webkit_policy_decision_ignore(p);

    // Attempt to extract the requested URI from the navigation object.
    r = webkit_navigation_action_get_request(n); 
    
    // As this function is now done with the nav-action, it ought to be freed.
    webkit_navigation_action_free(n);

    // Sanity check, make sure we got a URI request.
    if (!r) {

        // As no WebKitURIRequest was been detected, return false.
        return false;
    }

    // Grab the URI needed to get to the new page, assuming the client has
    // not yet been destroyed.
    if (c) {
        print_debug("decidepolicy() --> Policy decision requests the "
                    "following URI:");
        print_debug(webkit_uri_request_get_uri(r));
        assign_to_str(&c->linkhover, webkit_uri_request_get_uri(r));
    }

    // Clean up the memory used by the URI object.
    free(r);

    // Pass along the chain of arguments to the newly generated window.
    print_debug("decidepolicy() --> Generating new browser window...");
    newwindow(c);

    // With the signal handled as intended, send the complete flag back.
    return true;
}

//! Destroy any memory and structs associated with a given Client object.
/*
 * @param   GtkWidget   widget that holds the window object
 * @param   Client      current client
 *
 * @return  none
 */
void destroyclient(GtkWidget* w, Client *c)
{
    // Input validation
    if (!c) {
        return;
    }

    // Define a pointer, it'll get used to cycle through our list of
    // clients objects; this is done of the purpose of wiping away only
    // the specified present instant (i.e. this window and all of it's
    // associated content).
    Client *p;

    // Send the stop loading signal to the page, for obvious reasons as
    // there is no need to continue at that point.
    webkit_web_view_stop_loading(c->view);

    // Check if a pre-existing download location label is open.
    if (c->download_location_label) {

        // Hide the download location label.
        gtk_widget_hide(c->download_location_label);

        // Since it is using memory, it needs to be freed.
        gtk_widget_destroy(c->download_location_label);
        c->download_location_label = NULL;
        print_debug("destroyclient() --> Cleaned up download label.");
    }

    // Check if a pre-existing dialog window is open.
    if (c->dialog) {
   
        // Hide the current dialog. 
        gtk_widget_hide(c->dialog);

        // Since it is using memory, it needs to be freed.
        gtk_widget_destroy(c->dialog);
        c->dialog = NULL;
        print_debug("destroyclient() --> Cleaned up dialog box.");
    }

    // Destroy the window view.
    gtk_widget_destroy(GTK_WIDGET(c->view));
    print_debug("destroyclient() --> Cleaned up WebKitView object.");

    // Finally, destroy the browser window.
    gtk_widget_destroy(c->win);
    print_debug("destroyclient() --> Cleaned up GTK Window object.");

    // Grab the next client in line...
    for (p = clients; p && p->next != c; p = p->next);

    // If we've gone through all of them and not found the originally
    // specified client again, then just grab the latest element.
    if (p) {
        p->next = c->next;

    // Otherwise reset our global pointer Client array to the next client.
    } else {
        clients = c->next;
    }

    // Since we've either found the next client or the end, we can safely
    // dispose of this client. 
    free(c);
    print_debug("destroyclient() --> Freed client object.");

    // Terminate our GTK window instance, if no other clients are running.
    if (clients == NULL) {
        gtk_main_quit();
        print_debug("destroyclient() --> Terminated GTK loop program.");
    }

    // Wreck it good.
    return;
}

//! Terminate the program with a given error message to stderr.
/*!
 * @param    string   error message to stderr
 * @param    ...
 *
 * @return   none
 */
void terminate(const char *errstr, ...)
{
    // Variable declaration
    va_list ap;

    // Print out the string and errno to stderr.
    va_start(ap, errstr);
    vfprintf(stderr, errstr, ap);
    va_end(ap);

    // Throw a failure and exit the program.
    exit(EXIT_FAILURE);
}

//! Find the chosen set of text.
/*!
 * @param    Client    current client
 * @param    Arg       given argument
 *
 * @return   none
 */
void find(Client *c, const Arg *arg)
{
    // Variable declaration
    WebKitFindController *wfc = webkit_web_view_get_find_controller(c->view);
    guint32 wfc_options       = WEBKIT_FIND_OPTIONS_CASE_INSENSITIVE;
    bool search_forwards      = *(bool *)arg;

    // Sanity check, make sure this actually returned a finder.
    if (!wfc) {

        // Debug mode, tell the programmer that th
        print_debug("find() --> Invalid or recently closed WebKitView "
                    "window. Doing nothing...");

        // Return whence this came.
        return;
    }

    // Further sanity check, make sure that the end-user actually defined
    // a piece of text to search for.
    if (!c || !c->text_to_search_for || !strlen(c->text_to_search_for)) {

        // Debug mode, tell the programmer that th
        print_debug("find() --> Invalid or empty text search string.");

        // Go back.
        return;
    }

    // If given the command to search backwards, attempt to do so.
    if (!search_forwards) {
        wfc_options |= WEBKIT_FIND_OPTIONS_BACKWARDS; 
    }

    // Attempt to determine if the text exists within the page, up to a
    // maximum of 200 to prevent any possible overflow issues that may exist.
    webkit_find_controller_search (wfc,
                                   c->text_to_search_for,
                                   wfc_options,
                                   200);

    // Find text finding text text fine.
    return;
}

//! Enable / disable fullscreen mode.
/*!
 * @param    Client   current client
 * @param    Arg      given argument
 *
 * @return   none
 */
void fullscreen(Client *c, const Arg *arg)
{
    // Input validation
    if (!c) {
        return;
    } 

    // If fullscreen, go ahead and return to normal.
    if (c->fullscreen) {
        gtk_window_unfullscreen(GTK_WINDOW(c->win));

    // Otherwise make it full!
    } else {
        gtk_window_fullscreen(GTK_WINDOW(c->win));
    }

    // Invert the fullscreen flag.
    c->fullscreen = !c->fullscreen;

    // Return with greater or lesser sight.
    return;
}

//! Determine whether to allow or deny a given Geo request.
/*!
 * @param    WebKitWebView                        window view
 * @param    WebKitGeolocationPermissionRequest   geo policy decision
 * @param    Client                               current client
 *
 * @return   none
 */
bool geopolicyrequested(WebKitWebView *v,
  WebKitGeolocationPermissionRequest *d, Client *c)
{
    // Input validation.
    if (!d || !c) {
        return false;
    } 

    // If we allow Geolocation, go ahead and send the allow signal.
    if (allowgeolocation) {
        webkit_permission_request_allow((WebKitPermissionRequest*) d);
        print_debug("geopolicyrequested() --> Allowed geolocation access "
                    "request.");

    // Otherwise we do not, and thus must deny.
    } else {
        webkit_permission_request_deny((WebKitPermissionRequest*) d);
        print_debug("geopolicyrequested() --> Denied geolocation access "
                    "request.");
    }

    // The global awaits.
    return true;
}

//! Extract the requested URI using WebKit.
/*!
 * @param   Client   current client
 *
 * @return  string   URI
 */
char* geturi(Client *c)
{
    // Input validation
    if (!c) {
        return NULL;
    }

    // If this results in a null, then return good ol' about:blank.
    if (!webkit_web_view_get_uri(c->view)) {
        return "about:blank";
    }

    // Otherwise return the URI as a string.
    print_debug("geturi() --> Attempting to grab URI.");
    return (char *)webkit_web_view_get_uri(c->view);
}

//! Grab or assemble the relevant style files.
/*!
 * @param   string   URI location
 *
 * @return  none 
 */
const char* getstyle(const char *uri)
{
    // Variable declaration
    int i = 0;

    // If we have a base style file, return that one.
    if (stylefile != NULL) {
        return stylefile;
    }
    
    // For every given style...
    for (i = 0; i < LENGTH(styles); i++) {

        // Not a regex? Skip it.
        if (!styles[i].regex) {
            continue;
        }
 
        // If (re =~ /url/ ) then we have the right style, so return that.
        if (!regexec(&(styles[i].re), uri, 0, NULL, 0)) {
            return styles[i].style;
        }
    }

    // As a default, we return the empty string.
    return "";
}

//! Set the style of the requested URI
/*!
 * @param   Client   current client
 * @param   string   CSS style filename
 *
 * @return  none
 */
void setstyle(Client *c, const char *style)
{
    // Input validation
    if (!c || !style) {
        return;
    } 

    // Attempt to assemble a stylesheet object.
    WebKitUserStyleSheet *stylesheet
      = webkit_user_style_sheet_new(style,
                                    WEBKIT_USER_CONTENT_INJECT_TOP_FRAME,
                                    WEBKIT_USER_STYLE_LEVEL_USER,
                                    NULL,
                                    NULL);

    // If we didn't generate a style sheet, leave this function.
    if (!stylesheet) {
        return;
    }

    // Attempt to grab the content manager for the view.
    WebKitUserContentManager *wcm
      = webkit_web_view_get_user_content_manager(c->view);

    // Sanity check, make sure this actually got a content manager.
    if (!wcm) {
        return;
    }

    // Set the style 
    webkit_user_content_manager_add_style_sheet(wcm,stylesheet);

    // Clean up any remaining memory
    free(stylesheet);
    free(wcm);

    // Gotta go.
    return;
}

//! Initialize the download request to grab the intended file.
/*! 
 * @param    WebKitWebView    given window view
 * @param    WebKitDownload   newly created instance used for downloading
 * @param    Client           current client
 *
 * @return   bool             only false since we want to return zero.
 */
bool initdownload(WebKitWebView *view, WebKitDownload *o, Client *c)
{
    // Variable declaration
    Arg arg;
    char **arg_list = NULL;
    int i = 0;
    char *url_base_filename  = NULL;
    char *download_file_path = NULL;
    GtkWidget *box_content   = NULL;

    // Attempt to grab the requested URI from our download.
    WebKitURIRequest *r = webkit_download_get_request(o);

    // Terminate the Webkit2 download instance, since it is less reliable
    // than using other commandline tools; wget, curl, aria2, and so on.
    webkit_download_cancel(o);

    // If debug, then tell the user that this is attempting to spawn new
    // process for the download via cURL.
    print_debug("initdownload() --> WebKit Requested URI:");
    print_debug(webkit_uri_request_get_uri(r));
    print_debug("initdownload() --> Client Requested URI:");
    print_debug(geturi(c));

    // Sanity check, make sure the requsted URL WebKit requested is not blank.
    if (!webkit_uri_request_get_uri(r)) {
        print_debug("initdownload() --> WebKit Requested URI is blank! "
                    "Terminating download request...");
        return false;
    }

    // Attempt to grab the base filename from the WebKit requested URI.
    // This is done since g_path_get_basename does a 'malloc' and so thus
    // needs to be freed later.
    url_base_filename = g_path_get_basename(webkit_uri_request_get_uri(r));

    // Sanity check, make sure this actually got a filename.
    if (!url_base_filename) {
        print_debug("initdownload() --> Unable to allocate memory to store "
                    "base filename of WebKit URI to a string.");
        print_debug("initdownload() --> Terminating download request.");
        return false;
    }

    // Append the static global downloads_location (see config.h) to the
    // cURL argument for file output.
    download_file_path = g_build_filename(downloads_location,
                                          url_base_filename,
                                          NULL);

    // Sanity check, make sure this actually assembled a path.
    if (!download_file_path) {

        // If debug, tell the user what happened
        print_debug("initdownload() --> Unable to allocate memory to "
                    "build download file path.");

        // Free the url_base_filename string if it exists.
        if (url_base_filename) {
            free(url_base_filename);
        }

        // If debug, tell the user this terminates the download request.
        print_debug("initdownload() --> Terminating download request...");
        return false;
    }

    // If debug, tell the user that the program cURL arguments are being
    // defined.
    print_debug("initdownload() --> Defining cURL arguments...");

    // Cast the given URI to an argument, which uses aria2c to safely
    // and rapidly download files from the download request.
    //
    // Originally this used curl, with the following arguments:
    //
    // arg.v = (char*[]){"/usr/bin/curl",
    //                   "-OLJq",
    //                   "--user-agent",
    //                   useragent,
    //                   "--referer",
    //                   geturi(c),
    //                   "-b",
    //                   cookiefile,
    //                   "-c",
    //                   cookiefile,
    //                   "--url",
    //                   (char*) webkit_uri_request_get_uri(r),
    //                   NULL};
    //
    // Lately curl has become a bit too feature-rich for this minimalist
    // browser, so this has since been replaced with aria2c, which can
    // safely and securely download files in a lightweight manner.
    //
    arg.v = (char*[]){"/usr/bin/aria2c",
                      (debug_mode) ? "--quiet=false" : "--quiet=true",
                      "-d",
                      downloads_location,
                      "-o",
                      url_base_filename,
                      "--user-agent",
                      useragent,
                      "--referer",
                      geturi(c),
                      (char*) webkit_uri_request_get_uri(r),
                      NULL};

    // If debug mode, get ready to dump all of the cURL arguments to the
    // stdout for the purpose of examining them.
    if (debug_mode) {

        // If debug, print out the argument being used.
        print_debug("initdownload() --> cURL Download Argument:");
        arg_list = (char**) arg.v;
        for (i = 0; arg_list[i]; i++) {
            print_debug(arg_list[i]);
        }

        // If debug, then tell the user that this is attempting to spawn new
        // process for the download via cURL.
        print_debug("initdownload() --> Attempting to spawn new process.");
    }

    // Memory check, if the `c->download_location_label` variable exists and
    // has been previously defined, clear it away.
    if (c->download_location_label != NULL) {

        // If debug, tell the developer this program needs to clear memory
        // in order to make space for the new download location label.
        print_debug("initdownload() --> Freeing memory used by the "
                    "following GTK modal object: "
                    "c->download_location_label.");

        // Since the dialog no longer exists, this needs to clean up the
        // memory assigned via the previous label generation.
        gtk_widget_destroy(c->download_location_label);
        c->download_location_label = NULL;
        print_debug("initdownload() --> freed c->download_location_label");
    }

    // If we got this far, then tell the end-user that the download command
    // accomplished via exec(curl) has been backgrounded. As well, state
    // the location of where the file is being downloaded to.

    // Attempt to set a GtkEntry to allow the end-user to input an URL.
    c->download_location_label = gtk_label_new(download_file_path);

    // Sanity check, make sure this actually returned a new input box.
    if (!c->download_location_label) {
        print_debug("initdownload() --> Unable to assign memory for the "
                    "download location label.");
        return false;
    }

    // Set the maximum length of the input box to 100 characters.
    gtk_label_set_width_chars(GTK_LABEL(c->download_location_label), 80);

    // Attempt to set the requested size of the input_box entry widget
    gtk_widget_set_size_request(c->download_location_label, 680, 30);

    // Generate a new dialog for the download location pop-up, along with
    // flags to tell the OS this is a model dialog that is autodestroyed
    // once the parent is closed.
    c->dialog = gtk_dialog_new_with_buttons("Download queued and sent to "
      "the following location:",
      GTK_WINDOW(c->win),
      GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
      NULL,
      NULL);

    // Sanity check, make sure this actually generated a dialog.
    if (!c->dialog) {

        // If debug, tell the developer this program failed to assign
        // memory for the GTK modal dialog.
        print_debug("initdownload() --> Unable to assign memory for the "
                    "GTK modal object: c->dialog.");

        // Since the dialog no longer exists, this needs to clean up the
        // memory assigned via the previous label generation.
        gtk_widget_destroy(c->download_location_label);
        c->download_location_label = NULL;
        print_debug("initdownload() --> freed c->download_location_label");

        // Return false, which continues the callback.
        return false;
    }

    // Grab the GtkBox from the content area of the GtkDialog.
    box_content = gtk_dialog_get_content_area(GTK_DIALOG(c->dialog));

    // Sanity check, make sure this actually was able to find a GtkBox.
    if (!box_content) {

        // Tell the developer exactly what happened.
        print_debug("initdownload() --> Unable to access the content area "
                    "of the GtkDialog object: c->dialog");

        // Clean up any memory assigned to the dialog object, if it still
        // exists and is defined.
        if (c->dialog) {
            gtk_widget_destroy(c->dialog);
            c->dialog = NULL;
            print_debug("initdownload() --> freed c->dialog memory");
        }

        // Since the dialog no longer exists, this needs to clean up the
        // memory assigned.
        gtk_widget_destroy(c->download_location_label);
        c->download_location_label = NULL;
        print_debug("initdownload() --> freed c->download_location_label");

        // Return false, which continues the callback.
        return false;
    }

    // Add the download_location_label to the content area of the dialog.
    gtk_container_add(GTK_CONTAINER(box_content), c->download_location_label);

    // Since we actually got a valid dialog, go ahead and display it.
    gtk_widget_show(c->download_location_label);
    gtk_widget_show(c->dialog);

    // Blast the download file path away since we're done with it.
    if (download_file_path) {
        print_debug("initdownload() --> Freeing download_file_path string.");
        free(download_file_path);
    }

    // Fork this process to get wget via WebKit to download the requested file.
    spawn(c, &arg);

    // Having successfully built the download path, go ahead and free the
    // url_base_filename string since it is no longer needed.
    if (url_base_filename) {
        print_debug("initdownload() --> Freeing url_base_filename string.");
        free(url_base_filename);
    }

    // Having queried the download, go ahead and end the callback by
    // passing a return value of true.
    return true;
}

//! Opens / closes the element and script inspector.
/*!
 * @param   Client   current client
 * @param   Arg      list of arguments
 *
 * @return  none
 */
void inspector(Client *c, const Arg *arg)
{
    // Input validation
    if (!c) {
        return;
    }

    // Check whether or not the inspector is open, and then open/close
    // it accordingly based on what the end user is doing.
    if (c->isinspecting) {
        webkit_web_inspector_close(c->inspector);
    } else {
        webkit_web_inspector_show(c->inspector);
    }

    // Return from here.
    return;
}

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
bool keypress(GtkAccelGroup *group, GObject *obj, unsigned int key,
  GdkModifierType mods, Client *c)
{
    // Variable declaration
    unsigned int i = 0;

    // Clean 'em
    mods = CLEANMASK(mods);

    // Lower 'em
    key = gdk_keyval_to_lower(key);

    // Cycle thru the list of keys
    for (i = 0; i < LENGTH(keys); i++) {

        // If the key was pressed and it has an assigned function...
        if (key == keys[i].keyval
            && mods == keys[i].mod
            && keys[i].func) {

            // .., then assign it that function.
            keys[i].func(c, &(keys[i].arg));

            // Return true here, and the callback handles the rest.
            return true;
        }
    }

    // Otherwise no key was found, hence false.
    return false;
}

//! Callback for mouse-target-changed, displaying the URI into a window title.
/*!
 * @param   WebKitWebView         window view
 * @param   WebKitHitTestResult   result of hovering over a hyperlink
 * @param   unsigned int          callback modifiers
 * @param   Client                current client
 *
 * @return  none
 */
void mousetargetchanged(WebKitWebView *v, WebKitHitTestResult *hit_test_result,
  unsigned int modifiers, Client *c)
{
    // Input validation
    if (!hit_test_result || !c) {
        return;
    }

    // Variable declaration
    const char* link_uri = NULL;

    // Store the current WebKitHitTestResult into the client so that the
    // program knows the latest hit that occurred.
    c->hit_test_result = hit_test_result;

    // If the user has not hovered over a hyperlink, simply restore the 
    // original title to the browser window.
    if (!webkit_hit_test_result_context_is_link(hit_test_result)) {
        free(c->linkhover);
        c->linkhover = NULL;
        updatetitle(c);
        return;
    }

    // Attempt to extract the link URI.
    link_uri = webkit_hit_test_result_get_link_uri(hit_test_result);

    // Sanity check, make sure it got something back.
    if (!link_uri) {
        return;
    }

    // If the user has hovered over an autogenerated javascript internal,
    // simply return the original title.
    if (g_str_has_prefix(link_uri,"javascript:")) {
        free(c->linkhover);
        c->linkhover = NULL;
        updatetitle(c);
        return;
    } 

    // Attempt to grab the URI of the given hyperlink.
    c->linkhover = assign_to_str(&c->linkhover, link_uri);

    // Update the title
    updatetitle(c);

    // All ends well.
    return;
}


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
bool load_failed_callback(WebKitWebView *view, WebKitLoadEvent e,
  char *failing_uri, GError *error, Client *c)
{
    // Debug mode, tell the end-user that a URI load has failed.
    if (failing_uri && strlen(failing_uri) > 0) {
        print_debug("load_failed_callback() --> The following URI has failed to "
                    "load:");
        print_debug(failing_uri);
    }

    // Debug mode, dump the given error message.
    if (error && error->message && strlen(error->message) > 0) {
        print_debug("load_failed_callback() --> Error message was...");
        print_debug(error->message);
    }

    // Consider the event complete.
    return true;
}

//! Adjust the Xwindow title based on whether or not the page is loading
/*!
 * @param    WebKitWebView    given web view
 * @param    WebKitLoadEvent  load event
 * @param    Client           current client
 *
 * @return   none
 */
void loadstatuschange(WebKitWebView *view, WebKitLoadEvent *e, Client *c)
{
    // Input validation
    if (!c) {
        return;
    }

    // If the page has completely loaded... 
    if (webkit_web_view_get_estimated_load_progress(c->view) > 0.99) {

        // Tell the client that progress is complete.
        c->progress = 100;
        updatetitle(c);

        // If using temporary disk cache, attempt to free it.
        if (diskcache) {
            soup_cache_flush(diskcache);
            soup_cache_dump(diskcache);
        }

        // All done here.
        print_debug("loadstatuschange() --> Page load completed.");
        return;
    } 

    // If the page is currently being loaded... grab the current web address
    // and assign to the client's title URI.
    c->title = assign_to_str(&c->title, geturi(c));

    // HTTPS is being used, need to check whether or not the connection
    // is actually secure.
    if (strstr(c->title, "https://") == c->title) {

        // Set the flag if our SSL certification has failed.
        c->sslfailed = !(soup_message_get_flags(
          soup_message_new("HTTPS",c->title))
          & SOUP_MESSAGE_CERTIFICATE_TRUSTED);
    }

    // Set our intended styles, if any.
    if (enablestyle) {
        setstyle(c, getstyle(c->title));
    }

    // Nothing to see here.
    return;
}

//! Loads the given URI
/*!
 * @param  Client  the current client
 * @param  Arg     given set of arguments
 *
 * @return  none
 */
void loaduri(Client *c, const Arg *arg)
{
    // Input validation
    if (!c || !arg) {
        return;
    }

    // Variable declaration
    char *u = NULL;
    char *rp = NULL;
    const char *uri = (char *)arg->v;
    Arg a = { .b = FALSE };
    struct stat st;

    // Sanity check, make sure this got back a string.
    if (!uri || !strlen(uri)) {
        return;
    }

    // Further sanity checks, make sure we got a valid URI.
    if (strcmp(uri, "") == 0) {
        return;
    }

    // If in debug mode, attempt to print out the URI load request string.
    print_debug("loaduri() --> Attempting to load the following URI:");
    print_debug(uri);

    // Stat our URI string, make sure we weren't accidently given a file
    // path or directory.
    if (stat(uri, &st) == 0) {
        rp = realpath(uri, NULL);
        u = g_strdup_printf("file://%s", rp);
        free(rp);

    // Otherwise we can probably assume we have a website.
    } else {
        u = g_strrstr(uri, "://") ? g_strdup(uri)
            : g_strdup_printf("http://%s", uri);
    }

    // Sanity check, make sure this actually has a URI string...
    if (!u || !strlen(u)) {
        return;
    }

    // Webkit is kinda silly, and will often get stuck in infinite loops,
    // so we have to compare it here against the original as a safety check.
    if (strcmp(u, geturi(c)) == 0) {

        // Since we have once again arrived the same location, we can simply
        // reload the page and put an end to the madness.
        print_debug("loaduri() --> Reloading page...");
        reload(c, &a);

        // Since this still have a string laying around, wipe it away since
        // the g_strdup_printf() usage means this likely malloc'd at some
        // point in the code.
        if (u) {
            free(u);
        }

        // This now done.
        return;
    }
 
    // Otherwise we can safely proceed to the destination.
    webkit_web_view_load_uri(c->view, u);
    c->progress = 0;
    c->title = assign_to_str(&c->title, u);
    updatetitle(c);

    // Free our string and leave in peace.
    free(u);
    return;
}

//! Navigate our client to the intended location, whether backwards to the
//! previous page or forwards to the new page.
/*!
 * @param  Client  the current client
 * @param  Arg     new list of evaluated arguments
 */
void navigate(Client *c, const Arg *arg)
{
    // Input validation
    if (!c) {
        return;
    }

    // Determine our number of steps based on our argument count.
    int steps = *(int *)arg;

    // If zero, then the user is requesting the browser go to the home page.
    if (steps == 0) {
        Arg sub_arg = {.v = default_home_page};
        loaduri(c, &sub_arg);
        updatetitle(c);
        return;
    }

    // If positive, we move on the next page forward.
    if ((steps > 0) && webkit_web_view_can_go_forward(c->view)) {
        webkit_web_view_go_forward(c->view);
        return;
    }

    // If negative, we move go back to the previous page.
    if ((steps < 0) && webkit_web_view_can_go_back(c->view)) { 
        webkit_web_view_go_back(c->view);
        return;
    } 

    // Otherwise we do nothing and simply return from here.
    return;
}

//! Initialize a new browser client.
/*!
 * @return  Client   new instance of the browser client.
 */
Client* newclient(void)
{
    // Variable declaration
    Client *c;
    WebKitSettings *settings;
    GdkGeometry hints = { 1, 1 };

    // Localization "en_US" is almost everpresent on most *nix distros,
    // so it is a safe default choice.
    const char * const languages_to_accept[] = {"en_US", NULL};
    const char * const languages_to_spellcheck[] = {"en_US", NULL};

    // Assign some memory for our new Client object.
    if (!(c = calloc(1, sizeof(Client)))) {
        terminate("Cannot malloc sufficient space for client object!\n");
    }

    // Initialize our page properties.
    c->title = NULL;
    c->progress = 100;

    // Generate this window as a standard Top Level window.
    c->win = gtk_window_new(GTK_WINDOW_TOPLEVEL);

    // Sanity check, make sure this got a new GTK Window.
    if (!c->win) {
        return NULL;
    }

    // Define the window class and role, in this case use the program name.
    gtk_window_set_title(GTK_WINDOW(c->win), "sighte");
    gtk_window_set_role(GTK_WINDOW(c->win), "Sighte");
    
    // Set the default size of the new window.
    gtk_window_set_default_size(GTK_WINDOW(c->win),
                                browser_window_starting_height,
                                browser_window_starting_width);

    // Callback for the "destroy" signal of the GdkWindow
    g_signal_connect(G_OBJECT(c->win),
                     "destroy",
                     G_CALLBACK(destroyclient), c);

    // Callback for the "leave_notify_event" signal of the GdkWindow
    g_signal_connect(G_OBJECT(c->win),
                     "leave_notify_event",
                     G_CALLBACK(titlechangeleave), c);

    // Register any key strokes or click done by the end-user.
    registerkeystroke(c);

    // Pane
    c->pane = gtk_paned_new(GTK_ORIENTATION_VERTICAL);
    
    // Sanity check, make sure this got a new GTK Pane object.
    if (!c->pane) {
        return NULL;
    }

    // Set our current webview via the necessary WebKit object.
    c->view = WEBKIT_WEB_VIEW(webkit_web_view_new());
    
    // Sanity check, make sure this got a new WebKitView object.
    if (!c->view) {
        return NULL;
    }

    // Attempt to grab the default web context, which is useful for handling
    // the security and content interactions of a given web page.
    c->web_context = webkit_web_view_get_context(c->view);

    // Sanity check, make sure this got a new WebKitView object.
    if (!c->web_context) {
        return NULL;
    }

    // Set the default TLS policy of the web context.
    webkit_web_context_set_tls_errors_policy(c->web_context,
                                             WEBKIT_TLS_ERRORS_POLICY_IGNORE);

    // If disk caching is disabled, set the web browser cache policy to
    // prevent caching onto the disk.
    //
    // If a given computer has 8+ gigs of RAM and / or a SSD,
    // there is likely no need to cache to disk. Ergo, forcing the browser
    // into "document viewer" mode is complete safe and has no performance
    // consequences in those situations.
    //
    if (!enablediskcache) {
        webkit_web_context_set_cache_model(c->web_context,
                                           WEBKIT_CACHE_MODEL_DOCUMENT_VIEWER);
    }

    // Safety check, determine if the default OS settings attempt to
    // enforce multi-threaded mode.
    //
    // On certain Linux distros, or with certain home directory overrides,
    // it is possible to force WebKit to do all sorts of crazy things, such
    // as needless multi-threading. Ergo, any browser using WebKit needs to
    // to check for this beforehand.
    //
    if (webkit_web_context_get_process_model(c->web_context)
      == WEBKIT_PROCESS_MODEL_MULTIPLE_SECONDARY_PROCESSES) {

        // Since the browser has started in multi-threaded mode, then force
        // it into single thread mode.
        webkit_web_context_set_process_model(c->web_context,
          WEBKIT_PROCESS_MODEL_SHARED_SECONDARY_PROCESS);
    }

    // Provide the client with the necessary preferred language, as per the
    // WebKitContext process header "Accept-Language" attribute.
    webkit_web_context_set_preferred_languages(c->web_context,
      (const char * const *) &languages_to_accept);

    // Provide the client with the necessary spellcheck language support.
    //
    // Note that this only needs to occur once, since WebKit tends to
    // globalize it. Doing this too many times causes leaks and possibly
    // segfaults since WebKit malloc's but doesn't free this variable.
    //
    if (!webkit_web_context_get_spell_checking_languages(c->web_context)) {
        print_debug("newclient() --> No spellcheck languages detected, "
                    "using default:");
        print_debug(languages_to_spellcheck[0]);
        webkit_web_context_set_spell_checking_languages(c->web_context,
          (const char * const *) &languages_to_spellcheck);
    }

    // Usually WebKit is smart enough, but sometimes there is a need to force
    // enable browser spell checking.
    //
    // Note this only needs to occur once since the browser only spawns a
    // single, global WebContext instance.
    //
    print_debug("newclient() --> Determining if spellcheck is enabled or "
                "disabled...");
    if (!webkit_web_context_get_spell_checking_enabled(c->web_context)) {
        print_debug("newclient() --> Forcing spellcheck to be enabled.");
        webkit_web_context_set_spell_checking_enabled(c->web_context, true);
    }

    // In the event the page we have directed to has a new title, we need
    // to assign the proper callback to change it.
    g_signal_connect(G_OBJECT(c->view),
                     "notify::title",
                     G_CALLBACK(titlechange),
                     c);

    // In the event our hovers over an hyperlink, we need to assign the 
    // proper callback function for it.
    g_signal_connect(G_OBJECT(c->view),
                     "mouse-target-changed",
                     G_CALLBACK(mousetargetchanged),
                     c);

    // Assign the callback for our Geolocation policy functionality.
    g_signal_connect(G_OBJECT(c->view),
                     "permission-request",
                     G_CALLBACK(geopolicyrequested),
                     c);

    // Assign the callback for openning any new webviews.
    g_signal_connect(G_OBJECT(c->view),
                     "create",
                     G_CALLBACK(createwindow),
                     c);

    // Determine if a new window policy decision is requested.
    g_signal_connect(G_OBJECT(c->view),
                     "decide-policy",
                     G_CALLBACK(decidepolicy),
                     c);

    // Assign the callback for the load-failed signal.
    g_signal_connect(G_OBJECT(c->view),
                     "load-failed",
                     G_CALLBACK(load_failed_callback),
                     c);

    // Assign the percentage load callback.
    g_signal_connect(G_OBJECT(c->view),
                     "load-changed",
                     G_CALLBACK(loadstatuschange),
                     c);

    // Assign the percentage load progress updater callback.
    g_signal_connect(G_OBJECT(c->view),
                     "notify::estimated-load-progress",
                     G_CALLBACK(progresschange),
                     c);

    // Assign the callback to start the requested download.
    g_signal_connect(G_OBJECT(webkit_web_view_get_context(c->view)),
                     "download-started",
                     G_CALLBACK(initdownload),
                     c);

    // Response if a key stroke or click event has occurred.
    g_signal_connect(G_OBJECT(c->view),
                     "button-release-event",
                     G_CALLBACK(input_listener),
                     c);

    // Assign the callback for the left-click context menu.
    g_signal_connect(G_OBJECT(c->view),
                     "context-menu",
                     G_CALLBACK(contextmenu),
                     c);

    // Assign the callback for the URI prerequest phase.
    g_signal_connect(G_OBJECT(c->view),
                     "resource-load-started",
                     G_CALLBACK(prerequest),
                     c);

    // Callback for when the WebView attempts to undertake a print action.
    g_signal_connect(G_OBJECT(c->view),
                     "print",
                     G_CALLBACK(print_callback),
                     c);

    // Callback for when the WebView has crashed for some unknown reason.
    g_signal_connect(G_OBJECT(c->view),
                     "web-process-crashed",
                     G_CALLBACK(web_process_crashed_callback),
                     c);

    // Assign the rendered pane to our client window
    gtk_container_add(GTK_CONTAINER(c->win), c->pane);

    // Finally add all of them to our pane.
    gtk_paned_pack1(GTK_PANED(c->pane), GTK_WIDGET(c->view), true, true);

    // With all of the layers assembled successfully, we can simply make
    // all of them visible and set the focus.
    gtk_widget_grab_focus(GTK_WIDGET(c->view));
    gtk_widget_show(c->pane);
    gtk_widget_show(GTK_WIDGET(c->view));
    gtk_widget_show(c->win);

    // Align the page geometry based on the expected page widths.
    gtk_window_set_geometry_hints(GTK_WINDOW(c->win),
                                  NULL,
                                  &hints,
                                  GDK_HINT_MIN_SIZE);

    // Set the events group filter.
    gdk_window_set_events(gtk_widget_get_window(GTK_WIDGET(c->win)),
      GDK_ALL_EVENTS_MASK);
 
    // Evaluate our frame using the scripts.js file in our cache.
    runscript(c);

    // Grab the list of WebKit settings.
    settings = webkit_web_view_get_settings(c->view);
    
    // Set it to zoom using all content, rather than simply text.
    webkit_settings_set_zoom_text_only(settings, true);

    // Set the intended user agent.
    webkit_settings_set_user_agent(settings, useragent);

    // Whether or not to load images.
    webkit_settings_set_auto_load_images(settings, loadimages);

    // Whether or not to enable browser plugins
    webkit_settings_set_enable_plugins(settings, enableplugins);

    // Whether or not to enable javascript.
    webkit_settings_set_enable_javascript(settings, enablescripts);

    // Whether or not to enable spatial navigation.
    webkit_settings_set_enable_spatial_navigation(settings,
      enablespatialbrowsing);

    // If embedded-device mode is enabled, go ahead and disable the
    // hardware-acceleration features.
    if (embedded_device_mode) {
        webkit_settings_set_enable_webgl(settings, false);
        webkit_settings_set_enable_accelerated_2d_canvas(settings, false);
    }

    // Otherwise if embedded-device mode is disabled, go ahead and enable all
    // of the hardware-acceleration features.
    if (!embedded_device_mode) {
        webkit_settings_set_enable_webgl(settings, true);
        webkit_settings_set_enable_accelerated_2d_canvas(settings, true);
    }

    // Some websites engage in embedding frames-inside-of-frames. WebKit has
    // the ability to flatten them so they behave, when scrolling, as one big
    // frame. If for some reason it is not enabled, go ahead and turn it on.
    if (!webkit_settings_get_enable_frame_flattening(settings)) {
        webkit_settings_set_enable_frame_flattening(settings, true);
    }

    // Whether or not to enable extra functionality for developers.
    webkit_settings_set_enable_developer_extras(settings, true);

    // Debug mode, dump our console messages for debugging purposes.
    if (debug_mode) {
        webkit_settings_set_enable_write_console_messages_to_stdout(settings,
                                                                    true);
    // Otherwise the end-user does not see any console messages.
    } else {
        webkit_settings_set_enable_write_console_messages_to_stdout(settings,
                                                                    false);
    }

    // Define the default font size used for the browser.
    webkit_settings_set_minimum_font_size(settings, defaultfontsize);
    webkit_settings_set_default_font_size(settings, defaultfontsize);

    // Whether or not to enable resizable text areas.
    webkit_settings_set_enable_resizable_text_areas(settings, true);

    // If styles are enabled, then attempt to set the style.
    if (enablestyle) {
        setstyle(c, getstyle("about:blank"));
    }

    // Set the intended zoom level for the specific page.
    if (zoomlevel != 1.0) {
        webkit_web_view_set_zoom_level(c->view, zoomlevel);
    }

    // Pass the client a reference to the HTML inspector.
    c->inspector = webkit_web_view_get_inspector(c->view);

    // Initially hide it for the purposes of normal browsing.
    c->isinspecting = false;

    // Check if running in full screen mode.
    if (runinfullscreen) {
        fullscreen(c, NULL);
    }

    // Start with default Find and URI string values.
    c->text_to_search_for = NULL;

    // Add a pointer to this client to the global list of clients.
    c->next = clients;
    clients = c;

    // Grab and return the Xid of this window, if asked.
    if (showxid) {

        // Sync the GdkWindow to the Xdisplay.
        gdk_display_sync(gtk_widget_get_display(c->win));

        // Dump the Xid of the Xdisplay to STDOUT.
        printf("%u\n",
          (guint)GDK_WINDOW_XID(gtk_widget_get_window(GTK_WIDGET(c->win))));

        // Flush the file contents buffer.
        fflush(NULL);

        // Attempt to close the standard out connection
        if (fclose(stdout) != 0) {
            terminate("Error closing stdout");
        }
    }

    // Return the newly initialized Client.
    return c;
}

//! Opens a new window that uses the settings of the previous window.
/*
 * @param    Client   current client
 *
 * @return   none
 */
void newwindow(Client *c)
{
    // Variable declaration
    unsigned int i = 0;
    const char *cmd[18];
    const Arg a = { .v = (void *)cmd };

    // Append our program name.
    cmd[i++] = argv0;

    // Define our cookie policies
    cmd[i++] = "-a";
    cmd[i++] = cookiepolicies;

    // Whether or not to allow Geolocation.
    if (!allowgeolocation) {
        cmd[i++] = "-g";
    }

    // Check whether or not to load images.
    if (!loadimages) {
        cmd[i++] = "-i";
    }

    // Whether or not to enable plugins.
    if (!enableplugins) {
        cmd[i++] = "-p";
    }

    // Whether or not we enable javascript usage on a given page.
    if (!enablescripts) {
        cmd[i++] = "-s";
    }

    // Whether or not to display the Xwindow ID. 
    if (showxid) {
        cmd[i++] = "-x";
    }

    // If we have disk caching enabled, use it.
    if (enablediskcache) {
        cmd[i++] = "-D";
    }

    // If a user clicked on a hyperlink or policy request, give the client
    // that URI as we may need to switch to it.
    if (c && c->linkhover && strlen(c->linkhover)) {
        print_debug("newwindow() --> Target requested the following URI:");
        print_debug(c->linkhover);
        cmd[i++] = c->linkhover;
    }

    // Null terminate the command string.
    cmd[i++] = NULL;

    // Attempt to open the new window.
    spawn(NULL, &a);
}

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
bool contextmenu(WebKitWebView *view, WebKitContextMenu *menu,
  WebKitHitTestResult *target, GdkEvent *event, Client *c)
{
    // Debug mode, tell the end-user that a (custom?) context menu has been
    // requested by a given web service.
    print_debug("contextmenu() --> Context Menu signal detected.");

    // Propagate the event further.
    return false;
}

//! Paste an URI from the clipboard of the browser.
/*!
 * @param    GtkClipboard   Process clipboard.
 * @param    string         Clipboard text.
 * @param    gpointer       Pointer to the client.
 *
 * @return   none
 */
void pasteuri(GtkClipboard *clipboard, const char *text, gpointer d)
{
    // Assign the text string to the argument object.
    Arg arg = {.v = text };

    // If there is text, go ahead and attempt to use it.
    if (text != NULL) {
        loaduri((Client *) d, &arg);
    }

    // Nothing to return.
    return;
}

//! Callback for when a webview is given a "print" signal.
/*!
 * @param   WebKitWebView          current webview
 * @param   WebKitPrintOperation   given printer operation
 * @param   Arg                    given list of arguments
 *
 * @return  bool     if cancel   --> true
 *                   if continue --> false
 */
bool print_callback(WebKitWebView *w, WebKitPrintOperation *print_op,
  const Arg *arg)
{
    // Input validation.
    if (!w || !print_op) {
        return true;
    }

    // Go back whence we came...
    return false;
}

//! Tells WebKit a print key command was give, so pop-up the print-menu.
/*!
 * @param    Client   current client
 * @param    Arg      given list of arguments
 *
 * @return   none
 */
void print(Client *c, const Arg *arg)
{
    // Input validation
    if (!c) {
        return;
    }

    // Assemble a new print operation object.
    WebKitPrintOperation* print_op = webkit_print_operation_new(c->view);

    // In the event that this failed, simply halt this function
    if (!print_op) {
        return;
    }

    // Display the print dialogue screen.
    webkit_print_operation_run_dialog(print_op, NULL);

    // Go back whence we came...
    return;
}

//! If the web page loading process has changed, update the title.
/*!
 * @param    WebKitWebView   given web view
 * @param    GParamSpec      given params
 * @param    Client          current Client
 *
 * @return   none
 */
void progresschange(WebKitWebView *view, GParamSpec *pspec, Client *c)
{
    // Input validation
    if (!c) {
        return;
    }

    // Set the progress value to the current progress.
    c->progress = webkit_web_view_get_estimated_load_progress(c->view) * 100;

    // Update the given title. 
    updatetitle(c);

    // This is now done.
    return;
}

//! Open a new link in a new window
/*!
 * @param    Client   current client
 * @param    Arg      given arguments
 *
 * @return   none
 */
void linkopen(Client *c, const Arg *arg)
{
    // Tell the developer what the program is attempting to do.
    print_debug("linkopen() --> Attempting to open new window...");

    // Open a new window.
    newwindow(c);

    // Go back.
    return;
}

//! Reload the current page
/*!
 * @param   Client   current client
 * @param   Arg      given list of arguments
 *
 * @return  none
 */
void reload(Client *c, const Arg *arg)
{
    // Check to see if this program is currently using cache.
    bool nocache = *(bool *)arg;

    // If not using cache, we need to bypass.
    if (nocache) {
        webkit_web_view_reload_bypass_cache(c->view);

    // Otherwise just the normal reload is good.
    } else {
        webkit_web_view_reload(c->view);
    }

    // Back, back foul daemon.
    return;
}

//! Initialize basic browser functionality.
/*!
 * @return   none
 */
void setup(void)
{
    // Variable declaration
    int i;
    char *proxy;
    char *new_proxy;
    char *no_proxy;
    char **new_no_proxy;
    char *styledirfile;
    char *stylepath;
    GProxyResolver *pr;
    GError *error = NULL;

    // Send the signal to clean up any zombies immediately
    sigchld(0);
    gtk_init(NULL, NULL);

    // Grab the current display
    dpy = XOpenDisplay(NULL);

    // Create a simple window to be used with the overlay atoms.
    win = XCreateSimpleWindow(dpy, RootWindow(dpy,0), 1, 1, 0, 0, 0,
      BlackPixel(dpy,0), BlackPixel(dpy,0));

    // Map the window to the display.
    XMapWindow(dpy, win);

    // Assemble the paths needed to make basic browser functionality work.
    downloads_location = buildpath(downloads_location);
    cookiefile = buildfile(cookiefile);
    scriptfile = buildfile(scriptfile);
    cachefolder = buildpath(cachefolder);

    // If no style file is specified...
    if (stylefile == NULL) {

        // Build the style directory path.
        styledir = buildpath(styledir);

        // For each style present...
        for (i = 0; i < LENGTH(styles); i++) {

            // Attempt to compile the regexes.
            if (regcomp(&(styles[i].re), styles[i].regex,
                REG_EXTENDED)) {
                fprintf(stderr,"Couldn't compile regex: %s\n",styles[i].regex);
                styles[i].regex = NULL;
            }

            // Append a / to the front of the directory
            styledirfile = g_strconcat(styledir, "/", styles[i].style, NULL);

            // Append the filename to the front of the directory path.
            stylepath = buildfile(styledirfile);

            // Since this is a file, have WebKit treat it as such.
            styles[i].style = g_strconcat("file://", stylepath, NULL);

            // Free up the used memory.
            free(styledirfile);
            free(stylepath);
        }

        // Having build the path, release this string from memory.
        free(styledir);

    // Otherwise there is a style file, in which case the assemble the path. 
    } else {
        stylepath = buildfile(stylefile);
        stylefile = g_strconcat("file://", stylepath, NULL);
        g_free(stylepath);
    }

    // Main session used by the request handler
    default_soup_session = soup_session_new();

    // Add the cookie jar
    soup_session_add_feature(default_soup_session,
                             SOUP_SESSION_FEATURE(cookiejar_new(cookiefile,
                             FALSE, cookiepolicy_get())));

    // If disk caching, then go ahead and use it.
    if (enablediskcache) {
        diskcache = soup_cache_new(cachefolder,
                                   SOUP_CACHE_SINGLE_USER);
        soup_cache_set_max_size(diskcache, diskcachebytes);
        soup_cache_load(diskcache);
        soup_session_add_feature(default_soup_session,
                                 SOUP_SESSION_FEATURE(diskcache));
    }

    // Start a new SSL database object.
    tlsdb = g_tls_file_database_new(cafile, &error);

    // If doing so caused error, let the end user know.
    if (error) {
        g_warning("Error loading SSL database %s: %s",cafile,error->message);
        g_error_free(error);
    }

    // Attempt to the TLS / SSL security variables.
    g_object_set(G_OBJECT(default_soup_session), "tls-database", tlsdb, NULL);
    g_object_set(G_OBJECT(default_soup_session), "ssl-strict", strictssl, NULL);

    // If this network is behind a proxy
    if ((proxy = getenv("http_proxy")) && strcmp(proxy, "")) {

        // Format the URI based on how the request was handled.
        new_proxy = g_strrstr(proxy, "http://") || g_strrstr(proxy, "https://")
                    || g_strrstr(proxy, "socks://")
                    || g_strrstr(proxy, "socks4://")
                    || g_strrstr(proxy, "socks4a://")
                    || g_strrstr(proxy, "socks5://")
                    ? g_strdup(proxy)
                    : g_strdup_printf("http://%s", proxy);

        // Also check if there is no proxy allowed.
        new_no_proxy = ((no_proxy = getenv("no_proxy")) && strcmp(no_proxy, ""))
            ? g_strsplit(no_proxy, ",", -1) : NULL;

        // Attempt to resolve the given proxy.
        pr = g_simple_proxy_resolver_new(new_proxy, new_no_proxy);

        // Set the property of the proxy state of the current session.
        g_object_set(G_OBJECT(default_soup_session), "proxy-resolver", pr, NULL);

        // Free any memory used by the variables.
        free(new_proxy);
        g_strfreev(new_no_proxy);

        // Finally set a flag letting us know that a proxy is in use.
        usingproxy = 1;
    }

    // Browser setup is now complete.
    return;
}

//! Send the kill signal to one of our child processes.
/*!
 * @return  none
 */
void sigchld()
{
    // Send the signal 
    if (signal(SIGCHLD, sigchld) == SIG_ERR) {
        terminate("Can't install SIGCHLD handler");
    }

    // Cycle until our process is dead.
    while (0 < waitpid(-1, NULL, WNOHANG));

    // The process is dead, long live the process!
    return;
}

//! Spawn a child process, useful for new windows or downloads.
/*!
 * @param   Client   current client
 * @param   Arg      given list of arguments
 *
 * @return  none
 */
void spawn(Client *c, const Arg *arg)
{
    // If we failed to fork, or this process is the parent, then go ahead
    // and return.
    //
    // Note: I don't think we need to throw errors here if we fail, but I'm
    //       not entirely sure. 
    //
    if (fork() != 0) {
        print_debug("spawn() --> fork() has returned a non-zero value here. "
                    "So the original process has *probably* passed through "
                    "here intact.");
        return;
    }

    // If debug, tell the end-user that the process has been successfully
    // forked since subprocesses will return 0.
    print_debug("spawn() --> fork() has returned a zero value here. So "
                "a new process has been generated here.");

    // If we have a pre-existing display open, then close it.
    if (dpy) {
        print_debug("spawn() --> Closing window-manager display.");
        close(ConnectionNumber(dpy));
    }

    // Set the sid.
    print_debug("spawn() --> Setting sid value.");
    setsid();

    // Attempt to execute our given arguments.
    print_debug("spawn() --> Executing...");
    execvp(((char **)arg->v)[0], (char **)arg->v);

    // If this process is still hanging on, then probably we should inform
    // the end user that something horrible has happened.
    fprintf(stderr, "sighte: execvp %s", ((char **)arg->v)[0]);

    // Throw an error stating "pid x failed".
    perror(" failed");

    // Terminate the program.
    exit(0);
}

//! Open a browser dialog for undertaking certain actions.
/*!
 * @param   Client   current client
 * @param   Arg      given list of arguments
 *
 * @return  none
 */
void opendialog(Client *c, const Arg *arg)
{
    // Input validation
    if (!c || !arg) {
        return;
    }

    // Check if a pre-existing dialog window is open.
    if (c->dialog) {
   
        // Hide the current dialog. 
        gtk_widget_hide(c->dialog);

        // Since it's using memory, it needs to be freed.
        gtk_widget_destroy(c->dialog);
        c->dialog = NULL;
    }

    // Attempt to set a GtkEntry to allow the end-user to input an URL.
    GtkWidget *input_box = gtk_entry_new();

    // Sanity check, make sure this actually returned a new input box.
    if (!input_box) {
        return;
    }

    // Set the maximum length of the input box to 300 characters.
    gtk_entry_set_max_length(GTK_ENTRY(input_box), 300);

    // Attempt to set the requested size of the input_box entry widget
    gtk_widget_set_size_request(input_box, 680, 30);

    // Set the default activation mechanism via the "Enter" key.
    gtk_entry_set_activates_default(GTK_ENTRY(input_box), true);

    // Sanity check, make sure this function was given a valid argument.
    if (!arg || !arg->i
      || (arg->i != DIALOG_ACTION_GO && arg->i != DIALOG_ACTION_FIND)) {

        // Set the dialog action back to none.
        c->dialog_action = DIALOG_ACTION_NONE;

        // Clean up the input box.
        gtk_widget_destroy(input_box);

        // Then return to end this function.
        return;
    }

    // Attempt to grab the dialog action value.
    c->dialog_action = arg->i;

    // Initialize the dialog modal for requesting input for an URI.
    if (c->dialog_action == DIALOG_ACTION_GO) {
        c->dialog = gtk_dialog_new_with_buttons("Where would you like to go?",
          GTK_WINDOW(c->win),
          GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
          NULL,
          NULL);

    // Initialize the dialog modal for requesting input for a text search.
    } else if (c->dialog_action == DIALOG_ACTION_FIND) {
        c->dialog = gtk_dialog_new_with_buttons(
          "What would you like to search for?",
          GTK_WINDOW(c->win),
          GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
          NULL,
          NULL);
        c->dialog_action = DIALOG_ACTION_FIND;
    } 

    // Sanity check, make sure we could actually generate a dialog.
    if (!c->dialog) {
        gtk_widget_destroy(input_box);
        return;
    }

    // Attach the proper callback for when a key is pressed.
    g_signal_connect(G_OBJECT(input_box),
                     "key-press-event",
                     G_CALLBACK(handle_dialog_keypress),
                     c);

    // Set the default size of the new dialog.
    gtk_window_set_default_size(GTK_WINDOW(c->dialog), 700, 40);

    // Add the input box to this new dialog.
    gtk_dialog_add_action_widget(GTK_DIALOG(c->dialog), input_box, 1);

    // Finally, make the dialog window visible.
    gtk_widget_show(input_box);
    gtk_widget_show(c->dialog);

    // As this is done here, simply return away...
    return;
}

//! Callback to handle any keypresses that occur on a dialog.
/*!
 * @param   GtkWidget    dialog receiving the keypress
 * @param   GdkEventKey  event caused by keypress
 * @param   Client       current client
 *
 * @return  bool         true, since that tells the callback to stop.
 */
bool handle_dialog_keypress(GtkWidget *w, GdkEventKey *e, Client *c)
{
    // Input validation
    if (!c) {
        return true;
    }

    // Variable declaration
    const char* input_box_text;

    // This should only handle keyboard presses since there is nothing to
    // click on for the current dialog layout.
    if (e->type != GDK_KEY_PRESS) {
        return true;
    }

    // If the ESC key was pressed, attempt to close the dialog
    if (e->keyval == GDK_KEY_Escape) {
        gtk_widget_hide(c->dialog);
        return true;
    }

    // If anything else other than the Enter key was pressed, terminate the
    // callback as nothing needs to be done in those situations.
    if (e->keyval == GDK_KEY_Return) {

        // Sanity check, make sure this still has an input box.
        if (!w) {

            // Since nothing is present, hide the dialog and continue on.
            gtk_widget_hide(c->dialog);
            return false;
        }

        // Attempt to grab the new requested URL from the input box text.
        input_box_text = gtk_entry_get_text(GTK_ENTRY(w));

        // Check if the user has entered text into the input box.
        if (!input_box_text || !strlen(input_box_text)) {

            // Since nothing is present, hide the dialog and continue on.
            gtk_widget_hide(c->dialog);
            return false;
        }

        // If this is a go dialog action, when we need to adjust the URI.
        if (c->dialog_action == DIALOG_ACTION_GO) {

            // Dump the URL into an argument so it can be passed back.
            const Arg a = { .v = (void *) input_box_text };

            // Attempt to load the requested URL.
            loaduri(c,&a);

        // If this is a find dialog action, then we must search for text.
        } else if (c->dialog_action == DIALOG_ACTION_FIND) {

            // Set the find atom.
            c->text_to_search_for = (char*) input_box_text;

            // Set an argument stating that we want to search forwards. 
            const Arg a = { .b = true };

            // Call the find command.
            find(c, &a);
        }

        // Hide the widget since it has done its task.
        gtk_widget_hide(c->dialog);
 
        // With the event completed, send the true value back.
        return true;
    }

    // Other key values can simply retain their usual input response.
    return false;
}

//! Call to stop loading a given page.
/*
 * @param   Client   current client
 * @return  Arg      given arguments
 *
 * @return  none
 */
void stop(Client *c, const Arg *arg)
{
    // Give the command to stop loading our page.
    webkit_web_view_stop_loading(c->view);

    // Return back to where we started.
    return;
}

//! Change the title of our browser to the current site title.
/*
 * @param    WebKitWebView   main web view of our browser
 * @param    GParamSpec      useful for the gcallback
 * @param    Client          current client
 *
 * @return   none
 */
void titlechange(WebKitWebView *view, GParamSpec *pspec, Client *c)
{
    // Input validation
    if (!view || !c) {
        return;
    }

    // Attempt to grab a pointer to our current title.
    if (webkit_web_view_get_title(view)) {

        // Grab a copy of our title string, and push it into our client.
        c->title = assign_to_str(&c->title, webkit_web_view_get_title(view));

        // Update our title.
        updatetitle(c);
    }
}

//! A quick version of the above, useful for hovering over links.
/*!
 * @param   *void    unimportant
 * @param   *void    unimportant
 * @param   Client   current client
 *
 * @return  none
 */
void titlechangeleave(void *a, void *b, Client *c)
{
    // Nullify our hover, we don't yet want to navigate there.
    c->linkhover = NULL;

    // Update our title to reflect the hover over our link.
    updatetitle(c);

    // Finally we can return.
    return;
}

//! Flip the setting of a give gObject.
/*!
 * @param    Client   current client
 * @param    Arg      given argument
 *
 * @return   none
 */
void toggle(Client *c, const Arg *arg)
{
    // Input validation
    if (!c) {
        return;
    }

    // Variable declaration
    WebKitSettings *settings = webkit_web_view_get_settings(c->view);
    char *name = (char *)arg->v;
    bool value = false;
    Arg a      = { .b = FALSE };

    // Grab the value of our requested setting.
    g_object_get(G_OBJECT(settings), 
                 name,
                 &value,
                 NULL);

    // Set it to the opposite value.
    g_object_set(G_OBJECT(settings),
                 name,
                 !value,
                 NULL);

    // Reload our client with the new setting.
    reload(c, &a);

    // Fun times with the toggle function.
    return;
}

//! Switch the current cookies policy to the next one.
/*!
 * @param    Client   current client
 * @param    Arg      given argument
 *
 * @return   none
 */
void togglecookiepolicy(Client *c, const Arg *arg)
{
    // Input validation
    if (!c) {
        return;
    }

    // Variable declaration    
    SoupCookieJarAcceptPolicy policy;

    // Get the current cookie jar.
    SoupCookieJar *jar = SOUP_COOKIE_JAR(soup_session_get_feature(
                                         default_soup_session,
                                         SOUP_TYPE_COOKIE_JAR));

    // Grab the current policy of the jar.
    g_object_get(G_OBJECT(jar), "accept-policy", &policy, NULL);

    // Switch to the next policy.
    policysel = (policysel+1) % strlen(cookiepolicies);

    // Alter the cookie jar policy.
    g_object_set(G_OBJECT(jar),
                 "accept-policy",
                 cookiepolicy_get(),
                 NULL);

    // This might need to update the client title, so go ahead.
    updatetitle(c);
}

//! Switch geolocation off or on.
/*!
 * @param    Client   current client
 * @param    Arg      given arguments
 *
 * @return   none
 */
void togglegeolocation(Client *c, const Arg *arg)
{
    // Set b to false, we'll use it when we reload.
    Arg a = { .b = FALSE };

    // Inverse the current geolocation policy.
    allowgeolocation = !allowgeolocation;

    // Reload the current client
    reload(c, &a);
}

//! Toggle CSS styles on or off.
/*!
 * @param    Client   current client
 * @param    Arg      given list of arguments 
 * 
 * @return   none
 */
void togglestyle(Client *c, const Arg *arg)
{
    // Switch between style modes.
    enablestyle = !enablestyle;

    // If we have switched to enabled, then go ahead and use it! 
    setstyle(c, enablestyle ? getstyle(geturi(c)) : "");

    // Adjust the browser title
    updatetitle(c);

    // Might as well return then.
    return;
}

//! Alter the title of our browser window to align with current page or link.
/*!
 * @param   Client   current client
 *
 * @return  none
 */
void updatetitle(Client *c)
{
    // Input validation
    if (!c) {
        print_debug("updatetitle() --> No client given, so nothing to do...");
        return;
    }

    // Variable declaraton.
    char *t = NULL;

    // If hovering on top of a link...
    if (c->linkhover) {
        t = g_strdup_printf("%s", c->linkhover);

    // If the browser in the in progress of loading a page...
    } else if (c->progress != 100) {
        t = g_strdup_printf("[%i%%] - %s", c->progress,
                            c->title == NULL ? "" : c->title);

    // Otherwise the page has completely loaded, in which case simply show
    // the title of our page.
    } else {
        t = g_strdup_printf("%s", c->title == NULL ? "" : c->title);
    }

    // If this doesn't have a title, perhaps an error has occurred, or maybe
    // some sort of stupid javascript / PHP redirect. Ergo, better to have a
    // default for this sort of thing.
    if (!t || !strlen(t)) {
        print_debug("updatetitle() --> Empty or blank title given. Using "
                    "default browser title...");
        gtk_window_set_title(GTK_WINDOW(c->win), default_page_title);
        return;
    }

    // Otherwise this was given a title, so set the title of our browser
    // window to the value stored in the string t.
    gtk_window_set_title(GTK_WINDOW(c->win), t);

    // With our string now passed forward, clean away our current tmp string.
    free(t);

    // Is it set? It is safe?
    return;
}

//! Print out our usage information. 
/*!
 *  @return  none
 */
void usage(void)
{
    terminate("usage: sighte [-DfFgGiImMpPsSvx] [-a cookiepolicies ] "
      "[-c cookiefile] [-r scriptfile] [-t stylefile] [-z zoomlevel] [uri]\n");
}

//! Callback for when a webview is given a "web-process-crashed" signal.
/*!
 * @param   WebKitWebView          current webview
 * @param   Arg                    given list of arguments
 *
 * @return  bool     if cancel   --> true
 *                   if continue --> false
 */
bool web_process_crashed_callback(WebKitWebView *v, const Arg *arg)
{
    // Tell the end-user since this callback has executed that a possible
    // crash has occurred in one or more of the browser's WebKitWebView
    // structures.
    print_debug("web_process_crashed() --> Possible WebView crash detected!");

    // Consider the event complete.
    return true;
}

//! Adjust the current zoom level. 
/*!
 * @param   Client   current client 
 * @param   Arg      given list of arguments.
 * 
 * @return  none
 */
void zoom(Client *c, const Arg *arg)
{
    // Input validation
    if (!c) {
        return;
    }

    // Variable declaration
    double current_zoom = webkit_web_view_get_zoom_level(c->view);

    // Set our zoom mode to true since this is attempting a possible zoom.
    c->zoomed = true;

    // Apply the requested zoom modifier to the current zoom value.
    current_zoom += ((double) arg->i)/10;

    // Sanity check, make sure the zoom level never falls below 1.0
    if (current_zoom < 1.0) {
        current_zoom = 1.0;

    // Also check if the current zoom level exceeds 3.0
    } else if (current_zoom > 3.0) {
       current_zoom = 3.0;
       c->zoomed = false;
    }

    // Finally set the zoom value, which should be between 1.0 and 3.0
    webkit_web_view_set_zoom_level(c->view, current_zoom);

    // No such zooms remain here in these parts.
    return;
}

//
// PROGRAM MAIN
//
int main(int argc, char *argv[])
{
    // Variable declaration
    Arg arg;
    Client *c;

    // Assign a chunk of memory for our arguments.
    memset(&arg, 0, sizeof(arg));

    // Check for each of our command line arguments.
    for (argv0 = *argv, argv++, argc--; 
      argv[0] && argv[0][1] && argv[0][0] == '-'; argc--, argv++) {

        // Useful flag-argument variables.
        char _argc;
        char **_argv;

        // If we get a - char without a proper char, end here.
        if (argv[0][1] == '-' && argv[0][2] == '\0') {
            argv++;
            argc--;
            break;
        }

        // Otherwise we likely have a valid flag, so enter another loop where
        // each of the choices can be evaluated
        for (argv[0]++, _argv = argv; argv[0][0]; argv[0]++) {

            // If current does not match the expected, then we need to get out
            // of this loop since something horrible has happened.
            if (_argv != argv) {
                break;
            }

            // With that in mind, grab the latest argument.
            _argc = argv[0][0];

            // Switch thru the various possibilities.
            switch (_argc) {

            // Set a specific cookie policy, see config.h for more details.
            case 'a':
                cookiepolicies = EARGF(usage());
                break;

            // Enable or disabled disk caching
            case 'd':
                enablediskcache = 0;
                break;
            case 'D':
                enablediskcache = 1;
                break;

            // Start in normal / full screen mode
            case 'f':
                runinfullscreen = 0;
                break;
            case 'F':
                runinfullscreen = 1;
                break;

            // Enable / disabled geolocation permissions
            case 'g':
                allowgeolocation = 0;
                break;
            case 'G':
                allowgeolocation = 1;
                break;

            // Enable / disable images
            case 'i':
                loadimages = 0;
                break;
            case 'I':
                loadimages = 1;
                break;

            // Enabled / disable CSS3 styles
            case 'm':
                enablestyle = 0;
                break;
            case 'M':
                enablestyle = 1;
                break;

            // Enable or disable browser plugins
            case 'p':
                enableplugins = 0;
                break;
            case 'P':
                enableplugins = 1;
                break;

            // Set a user specified script file
            case 'r':
                scriptfile = EARGF(usage());
                break;

            // Enable or disable scripts
            case 's':
                enablescripts = 0;
                break;
            case 'S':
                enablescripts = 1;
                break;

            // Set a predefined user style file
            case 't':
                stylefile = EARGF(usage());
                break;

            // Version
            case 'v':
                terminate("sighte-"VERSION", "
                    "Copyright 2016 sighte browser, all rights reserved.\n");

            // Show xid
            case 'x':
                showxid = TRUE;
                break;

            // Zoom level
            case 'z':
                zoomlevel = strtof(EARGF(usage()), NULL);
                break;

            // Otherwise default to just printing the usage data.
            default:
                usage();
            } 
        }
        USED(_argc);
    }
    USED(argv);
    USED(argc);

    // If we got an URI argument, we need to take them into account.
    if (argc > 0) {
        arg.v = argv[0];
    }

    // Prepare our browser.
    setup();

    // Initialize a new browser client. 
    c = newclient();

    // Sanity check, make sure this could actually make a client.
    if (!c) {
        cleanup();
        print_debug("main() --> Unable to initialize client.");
        return 1;
    }

    // If given an URI argument, go ahead and use it.
    if (arg.v && strlen(arg.v)) {
        print_debug("main() --> The following URL argument was given:");
        print_debug(arg.v);
        loaduri(clients, &arg);

    // Otherwise take the browser to the default home page.
    } else {
        print_debug("main() --> The following URL argument was given:");
        print_debug(default_home_page);
        arg.v = default_home_page;
        loaduri(clients, &arg);
        updatetitle(c);
    }

    // Initialize the main Xwindow for our broswer via GTK+
    print_debug("main() --> Converging to GTK main loop.");
    gtk_main();

    // Having finished the task at hand, the above statement should return
    // back here after converging and completed.
    print_debug("main() --> Deconverged successfully from GTK main loop.");

    // Clean up our globals.
    cleanup();

    // If all when well, we can simply exit peacefully
    return 0;
}

