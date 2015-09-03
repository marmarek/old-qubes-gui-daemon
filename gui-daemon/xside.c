/*
 * The Qubes OS Project, http://www.qubes-os.org
 *
 * Copyright (C) 2010  Rafal Wojtczuk  <rafal@invisiblethingslab.com>
 * Copyright (C) 2010  Joanna Rutkowska <joanna@invisiblethingslab.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */

/* high level documentation is here:
 * http://wiki.qubes-os.org/trac/wiki/GUIdocs
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/shm.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <signal.h>
#include <poll.h>
#include <errno.h>
#include <unistd.h>
#include <spawn.h>
#include <execinfo.h>
#include <X11/X.h>
#include <X11/Xlib.h>
#include <X11/Intrinsic.h>
#include <X11/Xutil.h>
#include <X11/extensions/XShm.h>
#include <X11/extensions/Xrandr.h>
#include <X11/Xatom.h>
#include <libconfig.h>
#include <libnotify/notify.h>
#include <qubes-gui-protocol.h>
#include <qubes-xorg-tray-defs.h>
#include <libvchan.h>
#include <glib.h>
#include "txrx.h"
#include "double-buffer.h"
#include "list.h"
#include "error.h"
#include "png.h"

/* some configuration */

/* position at which to auto place windows in the agent
   we set Y to 24 so that tray icons, which are put at (0, 0), don't overlap with other windows
*/
#define WINDOW_DEFAULT_X 0
#define WINDOW_DEFAULT_Y 24

/* used to anonymize ourselves on non-exploited machines
   must only contain common resolutions */
static int screen_resolutions[] = {
	1366, 768,
	1920, 1080,
	/* TODO: should we add one of these?
	2560, 1440,
	2880, 1800, // MacBook Pro
	*/
	3840, 2160,
	0, 0
};

/* resolutions larger than the biggest one in screen_resolutions are multiple of this */
static int large_screen_resolution_unit_w = 1920;
static int large_screen_resolution_unit_h = 1080;

/* default width of forced colorful border */
#define BORDER_WIDTH 2
#define QUBES_CLIPBOARD_FILENAME "/var/run/qubes/qubes-clipboard.bin"
#define QREXEC_CLIENT_PATH "/usr/lib/qubes/qrexec-client"
#define QREXEC_POLICY_PATH "/usr/lib/qubes/qrexec-policy"
#define GUID_CONFIG_FILE "/etc/qubes/guid.conf"
#define GUID_CONFIG_DIR "/etc/qubes"
/* this feature was used to fill icon bg with VM color, later changed to white;
 * discussion: http://wiki.qubes-os.org/trac/ticket/127 */
// #define FILL_TRAY_BG
/* this makes any X11 error fatal (i.e. cause exit(1)). This behavior was the
 * case for a long time before introducing this option, so nothing really have
 * changed  */
#define MAKE_X11_ERRORS_FATAL

// Mod2 excluded as it is Num_Lock
#define SPECIAL_KEYS_MASK (Mod1Mask | Mod3Mask | Mod4Mask | ShiftMask | ControlMask )

// Special window ID meaning "whole screen"
#define FULLSCREEN_WINDOW_ID 0

#ifdef __GNUC__
#  define UNUSED(x) UNUSED_ ## x __attribute__((__unused__))
#else
#  define UNUSED(x) UNUSED_ ## x
#endif

enum clipboard_op {
	CLIPBOARD_COPY,
	CLIPBOARD_PASTE
};

/* per-window data */
struct windowdata {
	/* window attributes on the VM screen */
	int untrusted_remote_x;
	int untrusted_remote_y;
	int untrusted_remote_width;
	int untrusted_remote_height;
	int untrusted_remote_override_redirect;
	int remote_is_mapped;
	unsigned untrusted_remote_size_hint_flags;
	XID remote_winid;	/* window id on VM side */
	XID untrusted_remote_transient_for;	/* transient_for hint for WM, see http://tronche.com/gui/x/icccm/sec-4.html#WM_TRANSIENT_FOR */
	XID remote_parent;	/* parent window */
	XID remote_ref_window;

	/* window attributes on the host screen */
	int width;
	int height;
	int x;
	int y;
	int is_mapped;
	int is_docked;		/* is it docked tray icon */
	Window local_winid;	/* window id on X side */
	Window local_frame_winid; /* window id of frame window created by window manager */
	int override_redirect;	/* see http://tronche.com/gui/x/xlib/window/attributes/override-redirect.html */

	XShmSegmentInfo shminfo;	/* temporary shmid; see shmoverride/README */
	XImage *image;		/* image with window content */
	int image_height;	/* size of window content, not always the same as window in dom0! */
	int image_width;
	int have_queued_configure;	/* have configure request been sent to VM - waiting for confirmation */
	uint32_t flags_set;	/* window flags acked to gui-agent */
};

/* global variables
 * keep them in this struct for readability
 */
struct _global_handles {
	/* local X server handles and attributes */
	Display *display;
	int screen;		/* shortcut to the default screen */
	Window root_win;	/* root attributes */
	int root_width;		/* size of root window */
	int root_height;
	int remote_screen_width;
	int remote_screen_height;
	char* remote_monitor_layout;
	GC context;		/* context for pixmap operations */
	GC frame_gc;		/* graphic context to paint window frame */
#ifdef FILL_TRAY_BG
	GC tray_gc;		/* graphic context to paint tray background */
#endif
	/* atoms for comunitating with xserver */
	int xrandr_major;
	int xrandr_minor;
	int xrandr_event_base;
	int xrandr_error_base;
	Atom wmDeleteMessage;	/* Atom: WM_DELETE_WINDOW */
	Atom tray_selection;	/* Atom: _NET_SYSTEM_TRAY_SELECTION_S<creen number> */
	Atom tray_opcode;	/* Atom: _NET_SYSTEM_TRAY_MESSAGE_OPCODE */
	Atom xembed_message;	/* Atom: _XEMBED */
	Atom xembed_info;	/* Atom: _XEMBED_INFO */
	Atom wm_state;         /* Atom: _NET_WM_STATE */
	Atom wm_state_fullscreen; /* Atom: _NET_WM_STATE_FULLSCREEN */
	Atom wm_state_demands_attention; /* Atom: _NET_WM_STATE_DEMANDS_ATTENTION */
	Atom wm_state_hidden;	/* Atom: _NET_WM_STATE_HIDDEN */
	Atom wm_user_time;  /* Atom: _NET_WM_USER_TIME */
	Atom frame_extents; /* Atom: _NET_FRAME_EXTENTS */
	/* shared memory handling */
	struct shm_cmd *shmcmd;	/* shared memory with Xorg */
	uint32_t cmd_shmid;		/* shared memory id - received from shmoverride.so through shm.id file */
	int inter_appviewer_lock_fd; /* FD of lock file used to synchronize shared memory access */
	/* Client VM parameters */
	libvchan_t *vchan;
	char vmname[32];	/* name of VM */
	int domid;		/* Xen domain id (GUI) */
	int target_domid;		/* Xen domain id (VM) - can differ from domid when GUI is stubdom */
	char *cmdline_color;	/* color of frame */
	char *cmdline_icon;	/* icon hint for WM */
	unsigned long *icon_data; /* loaded icon image, ready for _NEW_WM_ICON property */
	int icon_data_len; /* size of icon_data, in sizeof(*icon_data) units */
	int label_index;	/* label (frame color) hint for WM */
	struct windowdata *screen_window; /* window of whole VM screen */
	/* lists of windows: */
	/*   indexed by remote window id */
	struct genlist *remote2local;
	/*   indexed by local window id */
	struct genlist *wid2windowdata;
	/* counters and other state */
	int clipboard_requested;	/* if clippoard content was requested by dom0 */
	Time clipboard_xevent_time;  /* timestamp of keypress which triggered last copy/paste */
	int windows_count;	/* created window count */
	struct windowdata *last_input_window;
	/* signal was caught */
	int volatile reload_requested;
	pid_t pulseaudio_pid;
	/* configuration */
	int log_level;		/* log level */
	int startup_timeout;
	int nofork;			   /* do not fork into background - used during guid restart */
	int invisible;			/* do not show any VM window */
	pid_t kill_on_connect;  /* pid to kill when connection to gui agent is established */
	int allow_utf8_titles;	/* allow UTF-8 chars in window title */
	int allow_fullscreen;   /* allow fullscreen windows without decoration */
	int copy_seq_mask;	/* modifiers mask for secure-copy key sequence */
	KeySym copy_seq_key;	/* key for secure-copy key sequence */
	int paste_seq_mask;	/* modifiers mask for secure-paste key sequence */
	KeySym paste_seq_key;	/* key for secure-paste key sequence */
	int qrexec_clipboard;	/* 0: use GUI protocol to fetch/put clipboard, 1: use qrexec */
	int use_kdialog;	/* use kdialog for prompts (default on KDE) or zenity (default on non-KDE) */
	int audio_low_latency; /* set low-latency mode while starting pacat-simple-vchan */
	int pointer_distance;
	GTree* window_width_tree; /* we use these trees to find the max window width/height in O(log n) time */
	GTree* window_height_tree;
	int private_mode;
};

typedef struct _global_handles Ghandles;
static Ghandles ghandles;

/* macro used to verify data from VM */
#define VERIFY(x) if (!(x)) { \
		if (ask_whether_verify_failed(g, __STRING(x))) \
			return; \
	}

/* calculate virtual width */
#define XORG_DEFAULT_XINC 8
#define _VIRTUALX(x) ( (((x)+XORG_DEFAULT_XINC-1)/XORG_DEFAULT_XINC)*XORG_DEFAULT_XINC )

/* short macro for beginning of each xevent handling function
 * checks if this window is managed by guid and declares windowdata struct
 * pointer */
#define CHECK_NONMANAGED_WINDOW(g, id) struct windowdata *vm_window; \
	if (!(vm_window=check_nonmanaged_window(g, id))) return

#ifndef min
#define min(x,y) ((x)>(y)?(y):(x))
#endif
#ifndef max
#define max(x,y) ((x)<(y)?(y):(x))
#endif

#define KDIALOG_PATH "/usr/bin/kdialog"
#define ZENITY_PATH "/usr/bin/zenity"

static inline int sanitize_width(int untrusted_width)
{
	return min(max(untrusted_width, 0), MAX_WINDOW_WIDTH);
}

static inline int sanitize_height(int untrusted_height)
{
	return min(max(untrusted_height, 0), MAX_WINDOW_HEIGHT);
}

static inline int sanitize_x(int untrusted_x)
{
	return min(max(untrusted_x, -2 * MAX_WINDOW_WIDTH), 2 * MAX_WINDOW_WIDTH);
}

static inline int sanitize_y(int untrusted_y)
{
	return min(max(untrusted_y, -2 * MAX_WINDOW_HEIGHT), 2 * MAX_WINDOW_HEIGHT);
}

/* in private mode, prevent VM from enlarging the monitor size by creating a large window */
static inline int sanitize_window_width(Ghandles * g, int untrusted_width)
{
	int width = sanitize_width(untrusted_width);
	return g->private_mode ? min(width, g->remote_screen_width - WINDOW_DEFAULT_X) : width;
}

static inline int sanitize_window_height(Ghandles* g, int untrusted_height)
{
	int height = sanitize_height(untrusted_height);
	return g->private_mode ? min(height, g->remote_screen_height - WINDOW_DEFAULT_Y) : height;
}

static struct windowdata* lookup_remote(Ghandles * g, Window win) {
	struct genlist* l;
	if(!win)
		return 0;
	l = list_lookup(g->remote2local, win);
	if(!l)
		return 0;
	return l->data;
}

static int ptrcmp_reverse(const void* a, const void* b)
{
	if(a < b)
		return 1;
	else if(a > b)
		return -1;
	else
		return 0;
}

static void tree_inc_value(GTree* tree, void* key) {
	g_tree_insert(tree, key, (void*)((uintptr_t)g_tree_lookup(tree, key) + 1));
}

static void tree_dec_value(GTree* tree, void* key) {
	uintptr_t v = (uintptr_t)g_tree_lookup(tree, key);
	if(v <= 1)
		g_tree_remove(tree, key);
	else
		g_tree_insert(tree, key, (void*)(v - 1));
}

static gboolean tree_get_first_key_traverse_func(gpointer key, gpointer UNUSED(value), gpointer data)
{
	*(void**)data = key;
	return TRUE;
}

static const void* tree_get_first_key(GTree* tree) {
	const void* key = 0;
	g_tree_foreach(tree, tree_get_first_key_traverse_func, &key);
	return key;
}

static void set_window_size(Ghandles * g, struct windowdata *vm_window, int width, int height)
{
	if(width != vm_window->width) {
		if(vm_window->width)
			tree_dec_value(g->window_width_tree, (void*)(uintptr_t)vm_window->width);
		if(width)
			tree_inc_value(g->window_width_tree, (void*)(uintptr_t)width);
		vm_window->width = width;
	}

	if(height != vm_window->height) {
		if(vm_window->height)
			tree_dec_value(g->window_height_tree, (void*)(uintptr_t)vm_window->height);
		if(height)
			tree_inc_value(g->window_height_tree, (void*)(uintptr_t)height);
		vm_window->height = height;
	}
}


static void inter_appviewer_lock(Ghandles *g, int mode);
static void release_mapped_mfns(Ghandles * g, struct windowdata *vm_window);

static void show_error_message (Ghandles * g, const char *msg)
{
	char message[1024];
	NotifyNotification *notify;

	fprintf(stderr, "%s\n", msg);
	if (!notify_init("qubes-guid")) {
		fprintf(stderr, "Failed to init notification subsystem\n");
		return;
	}
	snprintf(message, sizeof message, "ERROR(%s): %s", g->vmname, msg);
	notify = notify_notification_new(message, NULL, g->cmdline_icon);
	if (!notify_notification_show(notify, NULL)) {
		fprintf(stderr, "Failed to send notification\n");
	}
	g_object_unref (G_OBJECT (notify));
	// need to init/uninit every time because some notification daemons (namely
	// xfce4-notifyd) starts only on demand and connection reference become
	// stale after some idle period
	notify_uninit();
}

/* ask user when VM sent invalid message */
static int ask_whether_verify_failed(Ghandles * g, const char *cond)
{
	char text[1024];
	char dontagain_param[128];
	int ret = 1;
	pid_t pid;
	fprintf(stderr, "Verify failed: %s\n", cond);
	/* to be enabled with KDE >= 4.6 in dom0 */
	//#define NEW_KDIALOG
#ifdef NEW_KDIALOG
	snprintf(text, sizeof(text),
			"The domain %s attempted to perform an invalid or suspicious GUI "
			"request. This might be a sign that the domain has been compromised "
			"and is attempting to compromise the GUI daemon (Dom0 domain). In "
			"rare cases, however, it might be possible that a legitimate "
			"application trigger such condition (check the guid logs for more "
			"information). <br/><br/>"
			"Click \"Terminate\" to terminate this domain immediately, or "
			"\"Ignore\" to ignore this condition check and allow the GUI request "
			"to proceed.",
		 g->vmname);
#else
	snprintf(text, sizeof(text),
			"The domain %s attempted to perform an invalid or suspicious GUI "
			"request. This might be a sign that the domain has been compromised "
			"and is attempting to compromise the GUI daemon (Dom0 domain). In "
			"rare cases, however, it might be possible that a legitimate "
			"application trigger such condition (check the guid logs for more "
			"information). <br/><br/>"
			"Do you allow this VM to continue running?",
		 g->vmname);
#endif
	snprintf(dontagain_param, sizeof(dontagain_param), "qubes-quid-%s:%s", g->vmname, cond);

	pid = fork();
	switch (pid) {
		case 0:
			if (g->use_kdialog) {
#ifdef NEW_KDIALOG
				execlp(KDIALOG_PATH, "kdialog", "--dontagain", dontagain_param, "--no-label", "Terminate", "--yes-label", "Ignore", "--warningyesno", text, (char*)NULL);
#else
				execlp(KDIALOG_PATH, "kdialog", "--dontagain", dontagain_param, "--warningyesno", text, (char*)NULL);
#endif
			} else {
				execlp(ZENITY_PATH, "zenity", "--question", "--ok-label", "Terminate", "--cancel-label", "Ignore", "--text", text, (char*)NULL);
			}
			perror("execlp");
			_exit(1);
		case -1:
			perror("fork");
			exit(1);
		default:
			waitpid(pid, &ret, 0);
			ret = WEXITSTATUS(ret);
	}
	if (!g->use_kdialog) {
		// in zenity we use "OK" as "Terminate" to have it default
		// so invert the result
		ret ^= 1;
	}
	switch (ret) {
//	case 2:	/*cancel */
//		break;
	case 0:	/* YES */
		return 0;
	case 1:	/* NO */
		execl("/usr/sbin/xl", "xl", "destroy", g->vmname, (char*)NULL);
		perror("Problems executing xl");
		exit(1);
	default:
		fprintf(stderr, "Problems executing %s ?\n", g->use_kdialog ? "kdialog" : "zenity");
		exit(1);
	}
	/* should never happend */
	return 1;
}

int x11_error_handler(Display * dpy, XErrorEvent * ev)
{
	/* log the error */
	dummy_handler(dpy, ev);
#ifdef MAKE_X11_ERRORS_FATAL
	exit(1);
#endif
	return 0;
}

/* prepare graphic context for painting colorful frame */
static void get_frame_gc(Ghandles * g, const char *name)
{
	XGCValues values;
	XColor fcolor, dummy;
	if (name[0] == '0' && (name[1] == 'x' || name[1] == 'X')) {
		unsigned int rgb = strtoul(name, 0, 16);
		fcolor.blue = (rgb & 0xff) * 257;
		rgb >>= 8;
		fcolor.green = (rgb & 0xff) * 257;
		rgb >>= 8;
		fcolor.red = (rgb & 0xff) * 257;
		XAllocColor(g->display,
			    XDefaultColormap(g->display, g->screen),
			    &fcolor);
	} else
		XAllocNamedColor(g->display,
				 XDefaultColormap(g->display, g->screen),
				 name, &fcolor, &dummy);
	values.foreground = fcolor.pixel;
	g->frame_gc =
	    XCreateGC(g->display, g->root_win, GCForeground, &values);
}

#ifdef FILL_TRAY_BG
/* prepare graphic context for tray background */
static void get_tray_gc(Ghandles * g)
{
	XGCValues values;
	values.foreground = WhitePixel(g->display, g->screen);
	g->tray_gc =
	    XCreateGC(g->display, g->root_win, GCForeground, &values);
}
#endif

/* create local window - on VM request.
 * parameters are sanitized already
 */
static Window mkwindow(Ghandles * g, struct windowdata *vm_window)
{
	char *gargv[1] = { NULL };
	struct windowdata* parentdata;
	Window child_win;
	Window parent;
	XSizeHints my_size_hints;	/* hints for the window manager */
	Atom atom_label;
	int user_time = 0;

	my_size_hints.flags = PSize | PPosition;
	my_size_hints.width = vm_window->width;
	my_size_hints.height = vm_window->height;

	if ((parentdata = lookup_remote(g, vm_window->remote_parent)))
		parent = parentdata->local_winid;
	else
		parent = g->root_win;
	child_win = XCreateSimpleWindow(g->display, parent,
					vm_window->x, vm_window->y,
					vm_window->width,
					vm_window->height, 0,
					BlackPixel(g->display, g->screen),
					WhitePixel(g->display, g->screen));
	if(vm_window->override_redirect) {
		XSetWindowAttributes attr;

		memset(&attr, 0, sizeof(attr));
		attr.override_redirect = vm_window->override_redirect;
		XChangeWindowAttributes(g->display, child_win,
					CWOverrideRedirect, &attr);
	}
	/* pass my size hints to the window manager, along with window
	   and icon names */
	(void) XSetStandardProperties(g->display, child_win,
				      "VMapp command", "Pixmap", None,
				      gargv, 0, &my_size_hints);
	(void) XSelectInput(g->display, child_win,
			    ExposureMask | KeyPressMask | KeyReleaseMask |
			    ButtonPressMask | ButtonReleaseMask |
			    PointerMotionMask | EnterWindowMask | LeaveWindowMask |
			    FocusChangeMask | StructureNotifyMask | PropertyChangeMask);
	XSetWMProtocols(g->display, child_win, &g->wmDeleteMessage, 1);
	if (g->icon_data) {
		Atom atom_icon = XInternAtom(g->display, "_NET_WM_ICON", 0);
		XChangeProperty(g->display, child_win, atom_icon, XA_CARDINAL, 32,
				PropModeReplace, (unsigned char *) g->icon_data,
				g->icon_data_len);
		XClassHint class_hint =
		    { g->vmname, g->vmname };
		XSetClassHint(g->display, child_win, &class_hint);
		// perhaps set also icon_pixmap property in WM_HINTS (two Pixmaps -
		// icon and the mask), but hopefully all window managers supports
		// _NET_WM_ICON
	} else if (g->cmdline_icon) {
		XClassHint class_hint =
		    { g->cmdline_icon, g->cmdline_icon };
		XSetClassHint(g->display, child_win, &class_hint);
	}
	// Set '_QUBES_LABEL' property so that Window Manager can read it and draw proper decoration
	atom_label = XInternAtom(g->display, "_QUBES_LABEL", 0);
	XChangeProperty(g->display, child_win, atom_label, XA_CARDINAL,
			8 /* 8 bit is enough */ , PropModeReplace,
			(unsigned char *) &g->label_index, 1);

	// Set '_QUBES_VMNAME' property so that Window Manager can read it and nicely display it
	atom_label = XInternAtom(g->display, "_QUBES_VMNAME", 0);
	XChangeProperty(g->display, child_win, atom_label, XA_STRING,
			8 /* 8 bit is enough */ , PropModeReplace,
			(const unsigned char *) g->vmname,
			strlen(g->vmname));

	// Set '_QUBES_VMWINDOWID' property so that additional plugins can
	// synchronize window state (icon etc)
	atom_label = XInternAtom(g->display, "_QUBES_VMWINDOWID", 0);
	XChangeProperty(g->display, child_win, atom_label, XA_WINDOW,
			32, PropModeReplace,
			(const unsigned char *)&vm_window->remote_winid,
			1);

	// prevent focus stealing
	XChangeProperty(g->display, child_win, g->wm_user_time, XA_CARDINAL,
			32, PropModeReplace,
			(const unsigned char *)&user_time,
			1);

	if (vm_window->remote_winid == FULLSCREEN_WINDOW_ID) {
		/* whole screen window */
		g->screen_window = vm_window;
	}

	return child_win;
}

/* prepare global variables content:
 * most of them are handles to local Xserver structures */
static void mkghandles(Ghandles * g)
{
	char tray_sel_atom_name[64];
	XWindowAttributes attr;
	g->display = XOpenDisplay(NULL);
	if (!g->display) {
		perror("XOpenDisplay");
		exit(1);
	}
	if(!XRRQueryExtension(g->display, &g->xrandr_event_base, &g->xrandr_error_base) ||
		!XRRQueryVersion(g->display, &g->xrandr_major, &g->xrandr_minor) ||
		g->xrandr_major < 1 || (g->xrandr_major == 1 && g->xrandr_minor < 2)
		) {
		fprintf(stderr, "X server must support XRandR 1.2 or later\n");
		exit(1);
	}

	g->screen = DefaultScreen(g->display);
	g->root_win = RootWindow(g->display, g->screen);
	XGetWindowAttributes(g->display, g->root_win, &attr);
	g->root_width = _VIRTUALX(attr.width);
	g->root_height = attr.height;
	if(!g->private_mode) {
		g->remote_screen_width = g->root_width;
		g->remote_screen_height = g->root_height;
	} else {
		g->remote_screen_width = screen_resolutions[0];
		g->remote_screen_height = screen_resolutions[1];
	}
	g->context = XCreateGC(g->display, g->root_win, 0, NULL);
	g->wmDeleteMessage =
	    XInternAtom(g->display, "WM_DELETE_WINDOW", True);
	g->clipboard_requested = 0;
	g->clipboard_xevent_time = 0;
	snprintf(tray_sel_atom_name, sizeof(tray_sel_atom_name),
		 "_NET_SYSTEM_TRAY_S%u", DefaultScreen(g->display));
	g->tray_selection =
	    XInternAtom(g->display, tray_sel_atom_name, False);
	g->tray_opcode =
	    XInternAtom(g->display, "_NET_SYSTEM_TRAY_OPCODE", False);
	g->xembed_message = XInternAtom(g->display, "_XEMBED", False);
	g->xembed_info = XInternAtom(g->display, "_XEMBED_INFO", False);
	g->wm_state = XInternAtom(g->display, "_NET_WM_STATE", False);
	g->wm_state_fullscreen = XInternAtom(g->display, "_NET_WM_STATE_FULLSCREEN", False);
	g->wm_state_demands_attention = XInternAtom(g->display, "_NET_WM_STATE_DEMANDS_ATTENTION", False);
	g->wm_state_hidden = XInternAtom(g->display, "_NET_WM_STATE_HIDDEN", False);
	g->wm_user_time = XInternAtom(g->display, "_NET_WM_USER_TIME", False);
	g->frame_extents = XInternAtom(g->display, "_NET_FRAME_EXTENTS", False);
	/* create graphical contexts */
	get_frame_gc(g, g->cmdline_color ? : "red");
#ifdef FILL_TRAY_BG
	get_tray_gc(g);
#endif
	/* init window lists */
	g->remote2local = list_new();
	g->wid2windowdata = list_new();
	g->screen_window = NULL;
	/* use qrexec for clipboard operations when stubdom GUI is used */
	if (g->domid != g->target_domid)
		g->qrexec_clipboard = 1;
	/* disable private mode for HVM domains since SetMonitorLayout hangs
       and the Win7 tools don't properly redirect windows */
	if (g->qrexec_clipboard)
		g->private_mode = 0;
	if (getenv("KDE_SESSION_UID"))
		g->use_kdialog = 1;
	else
		g->use_kdialog = 0;
	g->window_width_tree = g_tree_new(ptrcmp_reverse);
	g->window_height_tree = g_tree_new(ptrcmp_reverse);

	g->icon_data = NULL;
	g->icon_data_len = 0;
	if (g->cmdline_icon && g->cmdline_icon[0] == '/') {
		/* in case of error g->icon_data will remain NULL so cmdline_icon will
		 * be used instead (as icon label) */
		g->icon_data = load_png(g->cmdline_icon, &g->icon_data_len);
		if (g->icon_data) {
			fprintf(stderr, "Icon size: %lux%lu\n", g->icon_data[0], g->icon_data[1]);
		}
	}
	g->inter_appviewer_lock_fd = open("/var/run/qubes/appviewer.lock",
			O_RDWR | O_CREAT, 0666);
	if (g->inter_appviewer_lock_fd < 0) {
		perror("create lock");
		exit(1);
	}
	/* ignore possible errors */
	fchmod(g->inter_appviewer_lock_fd, 0666);
}

/* reload X server parameters, especially after monitor/screen layout change */
void reload(Ghandles * g) {
	XWindowAttributes attr;

	g->screen = DefaultScreen(g->display);
	g->root_win = RootWindow(g->display, g->screen);
	XGetWindowAttributes(g->display, g->root_win, &attr);
	g->root_width = _VIRTUALX(attr.width);
	g->root_height = attr.height;
}

/* find if window (given by id) is managed by this guid */
static struct windowdata *check_nonmanaged_window(Ghandles * g, XID id)
{
	struct genlist *item = list_lookup(g->wid2windowdata, id);
	if (!item) {
		if (g->log_level > 0)
			fprintf(stderr, "cannot lookup 0x%x in wid2windowdata\n",
					(int) id);
		return NULL;
	}
	return item->data;
}

/* caller must take inter_appviewer_lock first */
static Time get_clipboard_file_xevent_timestamp() {
	FILE *file;
	Time timestamp;

	file = fopen(QUBES_CLIPBOARD_FILENAME ".xevent", "r");
	if (!file) {
		perror("open " QUBES_CLIPBOARD_FILENAME ".xevent");
		return 0;
	}
	fscanf(file, "%lu", &timestamp);
	fclose(file);
	return timestamp;
}

/* caller must take inter_appviewer_lock first */
static void save_clipboard_file_xevent_timestamp(Time timestamp) {
	FILE *file;

	file = fopen(QUBES_CLIPBOARD_FILENAME ".xevent", "w");
	if (!file) {
		perror("open " QUBES_CLIPBOARD_FILENAME ".xevent");
		exit(1);
	}
	fprintf(file, "%lu\n", timestamp);
	fclose(file);
}

static void save_clipboard_source_vmname(const char *vmname) {
	FILE *file;

	file = fopen(QUBES_CLIPBOARD_FILENAME ".source", "w");
	if (!file) {
		perror("open " QUBES_CLIPBOARD_FILENAME ".source");
		exit(1);
	}
	fwrite(vmname, strlen(vmname), 1, file);
	fclose(file);
}

/* fetch clippboard content from file */
/* lock already taken in is_special_keypress() */
static void get_qubes_clipboard(Ghandles *g, char **data, int *len)
{
	FILE *file;
	*len = 0;
	file = fopen(QUBES_CLIPBOARD_FILENAME, "r");
	if (!file)
		return;
	if (fseek(file, 0, SEEK_END) < 0) {
		show_error_message(g, "secure paste: failed to seek in " QUBES_CLIPBOARD_FILENAME);
		goto close_done;
	}
	*len = ftell(file);
	if (*len < 0) {
		*len = 0;
		show_error_message(g, "secure paste: failed to determine size of "
			QUBES_CLIPBOARD_FILENAME);
		goto close_done;
	}
	if (*len == 0)
		goto close_done;
	*data = malloc(*len);
	if (!*data) {
		perror("malloc");
		exit(1);
	}
	if (fseek(file, 0, SEEK_SET) < 0) {
		free(*data);
		*data = NULL;
		*len = 0;
		show_error_message(g, "secure paste: failed to seek in "
			QUBES_CLIPBOARD_FILENAME);
		goto close_done;
	}
	*len=fread(*data, 1, *len, file);
	if (*len < 0) {
		*len = 0;
		free(*data);
		*data=NULL;
		show_error_message(g, "secure paste: failed to read from "
			QUBES_CLIPBOARD_FILENAME);
		goto close_done;
	}
close_done:
	fclose(file);
	truncate(QUBES_CLIPBOARD_FILENAME, 0);
	save_clipboard_source_vmname("");
}

static int run_clipboard_rpc(Ghandles * g, enum clipboard_op op) {
	char *path_stdin, *path_stdout, *service_call;
	pid_t pid;
	struct rlimit rl;
	int fd;
	char domid_str[16];
	int status;

	switch (op) {
		case CLIPBOARD_COPY:
			path_stdin = "/dev/null";
			path_stdout = QUBES_CLIPBOARD_FILENAME;
			service_call = "DEFAULT:QUBESRPC qubes.ClipboardCopy";
			break;
		case CLIPBOARD_PASTE:
			path_stdin = QUBES_CLIPBOARD_FILENAME;
			path_stdout = "/dev/null";
			service_call = "DEFAULT:QUBESRPC qubes.ClipboardPaste";
			break;
		default:
			/* not reachable */
			return 0;
	}
	switch (pid=fork()) {
		case -1:
			perror("fork");
			exit(1);
		case 0:
			/* in case of error do not use exit(1) in child to not fire
			 * atexit() registered functions; use _exit() instead (which do not
			 * fire that functions) */
			fd = open(path_stdout, O_WRONLY|O_CREAT|O_TRUNC, 0644);
			if (fd < 0) {
				perror("open");
				_exit(1);
			}
			if (op == CLIPBOARD_COPY) {
				rl.rlim_cur = MAX_CLIPBOARD_SIZE;
				rl.rlim_max = MAX_CLIPBOARD_SIZE;
				setrlimit(RLIMIT_FSIZE, &rl);
				// TODO: place for security filter (via pipe() and another fork+exec)
			}
			dup2(fd, 1);
			close(fd);
			fd = open(path_stdin, O_RDONLY);
			if (fd < 0) {
				perror("open");
				_exit(1);
			}
			dup2(fd, 0);
			close(fd);
			snprintf(domid_str, sizeof(domid_str), "%d", g->target_domid);
			execl(QREXEC_CLIENT_PATH, "qrexec-client", "-d", domid_str, service_call, (char*)NULL);
			perror("execl");
			_exit(1);
		default:
			waitpid(pid, &status, 0);
	}
	return WEXITSTATUS(status) == 0;
}

static int fetch_qubes_clipboard_using_qrexec(Ghandles * g) {
	int ret;

	inter_appviewer_lock(g, 1);
	ret = run_clipboard_rpc(g, CLIPBOARD_COPY);
	if (ret) {
		save_clipboard_source_vmname(g->vmname);
		save_clipboard_file_xevent_timestamp(g->clipboard_xevent_time);
	} else {
		truncate(QUBES_CLIPBOARD_FILENAME, 0);
		save_clipboard_source_vmname("");
	}

	inter_appviewer_lock(g, 0);
	return ret;
}

/* lock already taken in is_special_keypress() */
static int paste_qubes_clipboard_using_qrexec(Ghandles * g) {
	int ret;

	ret = run_clipboard_rpc(g, CLIPBOARD_PASTE);
	if (ret) {
		truncate(QUBES_CLIPBOARD_FILENAME, 0);
		save_clipboard_source_vmname("");
	}

	return ret;
}


/* handle VM message: MSG_CLIPBOARD_DATA
 *  - checks if clipboard data was requested
 *  - store it in file
 */
static void handle_clipboard_data(Ghandles * g, unsigned int untrusted_len)
{
	FILE *file;
	char *untrusted_data;
	size_t untrusted_data_sz;
	Time clipboard_file_xevent_time;
	if (g->log_level > 0)
		fprintf(stderr, "handle_clipboard_data, len=0x%x\n",
			untrusted_len);
	if (untrusted_len > MAX_CLIPBOARD_SIZE) {
		fprintf(stderr, "clipboard data len 0x%x?\n",
			untrusted_len);
		exit(1);
	}
	/* now sanitized */
	untrusted_data_sz = untrusted_len;
	untrusted_data = malloc(untrusted_data_sz);
	if (!untrusted_data) {
		perror("malloc");
		exit(1);
	}
	read_data(g->vchan, untrusted_data, untrusted_data_sz);
	if (!g->clipboard_requested) {
		free(untrusted_data);
		fprintf(stderr,
			"received clipboard data when not requested\n");
		return;
	}
	inter_appviewer_lock(g, 1);
	clipboard_file_xevent_time = get_clipboard_file_xevent_timestamp();
	if (clipboard_file_xevent_time > g->clipboard_xevent_time) {
		/* some other clipboard operation happened in the meantime, discard
		 * request */
		inter_appviewer_lock(g, 0);
		fprintf(stderr,
			"received clipboard data after some other clipboard op, discarding\n");
		return;
	}
	file = fopen(QUBES_CLIPBOARD_FILENAME, "w");
	if (!file) {
		show_error_message(g, "secure copy: failed to open file " QUBES_CLIPBOARD_FILENAME);
		goto error;
	}
	if (fwrite(untrusted_data, 1, untrusted_data_sz, file) != untrusted_data_sz) {
		fclose(file);
		show_error_message(g, "secure copy: failed to write to file " QUBES_CLIPBOARD_FILENAME);
		goto error;
	}
	if (fclose(file) < 0) {
		show_error_message(g, "secure copy: failed to close file " QUBES_CLIPBOARD_FILENAME);
		goto error;
	}
	save_clipboard_source_vmname(g->vmname);
	save_clipboard_file_xevent_timestamp(g->clipboard_xevent_time);
error:
	inter_appviewer_lock(g, 0);
	g->clipboard_requested = 0;
	free(untrusted_data);
}

static int evaluate_clipboard_policy(Ghandles * g) {
	int fd, len;
	char source_vm[255];
	int status;
	pid_t pid;

	fd = open(QUBES_CLIPBOARD_FILENAME ".source", O_RDONLY);
	if (fd < 0)
		return 0;

	len = read(fd, source_vm, sizeof(source_vm)-1);
	if (len < 0) {
		perror("read");
		close(fd);
		return 0;
	}
	close(fd);
	if (len == 0) {
		/* empty clipboard */
		return 0;
	}
	source_vm[len] = 0;
	switch(pid=fork()) {
		case -1:
			perror("fork");
			exit(1);
		case 0:
			execl(QREXEC_POLICY_PATH, "qrexec-policy", "--assume-yes-for-ask", "--just-evaluate",
					"dummy_id", source_vm, g->vmname, "qubes.ClipboardPaste", "0", (char*)NULL);
			perror("execl");
			_exit(1);
		default:
			waitpid(pid, &status, 0);
	}
	return WEXITSTATUS(status) == 0;
}

/* check and handle guid-special keys
 * currently only for inter-vm clipboard copy
 */
static int is_special_keypress(Ghandles * g, const XKeyEvent * ev, XID remote_winid)
{
	struct msg_hdr hdr;
	char *data;
	int len;
	Time clipboard_file_xevent_time;
	if (((int)ev->state & SPECIAL_KEYS_MASK) ==
	    g->copy_seq_mask
	    && ev->keycode == XKeysymToKeycode(g->display,
					       g->copy_seq_key)) {
		if (ev->type != KeyPress)
			return 1;
		g->clipboard_xevent_time = ev->time;
		if (g->qrexec_clipboard) {
			int ret = fetch_qubes_clipboard_using_qrexec(g);
			if (g->log_level > 0)
				fprintf(stderr, "secure copy: %s\n", ret?"success":"failed");
		} else {
			g->clipboard_requested = 1;
			hdr.type = MSG_CLIPBOARD_REQ;
			hdr.window = remote_winid;
			hdr.untrusted_len = 0;
			if (g->log_level > 0)
				fprintf(stderr, "secure copy\n");
			write_struct(g->vchan, hdr);
		}
		return 1;
	}
	if (((int)ev->state & SPECIAL_KEYS_MASK) ==
	    g->paste_seq_mask
	    && ev->keycode == XKeysymToKeycode(g->display,
					       g->paste_seq_key)) {
		if (ev->type != KeyPress)
			return 1;
		inter_appviewer_lock(g, 1);
		clipboard_file_xevent_time = get_clipboard_file_xevent_timestamp();
		if (clipboard_file_xevent_time > ev->time) {
			/* some other clipboard operation happened in the meantime, discard
			 * request */
			inter_appviewer_lock(g, 0);
			fprintf(stderr,
					"received clipboard xevent after some other clipboard op, discarding\n");
			return 1;
		}
		if (!evaluate_clipboard_policy(g)) {
			inter_appviewer_lock(g, 0);
			return 1;
		}
		if (g->qrexec_clipboard) {
			int ret = paste_qubes_clipboard_using_qrexec(g);
			if (g->log_level > 0)
				fprintf(stderr, "secure paste: %s\n", ret?"success":"failed");
		} else {
			hdr.type = MSG_CLIPBOARD_DATA;
			if (g->log_level > 0)
				fprintf(stderr, "secure paste\n");
			get_qubes_clipboard(g, &data, &len);
			if (len > 0) {
				/* MSG_CLIPBOARD_DATA uses the window field to pass the length
				   of the blob */
				hdr.window = len;
				hdr.untrusted_len = len;
				real_write_message(g->vchan, (char *) &hdr, sizeof(hdr),
						data, len);
				free(data);
			}
		}
		inter_appviewer_lock(g, 0);

		return 1;
	}
	return 0;
}

/* handle local Xserver event: XKeyEvent
 * send it to relevant window in VM
 */
static void process_xevent_keypress(Ghandles * g, const XKeyEvent * ev)
{
	struct msg_hdr hdr;
	struct msg_keypress k;
	CHECK_NONMANAGED_WINDOW(g, ev->window);
	g->last_input_window = vm_window;
	if (is_special_keypress(g, ev, vm_window->remote_winid))
		return;
	k.type = ev->type;
	k.x = ev->x;
	k.y = ev->y;
	k.state = ev->state;
	k.keycode = ev->keycode;
	hdr.type = MSG_KEYPRESS;
	hdr.window = vm_window->remote_winid;
	write_message(g->vchan, hdr, k);
//      fprintf(stderr, "win 0x%x(0x%x) type=%d keycode=%d\n",
//              (int) ev->window, hdr.window, k.type, k.keycode);
}

// debug routine
#ifdef DEBUG
static void dump_mapped(Ghandles * g)
{
	struct genlist *item = g->wid2windowdata->next;
	for (; item != g->wid2windowdata; item = item->next) {
		struct windowdata *c = item->data;
		if (c->is_mapped) {
			if (g->log_level > 1)
				fprintf(stderr,
					"id 0x%x(0x%x) w=0x%x h=0x%x rx=%d ry=%d ovr=%d\n",
					(int) c->local_winid,
					(int) c->remote_winid, c->width,
					c->height, c->x, c->y,
					c->override_redirect);
		}
	}
}
#endif

/* handle local Xserver event: XButtonEvent
 * same as XKeyEvent - send to relevant window in VM */
static void process_xevent_button(Ghandles * g, const XButtonEvent * ev)
{
	struct msg_hdr hdr;
	struct msg_button k;
	CHECK_NONMANAGED_WINDOW(g, ev->window);

	g->last_input_window = vm_window;
	k.type = ev->type;

	k.x = ev->x;
	k.y = ev->y;
	k.state = ev->state;
	k.button = ev->button;
	hdr.type = MSG_BUTTON;
	hdr.window = vm_window->remote_winid;
	write_message(g->vchan, hdr, k);
	if (g->log_level > 1)
		fprintf(stderr,
			"xside: win 0x%x(0x%x) type=%d button=%d x=%d, y=%d\n",
			(int) ev->window, hdr.window, k.type, k.button,
			k.x, k.y);
	if (vm_window->is_docked && ev->type == ButtonPress) {
		/* Take focus to that icon, to make possible keyboard nagivation
		 * through the menu */
		XSetInputFocus(g->display, vm_window->local_winid, RevertToParent,
				CurrentTime);
	}
}

/* handle local Xserver event: XCloseEvent
 * send to relevant window in VM */
static void process_xevent_close(Ghandles * g, XID window)
{
	struct msg_hdr hdr;
	CHECK_NONMANAGED_WINDOW(g, window);
	hdr.type = MSG_CLOSE;
	hdr.window = vm_window->remote_winid;
	hdr.untrusted_len = 0;
	write_struct(g->vchan, hdr);
}

/* handle local Xserver event XReparentEvent
 * store information whether the window is reparented into some frame window */
static void process_xevent_reparent(Ghandles *g, XReparentEvent *ev) {
	CHECK_NONMANAGED_WINDOW(g, ev->window);
	struct windowdata* parent = lookup_remote(g, vm_window->remote_parent);

	/* check if current parent matches the one in the VM - this means the
	 * window is reparented back into original structure (window manager
	 * restart?)
	 */
	if ((parent && ev->parent == parent->local_winid) ||
	    (!parent && ev->parent == g->root_win))
		vm_window->local_frame_winid = 0;
	else
		vm_window->local_frame_winid = ev->parent;
	if (g->log_level > 1)
		fprintf(stderr,
			"process_xevent_reparent(synth %d) local 0x%x remote 0x%x, "
			"local parent 0x%x, frame window 0x%x\n",
			ev->send_event,
			(int) vm_window->local_winid, (int) vm_window->remote_winid,
			(int)ev->parent, (int)vm_window->local_frame_winid);
}

/* send configure request for specified VM window */
static int send_configure(Ghandles * g, struct windowdata *vm_window)
{
	struct msg_hdr hdr;
	struct msg_configure msg;

	if (g->log_level > 1)
		fprintf(stderr,
			"send_configure, local 0x%x remote 0x%x, %d/%d, "
			"xy %d/%d\n",
			(int) vm_window->local_winid,
			(int) vm_window->remote_winid,
			vm_window->width, vm_window->height,
			vm_window->untrusted_remote_x, vm_window->untrusted_remote_y);

	hdr.type = MSG_CONFIGURE;
	hdr.window = vm_window->remote_winid;
	msg.height = vm_window->height;
	msg.width = vm_window->width;
	msg.x = vm_window->untrusted_remote_x;
	msg.y = vm_window->untrusted_remote_y;
	write_message(g->vchan, hdr, msg);
	return 1;
}

static void get_untrusted_remote_screen_xy(Ghandles* g, struct windowdata *vm_window, int* px, int* py)
{
	int x = 0;
	int y = 0;
	for(; vm_window; vm_window = lookup_remote(g, vm_window->remote_parent)) {
		x += vm_window->untrusted_remote_x;
		y += vm_window->untrusted_remote_y;
	}
	*px = x;
	*py = y;
}

static void clip_coordinate(int* c, int size, int limit, int have_pointer, int pointer, int have_align_transient, int transient_for_x, int transient_for_size) {
	if(size > limit)
		abort();

	if(*c < 0) {
		/* try to align to override-redirect transient (the menu that caused this submenu to open) */
		if(have_align_transient && transient_for_x >= size && transient_for_x <= limit)
			*c = transient_for_x - size;
		else if(have_align_transient && (transient_for_x + transient_for_size) >= size && (transient_for_x + transient_for_size + size) <= limit)
			*c = transient_for_x + transient_for_size;
		/* try to position the edge where the pointer is, on the closest side,
		   then on the farther one and otherwise align to the window edge */
		else if(have_pointer && pointer >= size && pointer <= limit)
			*c = pointer - size;
		else if(have_pointer && pointer >= 0 && (pointer + size) <= limit)
			*c = pointer;
		/* else just clip to edge */
		else
			*c = 0;
	} else if((*c + size) > limit) {
		/* flip everything and use the code above */
		*c = limit - *c - size;
		pointer = limit - pointer;
		transient_for_x = limit - transient_for_x - transient_for_size;

		clip_coordinate(c, size, limit, have_pointer, pointer, have_align_transient, transient_for_x, transient_for_size);

		*c = limit - *c - size;
	}
}

/* TODO: is there a way of getting this information with 1 roundtrip and no race conditions? */
static Window get_pointer_window(Display* dpy, Window start_win) {
	Window root, child;
	int pointer_x, pointer_y, root_pointer_x, root_pointer_y;
	unsigned mask;
	Window prev_win = 0;

	for(;;) {
		Window win = start_win;
		for(;;) {
			if(!XQueryPointer(dpy, win, &root, &child, &root_pointer_x, &root_pointer_y, &pointer_x, &pointer_y, &mask))
				return 0;
			if(!child || win == child)
				break;
			win = child;
		}
		/* only return when we get the same window twice to try to work around race conditions */
		if(win == prev_win)
			return win;
		prev_win = win;
	}
}


static void update_local(Ghandles * g, struct windowdata *vm_window, int remote_moved, int remote_resized, int remote_override_redirect_changed, int remote_transient_for_changed, int apply)
{
	struct windowdata *transient_for = lookup_remote(g, vm_window->untrusted_remote_transient_for);

	/* window to use as reference to translate coordinates */
	struct windowdata *ref_window = lookup_remote(g, vm_window->remote_ref_window);

	struct windowdata* parent = lookup_remote(g, vm_window->remote_parent);
	int moved;
	int resized;
	int override_redirect_changed;
	int transient_for_changed;
	int x = vm_window->x;
	int y = vm_window->y;
	int width = vm_window->width;
	int height = vm_window->height;
	int override_redirect = vm_window->override_redirect;

	override_redirect = vm_window->is_docked ? 0 : !!vm_window->untrusted_remote_override_redirect;

	if(!ref_window && override_redirect && g->last_input_window && g->last_input_window->is_docked) {
		/* fix programs that popup menus on tray icons with transient_for set to the main window */
		ref_window = g->last_input_window;
	}

	if(!ref_window && transient_for)
		ref_window = transient_for;

	if(!ref_window && override_redirect) {
		/* the GTK menu implementation allows to create popup meus without transient_for,
		   so use the last input window and hope for the best */
		ref_window = g->last_input_window;
	}

	vm_window->remote_ref_window = ref_window ? ref_window->remote_winid : 0;

	if(g->log_level > 1)
		fprintf(stderr, "update_local start for local 0x%x remote 0x%x: was (%i, %i) %ix%i override=%u is_mapped=%u remote%s%s%s%s (%i, %i) %ix%i override=%u is_mapped=%u transient_for local 0x%x remote 0x%x ref_window local 0x%x remote 0x%x parent local 0x%x remote 0x%x\n",
		    (int)vm_window->local_winid, (int)vm_window->remote_winid,
			vm_window->x, vm_window->y,
			vm_window->width, vm_window->height,
			vm_window->override_redirect,
			vm_window->is_mapped,
			remote_moved ? " moved" : "", remote_resized ? " resized" : "", remote_override_redirect_changed ? " override_redirect_changed" : "", remote_transient_for_changed ? " transient_for_changed" : "",
			vm_window->untrusted_remote_x, vm_window->untrusted_remote_y,
			vm_window->untrusted_remote_width, vm_window->untrusted_remote_height,
			vm_window->untrusted_remote_override_redirect,
			vm_window->remote_is_mapped,
			transient_for ? (int)transient_for->local_winid : 0, (int)vm_window->untrusted_remote_transient_for,
			ref_window ? (int)ref_window->local_winid : 0, ref_window ? (int)ref_window->remote_winid : 0,
			parent ? (int)parent->local_winid : 0, parent ? (int)parent->remote_winid : 0);

	/* We do not allow a docked window to change its size or redirection, period. */

	if(remote_resized && !vm_window->is_docked) {
		width = sanitize_window_width(g, vm_window->untrusted_remote_width);
		height = sanitize_window_height(g, vm_window->untrusted_remote_height);
	}

	if(vm_window->is_docked) {
		/* nothing */
	} else if(parent) {
		/* just pass child windows through */
		if(remote_moved) {
			x = sanitize_x(vm_window->untrusted_remote_x);
			y = sanitize_y(vm_window->untrusted_remote_y);
		}
	} else if(override_redirect &&
		vm_window->untrusted_remote_x <= 0 &&
		vm_window->untrusted_remote_y <= 0 &&
		(vm_window->untrusted_remote_width < 0 || (vm_window->untrusted_remote_x + (int)vm_window->untrusted_remote_width) <= 0) &&
		(vm_window->untrusted_remote_height < 0 || (vm_window->untrusted_remote_y + (int)vm_window->untrusted_remote_height) <= 0)
		) {
		/* hack to fix the GTK menu implementation that creates a visible offscreen window */
		x = -MAX_WINDOW_WIDTH;
		y = -MAX_WINDOW_HEIGHT;
	} else if(g->private_mode && ref_window) {
		/* place relative to an existing window */

		Window root, child;
		int pointer_x, pointer_y, root_pointer_x, root_pointer_y;
		int clip_width, clip_height;
		unsigned mask;
		int have_pointer;

		int avoid = 0;
		int avoid_x = 0, avoid_y = 0, avoid_width = 0, avoid_height = 0;

		int old_offset_x, old_offset_y;
		int offset_x, offset_y;
		struct windowdata *clip_window = ref_window;

		/* find a good window to clip our window to */
		for(;;) {
			struct windowdata* next;
			if(clip_window->is_docked)
				break;
			else if((next = lookup_remote(g, clip_window->remote_parent)))
				clip_window = next;
			else if((next = lookup_remote(g, clip_window->remote_ref_window)) || (next = lookup_remote(g, clip_window->untrusted_remote_transient_for))) {
				/* go up from unredirected window only if the upper window fully contains this window */
				if(!clip_window->override_redirect && (clip_window->x < next->x || clip_window->y < next->y || (clip_window->x + (int)clip_window->width) > (next->x + (int)next->width) || (clip_window->y + (int)clip_window->height) > (next->y + (int)next->height)))
					break;
				clip_window = next;
			}
			else
				break;
		}

		clip_width = (int)clip_window->width;
		clip_height = (int)clip_window->height;

		have_pointer = XQueryPointer(g->display, clip_window->local_winid, &root, &child, &root_pointer_x, &root_pointer_y, &pointer_x, &pointer_y, &mask);

		if(width > clip_width || height > clip_height) {
			Window pointer_window;
			int own_pointer = pointer_x >= 0 && pointer_y >= 0 && pointer_x < clip_width && pointer_y < clip_height &&
				(pointer_window = get_pointer_window(g->display, g->root_win)) && list_lookup(g->wid2windowdata, pointer_window);
			int old_clip_width = clip_width;
			int old_clip_height = clip_height;
			struct windowdata* old_clip_window = clip_window;

			/* clip popups from docked windows to the screen, so that they don't fall off the screen
			   TODO: these checks prevent keyboard-only access to tray windows, is that needed?
			*/
			if(override_redirect && clip_window->is_docked && own_pointer) {
				XWindowAttributes attr;
				XGetWindowAttributes(g->display, g->root_win, &attr);
				clip_window = 0;
				clip_width = attr.width;
				clip_height = attr.height;

				have_pointer = XQueryPointer(g->display, g->root_win, &root, &child, &root_pointer_x, &root_pointer_y, &pointer_x, &pointer_y, &mask);

				/* avoid the tray icon so the user has a chance to not interact with the popup and leak its orientation */
				if(XTranslateCoordinates(g->display, old_clip_window->local_winid, g->root_win, 0, 0, &avoid_x, &avoid_y, &child)) {
					avoid = 1;
					avoid_width = old_clip_width;
					avoid_height = old_clip_height;
				}
			}

			if(!own_pointer) {
				avoid = 1;
				avoid_x = pointer_x - g->pointer_distance;
				avoid_y = pointer_y - g->pointer_distance;
				avoid_width = 1 + g->pointer_distance * 2;
				avoid_height = 1 + g->pointer_distance * 2;
			}

			if(g->log_level > 1)
				fprintf(stderr, "update_local ref doesn't fit for local 0x%x remote 0x%x %ix%i > %ix%i clip_window local 0x%x remote 0x%x to_screen=%i avoid=%i own_pointer=%i\n",
			    (int)vm_window->local_winid, (int)vm_window->remote_winid,
				width, height, old_clip_width, old_clip_height, (int)old_clip_window->local_winid, (int)old_clip_window->remote_winid, !clip_window, avoid, own_pointer);
		}

		if(parent == clip_window)
			old_offset_x = old_offset_y = 0;
		else if(!XTranslateCoordinates(g->display, parent ? parent->local_winid : g->root_win, clip_window ? clip_window->local_winid : g->root_win, 0, 0, &old_offset_x, &old_offset_y, &child))
			goto unconstrained;

		old_offset_x += vm_window->x;
		old_offset_y += vm_window->y;
		offset_x = old_offset_x;
		offset_y = old_offset_y;

		/* start placing the window as requested */
		if(!override_redirect && !(vm_window->untrusted_remote_size_hint_flags & (PPosition | USPosition))) {
			offset_x = (int)(clip_width - width) >> 1;
			offset_y = (int)(clip_height - height) >> 1;

			if(g->log_level > 1)
				fprintf(stderr, "update_local ref autoplace for local 0x%x remote 0x%x (%i, %i)\n",
			    (int)vm_window->local_winid, (int)vm_window->remote_winid,
				offset_x, offset_y);
		} else {
			int untrusted_offset_x;
			int untrusted_offset_y;
			int untrusted_x, untrusted_y;

			/* translate coordinates using a mapping that maps remote ref_window to local ref_window */
			get_untrusted_remote_screen_xy(g, parent, &untrusted_x, &untrusted_y);
			untrusted_offset_x = untrusted_x + vm_window->untrusted_remote_x;
			untrusted_offset_y = untrusted_y + vm_window->untrusted_remote_y;

			get_untrusted_remote_screen_xy(g, ref_window, &untrusted_x, &untrusted_y);
			untrusted_offset_x -= untrusted_x;
			untrusted_offset_y -= untrusted_y;

			if(clip_window == ref_window)
				offset_x = offset_y = 0;
			else if(!XTranslateCoordinates(g->display, ref_window->local_winid, clip_window ? clip_window->local_winid : g->root_win, 0, 0, &offset_x, &offset_y, &child))
				goto unconstrained;

			offset_x += sanitize_x(untrusted_offset_x);
			offset_y += sanitize_y(untrusted_offset_y);

			if(g->log_level > 1)
				fprintf(stderr, "update_local ref place for local 0x%x remote 0x%x (%i, %i)\n",
			    (int)vm_window->local_winid, (int)vm_window->remote_winid,
				offset_x, offset_y);
		}

		/* if it fits in the clip window, clip it to it */
		if(width <= clip_width && height <= clip_height) {
			int transient_for_x = 0;
			int transient_for_y = 0;
			int have_align_transient = 0;

			have_align_transient = transient_for && transient_for != clip_window && transient_for->override_redirect && override_redirect &&
				XTranslateCoordinates(g->display, transient_for->local_winid, clip_window ? clip_window->local_winid : g->root_win, 0, 0, &transient_for_x, &transient_for_y, &child);

			clip_coordinate(&offset_x, (int)width, (int)clip_width, have_pointer, pointer_x, have_align_transient, transient_for_x, transient_for ? transient_for->width : 0);
			clip_coordinate(&offset_y, (int)height, (int)clip_height, have_pointer, pointer_y, have_align_transient, transient_for_y, transient_for ? transient_for->height : 0);

			if(g->log_level > 1)
				fprintf(stderr, "update_local clip for local 0x%x remote 0x%x have_align_transient=%i\n",
			    (int)vm_window->local_winid, (int)vm_window->remote_winid,
				have_align_transient);
		}

		/* avoid the pointer if we are not clipping to a window and don't own the pointer, or if we are clipping to the screen */
		if(avoid && (offset_x < (avoid_x + avoid_width) && offset_y < (avoid_y + avoid_height) && avoid_x < (offset_x + width) && avoid_y < (offset_y + height))) {
			/* choose the direction to move the window in: choose one pointing towards the clip window,
			   on the axis where the distance to the closest edge is greater */
			int d_left = avoid_x - clip_width;
			int d_right = -(avoid_x + avoid_width);
			int d_up = avoid_y - clip_height;
			int d_down = -(avoid_y + avoid_height);
			int d_max = max(max(d_left, d_right), max(d_up, d_down));

			if(g->log_level > 1)
				fprintf(stderr, "update_local avoid pointer for local 0x%x remote 0x%x: %i %i %i %i\n",
			    (int)vm_window->local_winid, (int)vm_window->remote_winid,
				d_left, d_right, d_up, d_down);

			if(d_down == d_max)
				offset_y = avoid_y + avoid_height;
			else if(d_right == d_max)
				offset_x = avoid_x + avoid_width;
			else if(d_left == d_max)
				offset_x = avoid_x - width;
			else if(d_up == d_max)
				offset_y = avoid_y - height;
			else
				abort();
		}

	    /* don't allow to create a window that completely contains the clip window to avoid spoofing */
		if(clip_window && offset_x < 0 && offset_y < 0 && (offset_x + (int)width) > (int)clip_width && (offset_y + (int)height) > (int)clip_height) {
			if(!avoid)
				offset_y = pointer_y;
			else
				offset_y = clip_height >> 1;

			if(g->log_level > 1)
				fprintf(stderr, "update_local prevent contained for local 0x%x remote 0x%x avoid=%i\n",
			    (int)vm_window->local_winid, (int)vm_window->remote_winid,
				avoid);
		}

		/*
		if((offset_x + (int)width) < 0 || (offset_y + (int)height) < 0 || offset_x > (int)clip_width || offset_y > (int)clip_height) {
			// if we are creating a window not overlapping or touching the clip window, disable override redirect
			override_redirect = 0;
		}
		*/

		if(offset_x != old_offset_x || offset_y != old_offset_y)
		{
			int base_x;
			int base_y;
			if(clip_window == parent)
				base_x = base_y = 0;
			else if(!XTranslateCoordinates(g->display, clip_window ? clip_window->local_winid : g->root_win, parent ? parent->local_winid : g->root_win, 0, 0, &base_x, &base_y, &child))
				goto unconstrained;

			x = base_x + offset_x;
			y = base_y + offset_y;
		}

		if(g->log_level > 1)
			fprintf(stderr, "update_local ref for local 0x%x remote 0x%x: (%i, %i) = (%i, %i) + (%i, %i) was (%i, %i) clip_window local 0x%x remote 0x%x\n",
		    (int)vm_window->local_winid, (int)vm_window->remote_winid,
			x, y, x - offset_x, y - offset_y, offset_x, offset_y, old_offset_x, old_offset_y,
			clip_window ? (int)clip_window->local_winid : 0, clip_window ? (int)clip_window->remote_winid : 0);
	} else if(g->private_mode || (!vm_window->untrusted_remote_override_redirect && !(vm_window->untrusted_remote_size_hint_flags & (PPosition | USPosition)))) {
		/* place unconstrained window */

		int pointer_x, pointer_y, root_pointer_x, root_pointer_y;
		Window root, child;
		unsigned mask;
		int have_pointer;

unconstrained:
		have_pointer = XQueryPointer(g->display, g->root_win, &root, &child, &root_pointer_x, &root_pointer_y, &pointer_x, &pointer_y, &mask);

		XWindowAttributes attr;
		XGetWindowAttributes(g->display, g->root_win, &attr);

		if(!vm_window->is_mapped) {
			/* center the window */
			x = (g->root_width - width) >> 1;
			y = max(0, (g->root_height - height) >> 1);
		}

		/* make sure we don't steal input events by disallowing overlap with the cursor */
		if(!have_pointer || (root_pointer_x < (x - g->pointer_distance) || root_pointer_y < (y - g->pointer_distance) || root_pointer_x >= (x + (int)width + g->pointer_distance) || root_pointer_y >= (y + (int)height + g->pointer_distance)))
		{}
		else {
			/* make sure the window doesn't overlap the pointer to avoid input stealing and
			   to avoid sniffing the cursor position, but put it close to it for usability

			   doing it like this ensures that the titlebar stays on screen
			*/
			if(root_pointer_y * 2 < attr.height)
				y = root_pointer_y + g->pointer_distance;
			else if(root_pointer_x * 2 < attr.width)
				x = root_pointer_x + g->pointer_distance;
			else
				x = root_pointer_x - width - g->pointer_distance;
		}

		if(g->log_level > 1)
			fprintf(stderr, "update_local top-level\n");

		/* don't allow to override redirect top level windows */
		override_redirect = 0;
	} else {
		x = sanitize_x(vm_window->untrusted_remote_x);
		y = sanitize_y(vm_window->untrusted_remote_y);
	}

	moved = x != vm_window->x || y != vm_window->y;
	resized = width != vm_window->width || height != vm_window->height;
	override_redirect_changed = override_redirect != vm_window->override_redirect;
	transient_for_changed = remote_transient_for_changed;

	if(g->log_level > 1)
		fprintf(stderr, "update_local end for local 0x%x remote 0x%x: (%i, %i) %ix%i override=%u%s%s%s%s\n",
		    (int)vm_window->local_winid, (int)vm_window->remote_winid,
			x, y,
			width, height,
			override_redirect,
			moved ? " moved" : "", resized ? " resized" : "", override_redirect_changed ? " override_redirect_changed" : "", transient_for_changed ? " transient_for_changed" : "");

	if(moved) {
		vm_window->x = x;
		vm_window->y = y;
	}
	if(resized)
		set_window_size(g, vm_window, width, height);
	if(override_redirect_changed)
		vm_window->override_redirect = override_redirect;

	if(apply) {
		if(transient_for_changed)
			XSetTransientForHint(g->display, vm_window->local_winid, transient_for ? transient_for->local_winid : 0);

		if (override_redirect_changed) {
			XSetWindowAttributes attr;

			memset(&attr, 0, sizeof(attr));
			attr.override_redirect = vm_window->override_redirect;
			XChangeWindowAttributes(g->display, vm_window->local_winid,
						CWOverrideRedirect, &attr);
		}

		if(moved) {
			int border_x, border_y;
			Atom act_type;
			long *frame_extents; // left, right, top, bottom
			unsigned long nitems, bytesleft;
			int ret, act_fmt;

			/* we have window content coordinates, but XMoveResizeWindow requires
			 * left top *border* pixel coordinates (if any border is present). */
			ret = XGetWindowProperty(g->display, vm_window->local_winid, g->frame_extents, 0, 4,
				False, XA_CARDINAL, &act_type, &act_fmt, &nitems, &bytesleft, (unsigned char**)&frame_extents);
			if (ret == Success && nitems == 4) {
				border_x = vm_window->x - frame_extents[0];
				border_y = vm_window->y - frame_extents[2];
				XFree(frame_extents);
			} else {
				/* assume no border */
				border_x = vm_window->x;
				border_y = vm_window->y;
			}

			if(resized)
				XMoveResizeWindow(g->display, vm_window->local_winid, border_x, border_y, vm_window->width, vm_window->height);
			else
				XMoveWindow(g->display, vm_window->local_winid, border_x, border_y);
		} else if(resized)
	        XResizeWindow(g->display, vm_window->local_winid, vm_window->width, vm_window->height);
	}
}

static int update_remote(Ghandles * g, struct windowdata *vm_window)
{
	int untrusted_remote_x;
	int untrusted_remote_y;

	if(!g->private_mode) {
		untrusted_remote_x = vm_window->untrusted_remote_x;
		untrusted_remote_y = vm_window->untrusted_remote_y;
		if(vm_window->is_docked) {
	        /* docked window is reparented to root_win on vmside */
		    Window win;
		    XTranslateCoordinates(g->display, vm_window->local_winid, g->root_win, 0, 0, &untrusted_remote_x, &untrusted_remote_y, &win);
		} else {
			untrusted_remote_x = vm_window->x;
			untrusted_remote_y = vm_window->y;
		}
	} else {
		if(vm_window->is_docked) {
			untrusted_remote_x = 0;
			untrusted_remote_y = 0;
		} else if(vm_window->remote_is_mapped && !lookup_remote(g, vm_window->remote_parent) && (
			(!lookup_remote(g, vm_window->untrusted_remote_transient_for) && !lookup_remote(g, vm_window->remote_ref_window)) || (!vm_window->untrusted_remote_override_redirect && !(vm_window->untrusted_remote_size_hint_flags & (PPosition | USPosition)))
		)) {
			/* simulate window manager automatically placing the window

		       move top-level windows placed at (0, 0) to (0, 20) to have a realistic value
			   given that most systems have titlebars and so that we can assume that
			   (0, 0) always means "automatic positioning" rather than "at top left corner of window X"

				TODO: is this the place to do this? or should we do this on map?
			 */
			untrusted_remote_x = WINDOW_DEFAULT_X;
			untrusted_remote_y = WINDOW_DEFAULT_Y;
		} else {
			untrusted_remote_x = vm_window->untrusted_remote_x;
			untrusted_remote_y = vm_window->untrusted_remote_y;
		}
	}

	if(untrusted_remote_x == vm_window->untrusted_remote_x && untrusted_remote_y == vm_window->untrusted_remote_y &&
		vm_window->width == vm_window->untrusted_remote_width && vm_window->height == vm_window->untrusted_remote_height)
		return 0;

	vm_window->untrusted_remote_x = untrusted_remote_x;
	vm_window->untrusted_remote_y = untrusted_remote_y;
	vm_window->untrusted_remote_width = vm_window->width;
	vm_window->untrusted_remote_height = vm_window->height;
	send_configure(g, vm_window);

	return 1;
}


static int send_set_monitor_layout(Ghandles* g)
{
	int err;
	int status;
	pid_t pid = -1;
	int devnull;
	int stdin_pipe[2] = {-1, -1};
	posix_spawn_file_actions_t file_actions;
	char domid_str[16];
	char* args[] = {"qrexec-client", "-d", domid_str, "DEFAULT:QUBESRPC qubes.SetMonitorLayout dom0", 0};

	// HACK: the qrexec-client process seems to hang for HVMs, just skip it for now
	if(g->qrexec_clipboard)
		return 1;

	snprintf(domid_str, sizeof(domid_str), "%d", g->target_domid);

	fprintf(stderr, "send_set_monitor_layout %s", g->remote_monitor_layout);

	devnull = open("/dev/null", O_RDWR | O_CLOEXEC);
	if(devnull < 0) {
		perror("open /dev/null");
		exit(1);
	}

	if(pipe2(stdin_pipe, O_CLOEXEC) < 0) {
		perror("pipe2");
		exit(1);
	}

	posix_spawn_file_actions_init(&file_actions);
	posix_spawn_file_actions_adddup2(&file_actions, stdin_pipe[0], 0);
	/* prevent an exploited VM sending output and spoofing our log messages */
	posix_spawn_file_actions_adddup2(&file_actions, devnull, 1);
	/* leave stderr attached to our stderr */

	err = posix_spawn(&pid, QREXEC_CLIENT_PATH, &file_actions, NULL, &args[0], NULL);
	if(err) {
		fprintf(stderr, "posix_spawn qrexec-client: %s\n", strerror(err));
		exit(1);
	}
	close(devnull);
	close(stdin_pipe[0]);

	write(stdin_pipe[1], g->remote_monitor_layout, strlen(g->remote_monitor_layout));
	close(stdin_pipe[1]);

	if(waitpid(pid, &status, 0) < 0) {
		perror("waitpid");
		exit(1);
	}

	return WEXITSTATUS(status) == 0;
}

static void update_remote_screen(Ghandles* g)
{
	int rsw;
	int rsh;
	int w, h;
	int i;

	if(!g->private_mode)
		return;

	w = (int)(intptr_t)tree_get_first_key(g->window_width_tree) + WINDOW_DEFAULT_X;
	h = (int)(intptr_t)tree_get_first_key(g->window_height_tree) + WINDOW_DEFAULT_Y;

	for(i = 0; screen_resolutions[i]; i += 2) {
		rsw = screen_resolutions[i];
		rsh = screen_resolutions[i + 1];

		if(w <= rsw && h <= rsh)
			break;
	}

	if(!screen_resolutions[i]) {
		/* we mostly give up trying to blend in with non-Qubes users here,
		   and just try to reduce the the number of notifications we have to send,
		   try to fit in video RAM and still send plausible multi-monitor configuration sizes
	    */

		rsw = ((w ? ((w - 1) / large_screen_resolution_unit_w) : 0) + 1) * large_screen_resolution_unit_w;
		if(rsw < w)
			rsw = w;
		rsh = ((h ? ((h - 1) / large_screen_resolution_unit_h) : 0) + 1) * large_screen_resolution_unit_h;
		if(rsh < h)
			rsh = h;
	}

	if(rsw != g->remote_screen_width || rsh != g->remote_screen_height) {
		g->remote_screen_width = rsw;
		g->remote_screen_height = rsh;
		if(g->remote_monitor_layout)
			free(g->remote_monitor_layout);
		asprintf(&g->remote_monitor_layout, "%u %u 0 0\n", g->remote_screen_width, g->remote_screen_height);

		send_set_monitor_layout(g);
	}
}

/* handle local Xserver event: XConfigureEvent
 * after some checks/fixes send to relevant window in VM */
static void process_xevent_configure(Ghandles * g, const XConfigureEvent * ev)
{
	int x, y;
	CHECK_NONMANAGED_WINDOW(g, ev->window);
	if (g->log_level > 1)
		fprintf(stderr,
			"process_xevent_configure(synth %d) local 0x%x remote 0x%x, %d/%d, was "
			"%d/%d, xy %d/%d was %d/%d\n",
			ev->send_event,
			(int) vm_window->local_winid,
			(int) vm_window->remote_winid, ev->width,
			ev->height, vm_window->width, vm_window->height,
			ev->x, ev->y, vm_window->x, vm_window->y);
	/* non-synthetic events are about window position/size relative to the embeding
	 * frame window (if applies), synthetic one (produced by window manager) are
	 * about window position relative to original window parent.
	 * Because synthetic one isn't generated in all the cases (for example
	 * resize window without changing its position), process both of them and
	 * possibly ignore if nothing have changed
	 * See http://tronche.com/gui/x/icccm/sec-4.html#s-4.1.5 for details
	 */
	if (!ev->send_event && vm_window->local_frame_winid) {
		/* needs to translate coordinates */
		Window parent, child;
		struct windowdata* parentdata = lookup_remote(g, vm_window->remote_parent);
		if (parentdata)
			parent = parentdata->local_winid;
		else
			parent = g->root_win;
		if(!XTranslateCoordinates(g->display, ev->window, parent,
				0, 0, &x, &y, &child))
			return;
		if (g->log_level > 1)
			fprintf(stderr, "  translated to %d/%d\n", x, y);
	} else {
		x = ev->x;
		y = ev->y;
	}

	if (vm_window->width == ev->width
	    && vm_window->height == ev->height && vm_window->x == x
	    && vm_window->y == y)
		return;
	set_window_size(g, vm_window, ev->width, ev->height);
	update_remote_screen(g);

	vm_window->x = x;
	vm_window->y = y;

// if AppVM has not unacknowledged previous resize msg, do not send another one
	if (vm_window->have_queued_configure)
		return;
	if(update_remote(g, vm_window)) {
		if (vm_window->remote_winid != FULLSCREEN_WINDOW_ID)
			vm_window->have_queued_configure = 1;
	}
}

/* handle VM message: MSG_CONFIGURE
 * check if we like new dimensions/position and move relevant window */
static void handle_configure_from_vm(Ghandles * g, struct windowdata *vm_window)
{
	struct msg_configure untrusted_conf;
	int moved, resized, override_redirect_changed;

	read_struct(g->vchan, untrusted_conf);
	if (g->log_level > 1)
		fprintf(stderr,
			"handle_configure_from_vm, local 0x%x remote 0x%x, %d/%d, was"
			" %d/%d, ovr=%d, xy %d/%d, was %d/%d, queued=%u\n",
			(int) vm_window->local_winid,
			(int) vm_window->remote_winid,
			untrusted_conf.width, untrusted_conf.height,
			vm_window->width, vm_window->height,
			untrusted_conf.override_redirect, untrusted_conf.x,
			untrusted_conf.y, vm_window->untrusted_remote_x, vm_window->untrusted_remote_y,
			vm_window->have_queued_configure);

	moved = vm_window->untrusted_remote_x != (int)untrusted_conf.x ||
	    vm_window->untrusted_remote_y != (int)untrusted_conf.y;

	resized = vm_window->untrusted_remote_width != (int)untrusted_conf.width ||
	    vm_window->untrusted_remote_height != (int)untrusted_conf.height;

	override_redirect_changed = vm_window->untrusted_remote_override_redirect != (int)untrusted_conf.override_redirect;

	if (vm_window->have_queued_configure) {
		if (moved || resized) {
			update_remote(g, vm_window);
			moved = 0;
			resized = 0;
		} else {
			// same dimensions; this is an ack for our previously sent configure req
			vm_window->have_queued_configure = 0;
		}
	}
	if (!moved && !resized && !override_redirect_changed)
		return;

	vm_window->untrusted_remote_x = (int)untrusted_conf.x;
	vm_window->untrusted_remote_y = (int)untrusted_conf.y;
	vm_window->untrusted_remote_width = (int)untrusted_conf.width;
	vm_window->untrusted_remote_height = (int)untrusted_conf.height;
	vm_window->untrusted_remote_override_redirect = untrusted_conf.override_redirect;

	update_local(g, vm_window, moved, resized, override_redirect_changed, 0, 1);
}

/* handle local Xserver event: EnterNotify, LeaveNotify
 * send it to VM, but alwo we use it to fix docked
 * window position */
static void process_xevent_crossing(Ghandles * g, const XCrossingEvent * ev)
{
	struct msg_hdr hdr;
	struct msg_crossing k;
	CHECK_NONMANAGED_WINDOW(g, ev->window);

	if (ev->type == EnterNotify) {
		char keys[32];
		XQueryKeymap(g->display, keys);
		hdr.type = MSG_KEYMAP_NOTIFY;
		hdr.window = 0;
		write_message(g->vchan, hdr, keys);
	}

	/* update position of docked windows */
	update_remote(g, vm_window);

	hdr.type = MSG_CROSSING;
	hdr.window = vm_window->remote_winid;
	k.type = ev->type;
	k.x = ev->x;
	k.y = ev->y;
	k.state = ev->state;
	k.mode = ev->mode;
	k.detail = ev->detail;
	k.focus = ev->focus;
	write_message(g->vchan, hdr, k);
}

/* handle local Xserver event: XMotionEvent
 * send to relevant window in VM */
static void process_xevent_motion(Ghandles * g, const XMotionEvent * ev)
{
	struct msg_hdr hdr;
	struct msg_motion k;
	CHECK_NONMANAGED_WINDOW(g, ev->window);

	k.x = ev->x;
	k.y = ev->y;
	k.state = ev->state;
	k.is_hint = ev->is_hint;
	hdr.type = MSG_MOTION;
	hdr.window = vm_window->remote_winid;
	write_message(g->vchan, hdr, k);
//      fprintf(stderr, "motion in 0x%x", ev->window);
}

/* handle local Xserver event: FocusIn, FocusOut
 * send to relevant window in VM */
static void process_xevent_focus(Ghandles * g, const XFocusChangeEvent * ev)
{
	struct msg_hdr hdr;
	struct msg_focus k;
	CHECK_NONMANAGED_WINDOW(g, ev->window);

	/* Ignore everything other than normal, non-temporary focus change. In
	 * practice it ignores NotifyGrab and NotifyUngrab. VM does not have any
	 * way to grab focus in dom0, so it shouldn't care about those events. Grab
	 * is used by window managers during task switching (either classic task
	 * switcher, or KDE "present windows" feature.
	 */
	if (ev->mode != NotifyNormal && ev->mode != NotifyWhileGrabbed)
		return;

	if (ev->type == FocusIn) {
		g->last_input_window = vm_window;
		char keys[32];
		XQueryKeymap(g->display, keys);
		hdr.type = MSG_KEYMAP_NOTIFY;
		hdr.window = 0;
		write_message(g->vchan, hdr, keys);
	}
	hdr.type = MSG_FOCUS;
	hdr.window = vm_window->remote_winid;
	k.type = ev->type;
	/* override NotifyWhileGrabbed with NotifyNormal b/c VM shouldn't care
	 * about window manager details during focus switching
	 */
	k.mode = NotifyNormal;
	k.detail = ev->detail;
	write_message(g->vchan, hdr, k);
}

/* update given fragment of window image
 * can be requested by VM (MSG_SHMIMAGE) and Xserver (XExposeEvent)
 * parameters are not sanitized earlier - we must check it carefully
 * also do not let to cover forced colorful frame (for undecoraded windows)
 */
static void do_shm_update(Ghandles * g, struct windowdata *vm_window,
		   int untrusted_x, int untrusted_y, int untrusted_w,
		   int untrusted_h)
{
	int border_width = BORDER_WIDTH;
	int x = 0, y = 0, w = 0, h = 0;
	int base_x = 0, base_y = 0;
	XImage* image = 0;

	/* sanitize start */
	if (untrusted_x < 0 || untrusted_y < 0) {
		if (g->log_level > 1)
			fprintf(stderr,
				"do_shm_update for 0x%x(remote 0x%x), x=%d, y=%d, w=%d, h=%d ?\n",
				(int) vm_window->local_winid,
				(int) vm_window->remote_winid, untrusted_x,
				untrusted_y, untrusted_w, untrusted_h);
		return;
	}
	if (vm_window->image) {
		image = vm_window->image;
		x = min(untrusted_x, vm_window->width);
		y = min(untrusted_y, vm_window->height);
		w = min(max(untrusted_w, 0), vm_window->image_width - x);
		h = min(max(untrusted_h, 0), vm_window->image_height - y);
	} else if (g->screen_window) {
		image = g->screen_window->image;
		base_x = sanitize_x(vm_window->untrusted_remote_x);
		base_y = sanitize_y(vm_window->untrusted_remote_y);

		/* update only onscreen window part */
		/* if base_ differs from untrusted_ it means it's off the screen */
		if (base_x != vm_window->untrusted_remote_x || base_y != vm_window->untrusted_remote_y)
			return;
		if (base_x+untrusted_x < 0) {
			untrusted_w += base_x + untrusted_x;
			untrusted_x = -base_x;
		}
		if (base_y+untrusted_y < 0) {
			untrusted_h += base_y + untrusted_y;
			untrusted_y = -vm_window->y;
		}
		x = min(untrusted_x, g->screen_window->image_width - base_x);
		y = min(untrusted_y, g->screen_window->image_height - base_y);
		w = min(max(untrusted_w, 0), g->screen_window->image_width - base_x - x);
		h = min(max(untrusted_h, 0), g->screen_window->image_height - base_y - y);
		if (w <= 0 || h <= 0)
			return;
	}
	/* else: no image to update, will return after possibly drawing a frame */

	/* sanitize end */

	if (!vm_window->override_redirect) {
		// Window Manager will take care of the frame...
		border_width = 0;
	}

	if (vm_window->is_docked) {
		border_width = 1;
	}

	int do_border = 0;
	int delta, i;
	/* window contains only (forced) frame, so no content to update */
	if (vm_window->width <= border_width * 2
	    || vm_window->height <= border_width * 2) {
		XFillRectangle(g->display, vm_window->local_winid,
			       g->frame_gc, 0, 0,
			       vm_window->width,
			       vm_window->height);
		return;
	}
	if (!vm_window->image && !(g->screen_window && g->screen_window->image))
		return;
	/* force frame to be visible: */
	/*   * left */
	delta = border_width - x;
	if (delta > 0) {
		w -= delta;
		x = border_width;
		do_border = 1;
	}
	/*   * right */
	delta = x + w - (vm_window->width - border_width);
	if (delta > 0) {
		w -= delta;
		do_border = 1;
	}
	/*   * top */
	delta = border_width - y;
	if (delta > 0) {
		h -= delta;
		y = border_width;
		do_border = 1;
	}
	/*   * bottom */
	delta = y + h - (vm_window->height - border_width);
	if (delta > 0) {
		h -= delta;
		do_border = 1;
	}

	/* again check if something left to update */
	if (w <= 0 || h <= 0)
		return;

	if (g->log_level > 1)
		fprintf(stderr,
				"  do_shm_update for 0x%x(remote 0x%x), after border calc: x=%d, y=%d, w=%d, h=%d\n",
				(int) vm_window->local_winid,
				(int) vm_window->remote_winid,
				x, y, w, h);

#ifdef FILL_TRAY_BG
	if (vm_window->is_docked) {
		char *data, *datap;
		size_t data_sz;
		int xp, yp;

		if (!vm_window->image) {
			/* TODO: implement screen_window handling */
			return;
		}
		/* allocate image_width _bits_ for each image line */
		data_sz =
		    (vm_window->image_width / 8 +
		     1) * vm_window->image_height;
		data = datap = calloc(1, data_sz);
		if (!data) {
			perror("malloc(%dx%x -> %zu\n",
				vm_window->image_width, vm_window->image_height, data_sz);
			exit(1);
		}

		/* Create local pixmap, put vmside image to it
		 * then get local image of the copy.
		 * This is needed because XGetPixel does not seem to work
		 * with XShmImage data.
		 *
		 * Always use 0,0 w+x,h+y coordinates to generate proper mask. */
		w = w + x;
		h = h + y;
		if (w > vm_window->image_width)
			w = vm_window->image_width;
		if (h > vm_window->image_height)
			h = vm_window->image_height;
		Pixmap pixmap =
		    XCreatePixmap(g->display, vm_window->local_winid,
				  vm_window->image_width,
				  vm_window->image_height,
				  24);
		XShmPutImage(g->display, pixmap, g->context,
			     vm_window->image, 0, 0, 0, 0,
			     vm_window->image_width,
			     vm_window->image_height, 0);
		XImage *image = XGetImage(g->display, pixmap, 0, 0, w, h,
					  0xFFFFFFFF, ZPixmap);
		/* Use top-left corner pixel color as transparency color */
		unsigned long back = XGetPixel(image, 0, 0);
		/* Generate data for transparency mask Bitmap */
		for (yp = 0; yp < h; yp++) {
			int step = 0;
			for (xp = 0; xp < w; xp++) {
				if (datap - data >= data_sz) {
					fprintf(stderr,
						"Impossible internal error\n");
					exit(1);
				}
				if (XGetPixel(image, xp, yp) != back)
					*datap |= 1 << (step % 8);
				if (step % 8 == 7)
					datap++;
				step++;
			}
			/* ensure that new line will start at new byte */
			if ((step - 1) % 8 != 7)
				datap++;
		}
		Pixmap mask = XCreateBitmapFromData(g->display,
						    vm_window->local_winid,
						    data, w, h);
		/* set trayicon background to white color */
		XFillRectangle(g->display, vm_window->local_winid,
			       g->tray_gc, 0, 0, vm_window->width,
			       vm_window->height);
		/* Paint clipped Image */
		XSetClipMask(g->display, g->context, mask);
		XPutImage(g->display, vm_window->local_winid,
			  g->context, image, 0, 0, 0, 0, w, h);
		/* Remove clipping */
		XSetClipMask(g->display, g->context, None);

		XFreePixmap(g->display, mask);
		XDestroyImage(image);
		XFreePixmap(g->display, pixmap);
		free(data);
		return;
	} else
#endif
	{
		if(image)
			XShmPutImage(g->display, vm_window->local_winid,
					g->context, image, base_x+x,
					base_y+y, x, y, w, h, 0);
	}
	if (!do_border)
		return;
	for (i = 0; i < border_width; i++)
		XDrawRectangle(g->display, vm_window->local_winid,
			       g->frame_gc, i, i,
			       vm_window->width - 1 - 2 * i,
			       vm_window->height - 1 - 2 * i);

}

/* handle local Xserver event: XExposeEvent
 * update relevant part of window using stored image
 */
static void process_xevent_expose(Ghandles * g, const XExposeEvent * ev)
{
	CHECK_NONMANAGED_WINDOW(g, ev->window);
	do_shm_update(g, vm_window, ev->x, ev->y, ev->width, ev->height);
}

/* handle local Xserver event: XMapEvent
 * after some checks, send to relevant window in VM */
static void process_xevent_mapnotify(Ghandles * g, const XMapEvent * ev)
{
	XWindowAttributes attr;
	CHECK_NONMANAGED_WINDOW(g, ev->window);
	vm_window->is_mapped = 1;
	if (vm_window->remote_is_mapped)
		return;
	XGetWindowAttributes(g->display, vm_window->local_winid, &attr);
	if (attr.map_state != IsViewable && !vm_window->is_docked) {
		/* Unmap windows that are not visible on vmside.
		 * WM may try to map non-viewable windows ie. when
		 * switching desktops.
		 */
		(void) XUnmapWindow(g->display, vm_window->local_winid);
		if (g->log_level > 1)
			fprintf(stderr, "WM tried to map 0x%x, revert\n",
				(int) vm_window->local_winid);
	} else {
		/* Tray windows shall be visible always */
		struct msg_hdr hdr;
		struct msg_map_info map_info;

		vm_window->remote_is_mapped = 1;

		map_info.override_redirect = attr.override_redirect;
		hdr.type = MSG_MAP;
		hdr.window = vm_window->remote_winid;
		write_message(g->vchan, hdr, map_info);

		/* update position of docked windows */
		update_remote(g, vm_window);
	}
}

static inline uint32_t flags_from_atom(Ghandles * g, Atom a) {
	if (a == g->wm_state_fullscreen)
		return WINDOW_FLAG_FULLSCREEN;
	else if (a == g->wm_state_demands_attention)
		return WINDOW_FLAG_DEMANDS_ATTENTION;
	else if (a == g->wm_state_hidden)
		return WINDOW_FLAG_MINIMIZE;
	else {
		/* ignore unsupported states */
	}
	return 0;
}

/* handle local Xserver event: XPropertyEvent
 * currently only _NET_WM_STATE is examined */
static void process_xevent_propertynotify(Ghandles *g, const XPropertyEvent * ev)
{
	Atom act_type;
	Atom *state_list;
	unsigned long nitems, bytesleft, i;
	int ret, act_fmt;
	uint32_t flags;
	struct msg_hdr hdr;
	struct msg_window_flags msg;

	CHECK_NONMANAGED_WINDOW(g, ev->window);
	if (ev->atom == g->wm_state) {
		if (!vm_window->is_mapped) /* TODO: why? is this correct? */
			return;
		if (ev->state == PropertyNewValue) {
			ret = XGetWindowProperty(g->display, vm_window->local_winid, g->wm_state, 0, 10,
					False, XA_ATOM, &act_type, &act_fmt, &nitems, &bytesleft, (unsigned char**)&state_list);
			if (ret == Success && bytesleft > 0) {
			  /* Ensure we read all of the atoms */
			  XFree(state_list);
			  ret = XGetWindowProperty(g->display, vm_window->local_winid, g->wm_state,
			        0, (10 * 4 + bytesleft + 3) / 4, False, XA_ATOM, &act_type, &act_fmt,
			        &nitems, &bytesleft, (unsigned char**)&state_list);
			}
			if (ret != Success) {
				if (g->log_level > 0) {
					fprintf(stderr, "Failed to get 0x%x window state details\n", (int)ev->window);
					return;
				}
			}
			flags = 0;
			for (i = 0; i < nitems; i++) {
				flags |= flags_from_atom(g, state_list[i]);
			}
			XFree(state_list);
		} else { /* PropertyDelete */
			flags = 0;
		}
		if (flags == vm_window->flags_set) {
			/* no change */
			return;
		}
		hdr.type = MSG_WINDOW_FLAGS;
		hdr.window = vm_window->remote_winid;
		msg.flags_set = flags & ~vm_window->flags_set;
		msg.flags_unset = ~flags & vm_window->flags_set;
		write_message(g->vchan, hdr, msg);
		vm_window->flags_set = flags;
	}
}

/* handle local Xserver event: _XEMBED
 * if window isn't mapped already - map it now */
static void process_xevent_xembed(Ghandles * g, const XClientMessageEvent * ev)
{
	CHECK_NONMANAGED_WINDOW(g, ev->window);
	if (g->log_level > 1)
		fprintf(stderr, "_XEMBED message %ld\n", ev->data.l[1]);
	if (ev->data.l[1] == XEMBED_EMBEDDED_NOTIFY) {
		if (vm_window->is_docked < 2) {
			vm_window->is_docked = 2;
			if (!vm_window->is_mapped && !g->invisible) {
				vm_window->is_mapped = 1;
				XMapWindow(g->display, ev->window);
			}
			/* update position of docked windows */
			update_remote(g, vm_window);
		}
	} else if (ev->data.l[1] == XEMBED_FOCUS_IN) {
		struct msg_hdr hdr;
		struct msg_focus k;
		char keys[32];
		XQueryKeymap(g->display, keys);
		hdr.type = MSG_KEYMAP_NOTIFY;
		hdr.window = 0;
		write_message(g->vchan, hdr, keys);
		hdr.type = MSG_FOCUS;
		hdr.window = vm_window->remote_winid;
		k.type = FocusIn;
		k.mode = NotifyNormal;
		k.detail = NotifyNonlinear;
		write_message(g->vchan, hdr, k);
	}
}

static void update_monitor_layout(Ghandles * g) {
    int i;
	char* monitor_layout = 0;
	size_t monitor_layout_size = 0;
	FILE* monitor_layout_stream;
	XRRScreenResources* res;

	if(g->private_mode)
		return;

	g->remote_screen_width = g->root_width;
	g->remote_screen_height = g->root_height;

	monitor_layout_stream = open_memstream(&monitor_layout, &monitor_layout_size);
	res = XRRGetScreenResources (g->display, g->root_win);
	for(i = 0; i < res->noutput; ++i) {
		if(res->outputs[i]) {
			XRROutputInfo* output = XRRGetOutputInfo (g->display, res, res->outputs[i]);
			if(output) {
				if(output->crtc) {
					XRRCrtcInfo* crtc = XRRGetCrtcInfo (g->display, res, output->crtc);
					if(crtc) {
						if(crtc->mode)
							fprintf(monitor_layout_stream, "%i %i %i %i\n", crtc->width, crtc->height, crtc->x, crtc->y);
						XRRFreeCrtcInfo(crtc);
					}
				}
				XRRFreeOutputInfo(output);
			}
		}
	}
	XRRFreeScreenResources(res);
	fclose(monitor_layout_stream);

	if(!g->remote_monitor_layout || strcmp(monitor_layout, g->remote_monitor_layout))   {
		if(g->remote_monitor_layout)
			free(g->remote_monitor_layout);
		g->remote_monitor_layout = monitor_layout;
		monitor_layout = 0;
		send_set_monitor_layout(g);
	}

	free(monitor_layout);
}

static void process_xevent_rrscreenchangenotify(Ghandles * g, const XRRScreenChangeNotifyEvent* ev ) {
	XRRUpdateConfiguration((XEvent*)ev);

	if(g->log_level > 1)
		fprintf(stderr, "RRScreenChangeNotify\n");

	reload(g);

	update_monitor_layout(g);
}

/* dispatch local Xserver event */
static void process_xevent(Ghandles * g)
{
	XEvent event_buffer;
	XNextEvent(g->display, &event_buffer);
	switch (event_buffer.type) {
	case KeyPress:
	case KeyRelease:
		process_xevent_keypress(g, (XKeyEvent *) & event_buffer);
		break;
	case ReparentNotify:
		process_xevent_reparent(g, (XReparentEvent *) &event_buffer);
		break;
	case ConfigureNotify:
		process_xevent_configure(g, (XConfigureEvent *) &
					 event_buffer);
		break;
	case ButtonPress:
	case ButtonRelease:
		process_xevent_button(g, (XButtonEvent *) & event_buffer);
		break;
	case MotionNotify:
		process_xevent_motion(g, (XMotionEvent *) & event_buffer);
		break;
	case EnterNotify:
	case LeaveNotify:
		process_xevent_crossing(g,
					(XCrossingEvent *) & event_buffer);
		break;
	case FocusIn:
	case FocusOut:
		process_xevent_focus(g,
				     (XFocusChangeEvent *) & event_buffer);
		break;
	case Expose:
		process_xevent_expose(g, (XExposeEvent *) & event_buffer);
		break;
	case MapNotify:
		process_xevent_mapnotify(g, (XMapEvent *) & event_buffer);
		break;
	case PropertyNotify:
		process_xevent_propertynotify(g, (XPropertyEvent *) & event_buffer);
		break;
	case ClientMessage:
//              fprintf(stderr, "xclient, atom=%s\n",
//                      XGetAtomName(g->display,
//                                   event_buffer.xclient.message_type));
		if (event_buffer.xclient.message_type == g->xembed_message) {
			process_xevent_xembed(g, (XClientMessageEvent *) &
					      event_buffer);
		} else if ((Atom)event_buffer.xclient.data.l[0] ==
			   g->wmDeleteMessage) {
			if (g->log_level > 0)
				fprintf(stderr, "close for 0x%x\n",
					(int) event_buffer.xclient.window);
			process_xevent_close(g,
					     event_buffer.xclient.window);
		}
		break;
	default:;
	}

	if(event_buffer.type == (g->xrandr_event_base + RRScreenChangeNotify))
		process_xevent_rrscreenchangenotify(g, (XRRScreenChangeNotifyEvent*)&event_buffer);
}


/* handle VM message: MSG_SHMIMAGE
 * pass message data to do_shm_update - there input validation will be done */
static void handle_shmimage(Ghandles * g, struct windowdata *vm_window)
{
	struct msg_shmimage untrusted_mx;

	read_struct(g->vchan, untrusted_mx);
	if (!vm_window->is_mapped)
		return;
	if (g->log_level >= 2) {
		fprintf(stderr, "shmimage for 0x%x(remote 0x%x), x: %d, y: %d, w: %d, h: %d\n",
				(int) vm_window->local_winid, (int) vm_window->remote_winid,
				untrusted_mx.x, untrusted_mx.y, untrusted_mx.width,
				untrusted_mx.height);
	}
	/* WARNING: passing raw values, input validation is done inside of
	 * do_shm_update */
	do_shm_update(g, vm_window, untrusted_mx.x, untrusted_mx.y,
		      untrusted_mx.width, untrusted_mx.height);
}

/* handle VM message: MSG_CREATE
 * checks given attributes and create appropriate window in local Xserver
 * (using mkwindow) */
static void handle_create(Ghandles * g, XID window)
{
	struct windowdata *vm_window;
	struct windowdata* parentdata;
	struct msg_create untrusted_crt;
	XID parent;

	vm_window =
	    (struct windowdata *) calloc(1, sizeof(struct windowdata));
	if (!vm_window) {
		perror("malloc(vm_window in handle_create)");
		exit(1);
	}
	/*
	   because of calloc vm_window->image = 0;
	   vm_window->is_mapped = 0;
	   vm_window->remote_is_mapped = 0;
	   vm_window->untrusted_remote_size_hint_flags = 0;
	   vm_window->local_winid = 0;
	   vm_window->dest = vm_window->src = vm_window->pix = 0;
	   vm_window->x = 0;
	   vm_window->y = 0;
	   vm_window->width = 0;
	   vm_window->height = 0;
	   vm_window->override_redirect = 0;
	 */
	read_struct(g->vchan, untrusted_crt);
	/* sanitize start */
	VERIFY((int) untrusted_crt.width >= 0
	       && (int) untrusted_crt.height >= 0);

	vm_window->untrusted_remote_x = untrusted_crt.x;
	vm_window->untrusted_remote_y = untrusted_crt.y;
	vm_window->untrusted_remote_width = untrusted_crt.width;
	vm_window->untrusted_remote_height = untrusted_crt.height;
	vm_window->untrusted_remote_override_redirect = untrusted_crt.override_redirect;
	parent = untrusted_crt.parent;
	/* do this before inserting ourselves */
	parentdata = lookup_remote(g, parent);
	/* sanitize end */

	vm_window->remote_winid = window;
	if (!list_insert(g->remote2local, window, vm_window)) {
		fprintf(stderr, "list_insert(g->remote2local failed\n");
		exit(1);
	}
	if (parentdata)
		vm_window->remote_parent = parent;
	else
		vm_window->remote_parent = 0;
	vm_window->untrusted_remote_transient_for = 0;
	vm_window->remote_ref_window = 0;

	update_local(g, vm_window, 1, 1, 0, 0, 0);

	vm_window->local_winid = mkwindow(&ghandles, vm_window);
	if (g->log_level > 0)
		fprintf(stderr,
			"Created 0x%x(0x%x) parent 0x%x(0x%x) ovr=%d x/y %d/%d w/h %d/%d\n",
			(int) vm_window->local_winid, (int) window,
			(int) (parentdata ? parentdata->local_winid : 0), (unsigned) parent,
			vm_window->override_redirect,
			vm_window->x, vm_window->y,
			vm_window->width, vm_window->height);
	if (!list_insert
	    (g->wid2windowdata, vm_window->local_winid, vm_window)) {
		fprintf(stderr, "list_insert(g->wid2windowdata failed\n");
		exit(1);
	}
}

/* handle VM message: MSG_DESTROY
 * destroy window locally, as requested */
static void handle_destroy(Ghandles * g, struct genlist *l)
{
	struct genlist *l2;
	struct windowdata *vm_window = l->data;
	g->windows_count--;
	if (vm_window == g->last_input_window)
		g->last_input_window = NULL;
	XDestroyWindow(g->display, vm_window->local_winid);
	if (g->log_level > 0)
		fprintf(stderr, " XDestroyWindow 0x%x\n",
			(int) vm_window->local_winid);
	if (vm_window->image)
		release_mapped_mfns(g, vm_window);
	l2 = list_lookup(g->wid2windowdata, vm_window->local_winid);
	list_remove(l);
	list_remove(l2);
	if (vm_window == g->screen_window)
		g->screen_window = NULL;
	/* remove the window from the max width/height data structures */
	set_window_size(g, vm_window, 0, 0);
	free(vm_window);
}

/* validate single UTF-8 character
 * return bytes count of this character, or 0 if the character is invalid */
static int validate_utf8_char(unsigned char *untrusted_c) {
	int tails_count = 0;
	int total_size = 0;
	/* it is safe to access byte pointed by the parameter and the next one
	 * (which can be terminating NULL), but every next byte can access only if
	 * neither of previous bytes was NULL
	 */

	/* According to http://www.ietf.org/rfc/rfc3629.txt:
	 *   UTF8-char   = UTF8-1 / UTF8-2 / UTF8-3 / UTF8-4
	 *   UTF8-1      = %x00-7F
	 *   UTF8-2      = %xC2-DF UTF8-tail
	 *   UTF8-3      = %xE0 %xA0-BF UTF8-tail / %xE1-EC 2( UTF8-tail ) /
	 *                 %xED %x80-9F UTF8-tail / %xEE-EF 2( UTF8-tail )
	 *   UTF8-4      = %xF0 %x90-BF 2( UTF8-tail ) / %xF1-F3 3( UTF8-tail ) /
	 *                 %xF4 %x80-8F 2( UTF8-tail )
	 *   UTF8-tail   = %x80-BF
	 */

	if (*untrusted_c <= 0x7F) {
		return 1;
	} else if (*untrusted_c >= 0xC2 && *untrusted_c <= 0xDF) {
		total_size = 2;
		tails_count = 1;
	} else switch (*untrusted_c) {
		case 0xE0:
			untrusted_c++;
			total_size = 3;
			if (*untrusted_c >= 0xA0 && *untrusted_c <= 0xBF)
				tails_count = 1;
			else
				return 0;
			break;
		case 0xE1: case 0xE2: case 0xE3: case 0xE4:
		case 0xE5: case 0xE6: case 0xE7: case 0xE8:
		case 0xE9: case 0xEA: case 0xEB: case 0xEC:
			/* 0xED */
		case 0xEE:
		case 0xEF:
			total_size = 3;
			tails_count = 2;
			break;
		case 0xED:
			untrusted_c++;
			total_size = 3;
			if (*untrusted_c >= 0x80 && *untrusted_c <= 0x9F)
				tails_count = 1;
			else
				return 0;
			break;
		case 0xF0:
			untrusted_c++;
			total_size = 4;
			if (*untrusted_c >= 0x90 && *untrusted_c <= 0xBF)
				tails_count = 2;
			else
				return 0;
			break;
		case 0xF1:
		case 0xF2:
		case 0xF3:
			total_size = 4;
			tails_count = 3;
			break;
		case 0xF4:
			untrusted_c++;
			if (*untrusted_c >= 0x80 && *untrusted_c <= 0x8F)
				tails_count = 2;
			else
				return 0;
			break;
		default:
			return 0;
	}

	while (tails_count-- > 0) {
		untrusted_c++;
		if (!(*untrusted_c >= 0x80 && *untrusted_c <= 0xBF))
			return 0;
	}
	return total_size;
}

/* replace non-printable characters with '_'
 * given string must be NULL terminated already */
static void sanitize_string_from_vm(unsigned char *untrusted_s, int allow_utf8)
{
	int utf8_ret;
	for (; *untrusted_s; untrusted_s++) {
		// allow only non-control ASCII chars
		if (*untrusted_s >= 0x20 && *untrusted_s <= 0x7E)
			continue;
		if (allow_utf8 && *untrusted_s >= 0x80) {
			utf8_ret = validate_utf8_char(untrusted_s);
			if (utf8_ret > 0) {
				/* loop will do one additional increment */
				untrusted_s += utf8_ret - 1;
				continue;
			}
		}
		*untrusted_s = '_';
	}
}

/* handle VM message: MSG_VMNAME
 * remove non-printable characters and pass to X server */
static void handle_wmname(Ghandles * g, struct windowdata *vm_window)
{
	XTextProperty text_prop;
	struct msg_wmname untrusted_msg;
	char buf[sizeof(untrusted_msg.data)];
	char *list[1] = { buf };

	read_struct(g->vchan, untrusted_msg);
	/* sanitize start */
	untrusted_msg.data[sizeof(untrusted_msg.data) - 1] = 0;
	sanitize_string_from_vm((unsigned char *) (untrusted_msg.data),
				g->allow_utf8_titles);
	snprintf(buf, sizeof(buf), "%s", untrusted_msg.data);
	/* sanitize end */
	if (g->log_level > 1)
		fprintf(stderr, "set title for window 0x%x\n",
			(int) vm_window->local_winid);
	Xutf8TextListToTextProperty(g->display, list, 1, XUTF8StringStyle,
				    &text_prop);
	XSetWMName(g->display, vm_window->local_winid, &text_prop);
	XSetWMIconName(g->display, vm_window->local_winid, &text_prop);
	XFree(text_prop.value);
}

/* handle VM message: MSG_WMHINTS
 * Pass hints for window manager to local X server */
static void handle_wmhints(Ghandles * g, struct windowdata *vm_window)
{
	struct msg_window_hints untrusted_msg;
	XSizeHints size_hints;

	memset(&size_hints, 0, sizeof(size_hints));

	read_struct(g->vchan, untrusted_msg);

	vm_window->untrusted_remote_size_hint_flags = untrusted_msg.flags;

	/* sanitize start */
	size_hints.flags = 0;
	/* check every value and pass it only when sane */
	if (untrusted_msg.flags & PMinSize) {
		size_hints.flags |= PMinSize;
		size_hints.min_width = sanitize_window_width(g, untrusted_msg.min_width);
		size_hints.min_height = sanitize_window_height(g, untrusted_msg.min_height);
	}
	if (untrusted_msg.flags & PMaxSize) {
		size_hints.flags |= PMaxSize;
		size_hints.max_width = sanitize_width(untrusted_msg.max_width);
		size_hints.max_height = sanitize_height(untrusted_msg.max_height);
	}
	if (untrusted_msg.flags & PResizeInc) {
		size_hints.flags |= PResizeInc;
		size_hints.width_inc = sanitize_width(untrusted_msg.width_inc);
		size_hints.height_inc = sanitize_height(untrusted_msg.height_inc);
	}
	if (untrusted_msg.flags & PBaseSize) {
		size_hints.flags |= PBaseSize;
		size_hints.base_width = sanitize_width(untrusted_msg.base_width);
		size_hints.base_height = sanitize_height(untrusted_msg.base_height);
	}
	/* always set PPosition since we place all the windows ourselves */
	size_hints.flags |= PPosition;
	if (untrusted_msg.flags & USPosition)
		size_hints.flags |= USPosition;
	/* sanitize end */

	if(size_hints.flags & PMinSize && (size_hints.min_width > vm_window->width || size_hints.min_height > vm_window->height)) {
		vm_window->untrusted_remote_width = max(size_hints.min_width, vm_window->untrusted_remote_width);
		vm_window->untrusted_remote_height = max(size_hints.min_height, vm_window->untrusted_remote_height);
		update_remote(g, vm_window);
		update_local(g, vm_window, 0, 1, 0, 0, 1);
	}

	if (g->log_level > 1)
		fprintf(stderr,
			"set WM_NORMAL_HINTS for window 0x%x to min=%d/%d, max=%d/%d, base=%d/%d, inc=%d/%d (flags 0x%x)\n",
			(int) vm_window->local_winid, size_hints.min_width,
			size_hints.min_height, size_hints.max_width,
			size_hints.max_height, size_hints.base_width,
			size_hints.base_height, size_hints.width_inc,
			size_hints.height_inc, (int) size_hints.flags);
	XSetWMNormalHints(g->display, vm_window->local_winid, &size_hints);
}

/* handle VM message: MSG_WINDOW_FLAGS
 * Pass window state flags for window manager to local X server */
static void handle_wmflags(Ghandles * g, struct windowdata *vm_window)
{
	struct msg_window_flags untrusted_msg;
	struct msg_window_flags msg;

	read_struct(g->vchan, untrusted_msg);

	/* sanitize start */
	VERIFY((untrusted_msg.flags_set & untrusted_msg.flags_unset) == 0);
	msg.flags_set = untrusted_msg.flags_set & (
			WINDOW_FLAG_FULLSCREEN |
			WINDOW_FLAG_DEMANDS_ATTENTION |
			WINDOW_FLAG_MINIMIZE);
	msg.flags_unset = untrusted_msg.flags_unset & (
			WINDOW_FLAG_FULLSCREEN |
			WINDOW_FLAG_DEMANDS_ATTENTION);
	/* sanitize end */

	if (!vm_window->is_mapped) {
		/* for unmapped windows, set property directly; only "set" list is
		 * processed (will override property) */
		Atom state_list[10];
		int i = 0;

		vm_window->flags_set &= ~(WINDOW_FLAG_FULLSCREEN | WINDOW_FLAG_DEMANDS_ATTENTION);
		if (msg.flags_set & WINDOW_FLAG_FULLSCREEN) {
			if (g->allow_fullscreen) {
				vm_window->flags_set |= WINDOW_FLAG_FULLSCREEN;
				state_list[i++] = g->wm_state_fullscreen;
			} else {
				/* if fullscreen not allowed, substitute request with maximize */
				state_list[i++] = XInternAtom(g->display, "_NET_WM_STATE_MAXIMIZED_VERT", False);
				state_list[i++] = XInternAtom(g->display, "_NET_WM_STATE_MAXIMIZED_HORZ", False);
			}
		}
		if (msg.flags_set & WINDOW_FLAG_DEMANDS_ATTENTION) {
			vm_window->flags_set |= WINDOW_FLAG_DEMANDS_ATTENTION;
			state_list[i++] = g->wm_state_demands_attention;
		}
		if (i > 0) {
			/* FIXME: error checking? */
			XChangeProperty(g->display, vm_window->local_winid, g->wm_state,
					XA_ATOM, 32, PropModeReplace, (unsigned char*)state_list,
					i);
		} else
			/* just in case */
			XDeleteProperty(g->display, vm_window->local_winid, g->wm_state);

		/* Regarding WINDOW_FLAG_MINIMIZE:
		 * Restoring window from minimize state is exactly the same as MSG_MAP,
		 * so to not risk some regressions do not duplicate the code. */
	} else {
		/* for mapped windows, send message to window manager (via root window) */
		XClientMessageEvent ev;
		uint32_t flags_all = msg.flags_set | msg.flags_unset;

		if (!flags_all)
			/* no change requested */
			return;

		// WINDOW_FLAG_FULLSCREEN and WINDOW_FLAG_MINIMIZE are mutually exclusive
		if (msg.flags_set & WINDOW_FLAG_MINIMIZE)
			msg.flags_set &= ~WINDOW_FLAG_FULLSCREEN;

		memset(&ev, 0, sizeof(ev));
		ev.type = ClientMessage;
		ev.display = g->display;
		ev.window = vm_window->local_winid;
		ev.message_type = g->wm_state;
		ev.format = 32;
		ev.data.l[3] = 1; /* source indication: normal application */

		/* ev.data.l[0]: 1 - add/set property, 0 - remove/unset property */
		if (flags_all & WINDOW_FLAG_FULLSCREEN) {
			ev.data.l[0] = (msg.flags_set & WINDOW_FLAG_FULLSCREEN) ? 1 : 0;
			if (g->allow_fullscreen) {
				ev.data.l[1] = g->wm_state_fullscreen;
				ev.data.l[2] = 0;
			} else {
				ev.data.l[1] = XInternAtom(g->display, "_NET_WM_STATE_MAXIMIZED_VERT", False);
				ev.data.l[2] = XInternAtom(g->display, "_NET_WM_STATE_MAXIMIZED_HORZ", False);
			}
			XSendEvent(g->display, g->root_win, False,
					(SubstructureNotifyMask|SubstructureRedirectMask),
					(XEvent*) &ev);
		}
		if (msg.flags_set & WINDOW_FLAG_DEMANDS_ATTENTION) {
			ev.data.l[0] = (msg.flags_set & WINDOW_FLAG_DEMANDS_ATTENTION) ? 1 : 0;
			ev.data.l[1] = g->wm_state_demands_attention;
			ev.data.l[2] = 0;
			XSendEvent(g->display, g->root_win, False,
					(SubstructureNotifyMask|SubstructureRedirectMask),
					(XEvent*) &ev);
		}
		if (msg.flags_set & WINDOW_FLAG_MINIMIZE) {
			XIconifyWindow(g->display, vm_window->local_winid, g->screen);
		}
	}
}

/* handle VM message: MSG_MAP
 * Map a window with given parameters */
static void handle_map(Ghandles * g, struct windowdata *vm_window)
{
	struct msg_map_info untrusted_txt;
	int transient_for_changed = 0;
	int override_redirect_changed = 0;

	read_struct(g->vchan, untrusted_txt);

	vm_window->remote_is_mapped = 1;

	if(untrusted_txt.transient_for != vm_window->untrusted_remote_transient_for) {
		transient_for_changed = 1;
		vm_window->untrusted_remote_transient_for = untrusted_txt.transient_for;
	}

	if((int)untrusted_txt.override_redirect != vm_window->untrusted_remote_override_redirect) {
		override_redirect_changed = 1;
		vm_window->untrusted_remote_override_redirect = untrusted_txt.override_redirect;
	}

	if(g->log_level > 1)
		fprintf(stderr, "map, local 0x%x remote 0x%x transient_for=0x%x override_redirect=%u\n",
            (int)vm_window->local_winid, (int)vm_window->remote_winid,
			(int)vm_window->untrusted_remote_transient_for,
			vm_window->override_redirect);

	update_local(g, vm_window, 0, 0, override_redirect_changed, transient_for_changed, 1);

	if(!vm_window->is_mapped && !g->invisible) {
		vm_window->is_mapped = 1;
		(void) XMapWindow(g->display, vm_window->local_winid);
	}
}

/* handle VM message: MSG_UNMAP
 * Unmap a window with given parameters */
static void handle_unmap(Ghandles * g, struct windowdata *vm_window)
{
	vm_window->remote_is_mapped = 0;
	vm_window->remote_ref_window = 0;
	vm_window->is_mapped = 0;
	(void) XUnmapWindow(g->display, vm_window->local_winid);
}

/* handle VM message: MSG_DOCK
 * Try to dock window in the tray
 * Rest of XEMBED protocol is catched in VM */
static void handle_dock(Ghandles * g, struct windowdata *vm_window)
{
	Window tray;
	if (g->log_level > 0)
		fprintf(stderr, "docking window 0x%x\n",
			(int) vm_window->local_winid);
	tray = XGetSelectionOwner(g->display, g->tray_selection);
	if (tray != None) {
		long data[2];
		XClientMessageEvent msg;

		data[0] = 0;
		data[1] = 1;
		XChangeProperty(g->display, vm_window->local_winid,
				g->xembed_info, g->xembed_info, 32,
				PropModeReplace, (unsigned char *) data,
				2);

		memset(&msg, 0, sizeof(msg));
		msg.type = ClientMessage;
		msg.window = tray;
		msg.message_type = g->tray_opcode;
		msg.format = 32;
		msg.data.l[0] = CurrentTime;
		msg.data.l[1] = SYSTEM_TRAY_REQUEST_DOCK;
		msg.data.l[2] = vm_window->local_winid;
		msg.display = g->display;
		XSendEvent(msg.display, msg.window, False, NoEventMask,
			   (XEvent *) & msg);
	}
	vm_window->is_docked = 1;
}

/* Obtain/release inter-vm lock
 * Used for handling shared Xserver memory and clipboard file */
static void inter_appviewer_lock(Ghandles *g, int mode)
{
	int cmd;
	if (mode)
		cmd = LOCK_EX;
	else
		cmd = LOCK_UN;
	if (flock(g->inter_appviewer_lock_fd, cmd) < 0) {
		perror("lock");
		exit(1);
	}
}

/* release shared memory connected with given window */
static void release_mapped_mfns(Ghandles * g, struct windowdata *vm_window)
{
	if (g->invisible)
		return;
	inter_appviewer_lock(g, 1);
	g->shmcmd->shmid = vm_window->shminfo.shmid;
	XShmDetach(g->display, &vm_window->shminfo);
	XDestroyImage(vm_window->image);
	XSync(g->display, False);
	inter_appviewer_lock(g, 0);
	vm_window->image = NULL;
	shmctl(vm_window->shminfo.shmid, IPC_RMID, 0);
}

/* handle VM message: MSG_MFNDUMP
 * Retrieve memory addresses connected with composition buffer of remote window
 */
static void handle_mfndump(Ghandles * g, struct windowdata *vm_window)
{
	char untrusted_shmcmd_data_from_remote[4096 * SHM_CMD_NUM_PAGES];
	struct shm_cmd *untrusted_shmcmd =
	    (struct shm_cmd *) untrusted_shmcmd_data_from_remote;
	unsigned num_mfn, off;
	static char dummybuf[100];

	if (vm_window->image)
		release_mapped_mfns(g, vm_window);
	read_data(g->vchan, untrusted_shmcmd_data_from_remote,
		  sizeof(struct shm_cmd));

	if (g->log_level > 1)
		fprintf(stderr, "MSG_MFNDUMP for 0x%x(0x%x): %dx%d, num_mfn 0x%x off 0x%x\n",
				(int) vm_window->local_winid, (int) vm_window->remote_winid,
				untrusted_shmcmd->width, untrusted_shmcmd->height,
				untrusted_shmcmd->num_mfn, untrusted_shmcmd->off);
	/* sanitize start */
	VERIFY(untrusted_shmcmd->num_mfn <= (unsigned)MAX_MFN_COUNT);
	num_mfn = untrusted_shmcmd->num_mfn;
	VERIFY((int) untrusted_shmcmd->width >= 0
	       && (int) untrusted_shmcmd->height >= 0);
	VERIFY((int) untrusted_shmcmd->width <= MAX_WINDOW_WIDTH
	       && (int) untrusted_shmcmd->height <= MAX_WINDOW_HEIGHT);
	VERIFY(untrusted_shmcmd->off < 4096);
	off = untrusted_shmcmd->off;
	/* unused for now: VERIFY(untrusted_shmcmd->bpp == 24); */
	/* sanitize end */
	vm_window->image_width = untrusted_shmcmd->width;
	vm_window->image_height = untrusted_shmcmd->height;	/* sanitized above */
	read_data(g->vchan, (char *) untrusted_shmcmd->mfns,
		  SIZEOF_SHARED_MFN * num_mfn);
	if (g->invisible)
		return;
	vm_window->image =
	    XShmCreateImage(g->display,
			    DefaultVisual(g->display, g->screen), 24,
			    ZPixmap, NULL, &vm_window->shminfo,
			    vm_window->image_width,
			    vm_window->image_height);
	if (!vm_window->image) {
		perror("XShmCreateImage");
		exit(1);
	}
	/* the below sanity check must be AFTER XShmCreateImage, it uses vm_window->image */
	if (num_mfn * 4096 <
	    vm_window->image->bytes_per_line * vm_window->image->height +
	    off) {
		fprintf(stderr,
			"handle_mfndump for window 0x%x(remote 0x%x)"
			" got too small num_mfn= 0x%x\n",
			(int) vm_window->local_winid,
			(int) vm_window->remote_winid, num_mfn);
		exit(1);
	}
	// temporary shmid; see shmoverride/README
	vm_window->shminfo.shmid =
	    shmget(IPC_PRIVATE, 1, IPC_CREAT | 0700);
	if (vm_window->shminfo.shmid < 0) {
		perror("shmget");
		exit(1);
	}
	/* ensure that _every_ not sanitized field is overrided by some trusted
	 * value */
	untrusted_shmcmd->shmid = vm_window->shminfo.shmid;
	untrusted_shmcmd->domid = g->domid;
	inter_appviewer_lock(g, 1);
	memcpy(g->shmcmd, untrusted_shmcmd_data_from_remote,
           sizeof(struct shm_cmd) + SIZEOF_SHARED_MFN * num_mfn);
    if (SIZEOF_SHARED_MFN * num_mfn + sizeof (struct shm_cmd) < 4096 * SHM_CMD_NUM_PAGES) {
      memset((char*)g->shmcmd->mfns + SIZEOF_SHARED_MFN * num_mfn, 0,
             4096 * SHM_CMD_NUM_PAGES - (SIZEOF_SHARED_MFN * num_mfn + sizeof (struct shm_cmd)));
    }
	vm_window->shminfo.shmaddr = vm_window->image->data = dummybuf;
	vm_window->shminfo.readOnly = True;
	XSync(g->display, False);
	if (!XShmAttach(g->display, &vm_window->shminfo)) {
		fprintf(stderr,
			"XShmAttach failed for window 0x%x(remote 0x%x)\n",
			(int) vm_window->local_winid,
			(int) vm_window->remote_winid);
	}
	XSync(g->display, False);
	g->shmcmd->shmid = g->cmd_shmid;
	inter_appviewer_lock(g, 0);
}

/* VM message dispatcher */
static void handle_message(Ghandles * g)
{
	struct msg_hdr untrusted_hdr;
	uint32_t type;
	XID window = 0;
	struct genlist *l;
	struct windowdata *vm_window = NULL;

	read_struct(g->vchan, untrusted_hdr);
	VERIFY(untrusted_hdr.type > MSG_MIN
	       && untrusted_hdr.type < MSG_MAX);
	/* sanitized msg type */
	type = untrusted_hdr.type;
	if (type == MSG_CLIPBOARD_DATA) {
		/* window field has special meaning here */
		handle_clipboard_data(g, untrusted_hdr.window);
		return;
	}
	l = list_lookup(g->remote2local, untrusted_hdr.window);
	if (type == MSG_CREATE) {
		if (l) {
			fprintf(stderr,
				"CREATE for already existing window id 0x%x?\n",
				untrusted_hdr.window);
			exit(1);
		}
		window = untrusted_hdr.window;
	} else {
		if (!l) {
			fprintf(stderr,
				"msg 0x%x without CREATE for 0x%x\n",
				type, untrusted_hdr.window);
			exit(1);
		}
		vm_window = l->data;
		/* not needed as it is in vm_window struct
		   window = untrusted_hdr.window;
		 */
	}

	switch (type) {
	case MSG_CREATE:
		handle_create(g, window);
		break;
	case MSG_DESTROY:
		handle_destroy(g, l);
		break;
	case MSG_MAP:
		handle_map(g, vm_window);
		break;
	case MSG_UNMAP:
		handle_unmap(g, vm_window);
		break;
	case MSG_CONFIGURE:
		handle_configure_from_vm(g, vm_window);
		break;
	case MSG_MFNDUMP:
		handle_mfndump(g, vm_window);
		break;
	case MSG_SHMIMAGE:
		handle_shmimage(g, vm_window);
		break;
	case MSG_WMNAME:
		handle_wmname(g, vm_window);
		break;
	case MSG_DOCK:
		handle_dock(g, vm_window);
		break;
	case MSG_WINDOW_HINTS:
		handle_wmhints(g, vm_window);
		break;
	case MSG_WINDOW_FLAGS:
		handle_wmflags(g, vm_window);
		break;
	default:
		fprintf(stderr, "got unknown msg type %d\n", type);
		exit(1);
	}
}

/* signal handler - connected to SIGTERM */
static void dummy_signal_handler(int UNUSED(x))
{
	exit(0);
}

/* signal handler - connected to SIGHUP */
static void sighup_signal_handler(int UNUSED(x))
{
	ghandles.reload_requested = 1;
}

static void print_backtrace(void)
{
	void *array[100];
	size_t size;
	char **strings;
	size_t i;


	if (ghandles.log_level > 1) {
		size = backtrace(array, 100);
		strings = backtrace_symbols(array, size);
		fprintf(stderr, "Obtained %zd stack frames.\n", size);

		for (i = 0; i < size; i++)
			printf("%s\n", strings[i]);

		free(strings);
	}

}

/* release all windows mapped memory */
static void release_all_mapped_mfns(void)
{
	struct genlist *curr;
	if (ghandles.log_level > 1)
		fprintf(stderr, "release_all_mapped_mfns running\n");
	print_backtrace();
	for (curr = ghandles.wid2windowdata->next;
	     curr != ghandles.wid2windowdata; curr = curr->next) {
		struct windowdata *vm_window = curr->data;
		if (vm_window->image)
			/* use og ghandles directly, as no other way get it (atexec cannot
			 * pass argument) */
			release_mapped_mfns(&ghandles, vm_window);
	}
}

/* start pulseaudio Dom0 proxy */
static void exec_pacat(Ghandles * g)
{
	int i, fd, maxfiles;
	pid_t pid;
	char domid_txt[20];
	char logname[80];
	char old_logname[80];
	struct rlimit rl;
	struct stat stat_buf;
	snprintf(domid_txt, sizeof domid_txt, "%d", g->domid);
	snprintf(logname, sizeof logname, "/var/log/qubes/pacat.%s.log",
		 g->vmname);
	snprintf(old_logname, sizeof old_logname, "/var/log/qubes/pacat.%s.log.old",
		 g->vmname);
	if (stat(logname, &stat_buf) == 0) {
	   if (rename(logname, old_logname) < 0) {
		   perror("Old logfile rename");
	   }
	}
	switch (pid=fork()) {
	case -1:
		perror("fork pacat");
		exit(1);
	case 0:
		maxfiles = getdtablesize();
		if (maxfiles < 0) {
			if (getrlimit(RLIMIT_NOFILE, &rl) == 0)
				maxfiles = rl.rlim_cur;
			else
				maxfiles = 256;
		}
		for (i = 0; i < maxfiles; i++)
			close(i);
		fd = open("/dev/null", O_RDWR); /* stdin */
		dup2(fd, 1); /* stdout */
		umask(0007);
		fd = open(logname, O_WRONLY | O_CREAT | O_TRUNC, 0640); /* stderr */
		umask(0077);
		if (g->audio_low_latency) {
			execl("/usr/bin/pacat-simple-vchan", "pacat-simple-vchan",
					"-l", domid_txt, g->vmname, NULL);
		} else {
			execl("/usr/bin/pacat-simple-vchan", "pacat-simple-vchan",
					domid_txt, g->vmname, NULL);
		}
		perror("execl");
		_exit(1);
	default:
		g->pulseaudio_pid = pid;
	}
}

/* send configuration parameters of X server to VM */
static void send_xconf(Ghandles * g)
{
	struct msg_xconf xconf;
	XWindowAttributes attr;
	XGetWindowAttributes(g->display, g->root_win, &attr);
	if(!g->private_mode) {
		xconf.w = _VIRTUALX(attr.width);
		xconf.h = attr.height;
		xconf.depth = attr.depth;
	} else {
		xconf.w = g->remote_screen_width;
		xconf.h = g->remote_screen_height;
		xconf.depth = 24;
	}
	xconf.mem = xconf.w * xconf.h * 4 / 1024 + 1;
	write_struct(g->vchan, xconf);
}

/* receive from VM and compare protocol version
 * abort if mismatch */
static void get_protocol_version(Ghandles * g)
{
	uint32_t untrusted_version;
	char message[1024];
	uint32_t version_major, version_minor;
	read_struct(g->vchan, untrusted_version);
	version_major = untrusted_version >> 16;
	version_minor = untrusted_version & 0xffff;

	if (version_major == QUBES_GUID_PROTOCOL_VERSION_MAJOR &&
			version_minor <= QUBES_GUID_PROTOCOL_VERSION_MINOR)
		return;
	if (version_major < QUBES_GUID_PROTOCOL_VERSION_MAJOR)
		snprintf(message, sizeof message, "%s %s \""
				"The GUI agent that runs in the VM '%s' implements outdated protocol (%d:%d), and must be updated.\n\n"
				"To start and access the VM or template without GUI virtualization, use the following commands:\n"
				"qvm-start --no-guid vmname\n"
				"sudo xl console vmname\"",
				g->use_kdialog ? KDIALOG_PATH : ZENITY_PATH,
				g->use_kdialog ? "--sorry" : "--error --text ",
				g->vmname, version_major, version_minor);
	else
		snprintf(message, sizeof message, "%s %s \""
				"The Dom0 GUI daemon do not support protocol version %d:%d, requested by the VM '%s'.\n"
				"To update Dom0, use 'qubes-dom0-update' command or do it via qubes-manager\"",
				g->use_kdialog ? KDIALOG_PATH : ZENITY_PATH,
				g->use_kdialog ? "--sorry" : "--error --text ",
				version_major, version_minor, g->vmname);
	system(message);
	exit(1);
}

/* wait until child process connects to VM */
static void wait_for_connection_in_parent(int *pipe_notify)
{
	// inside the parent process
	// wait for daemon to get connection with AppVM
	struct pollfd pipe_pollfd;
	int tries, ret;

	if (ghandles.log_level > 0)
		fprintf(stderr, "Connecting to VM's GUI agent: ");
	close(pipe_notify[1]);	// close the writing end
	pipe_pollfd.fd = pipe_notify[0];
	pipe_pollfd.events = POLLIN;

	for (tries = 0;; tries++) {
		if (ghandles.log_level > 0)
			fprintf(stderr, ".");
		ret = poll(&pipe_pollfd, 1, 1000);
		if (ret < 0) {
			perror("poll");
			exit(1);
		}
		if (ret > 0) {
			if (pipe_pollfd.revents & POLLIN)
				break;
			if (ghandles.log_level > 0)
				fprintf(stderr, "exiting\n");
			exit(1);
		}
		if (tries >= ghandles.startup_timeout) {
			if (ghandles.startup_timeout > 0) {
				if (ghandles.log_level > 0)
					fprintf(stderr, "timeout\n");
				exit(1);
			} else {
				if (ghandles.log_level > 0)
					fprintf(stderr, "in the background\n");
			}
			exit(0);
		}

	}
	if (ghandles.log_level > 0)
		fprintf(stderr, "connected\n");
	exit(0);
}

static void usage(void)
{
	fprintf(stderr,
		"usage: qubes-guid -d domain_id -N domain_name [-t target_domid] [-c color] [-l label_index] [-i icon name, no suffix, or icon.png path] [-v] [-q] [-a] [-f] [-K pid]\n");
	fprintf(stderr, "       -v  increase log verbosity\n");
	fprintf(stderr, "       -q  decrease log verbosity\n");
	fprintf(stderr, "       -Q  force usage of Qrexec for clipboard operations\n");
	fprintf(stderr, "       -n  do not wait for agent connection\n");
	fprintf(stderr, "       -a  low-latency audio mode\n");
	fprintf(stderr, "       -f  do not fork into background\n");
	fprintf(stderr, "       -I  run in \"invisible\" mode - do not show any VM window\n");
	fprintf(stderr, "       -K  when established connection to VM agent, send SIGUSR1 to given pid (ignored when -f set)\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Log levels:\n");
	fprintf(stderr, " 0 - only errors\n");
	fprintf(stderr, " 1 - some basic messages (default)\n");
	fprintf(stderr, " 2 - debug\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "target_domid should be used in case domain_id is stubdom\n");
}

static void parse_cmdline_vmname(Ghandles * g, int argc, char **argv)
{
	int opt;
	optind = 1;

	while ((opt = getopt(argc, argv, "d:t:N:c:l:i:K:vqQnafI")) != -1) {
		if (opt == 'N')
			strncpy(g->vmname, optarg, sizeof(g->vmname));
	}
}

static void parse_cmdline(Ghandles * g, int argc, char **argv)
{
	int opt;
	/* defaults */
	g->log_level = 1;
	g->qrexec_clipboard = 0;
	g->nofork = 0;
	g->kill_on_connect = 0;

	optind = 1;

	while ((opt = getopt(argc, argv, "d:t:N:c:l:i:K:vqQnafI")) != -1) {
		switch (opt) {
		case 'a':
			g->audio_low_latency = 1;
			break;
		case 'd':
			g->domid = atoi(optarg);
			break;
		case 't':
			g->target_domid = atoi(optarg);
			break;
		case 'N':
			/* already handled in parse_cmdline_vmname */
			break;
		case 'c':
			g->cmdline_color = optarg;
			break;
		case 'l':
			g->label_index = strtoul(optarg, NULL, 0);
			break;
		case 'i':
			g->cmdline_icon = optarg;
			break;
		case 'q':
			if (g->log_level > 0)
				g->log_level--;
			break;
		case 'v':
			g->log_level++;
			break;
		case 'Q':
			g->qrexec_clipboard = 1;
			break;
		case 'n':
			g->startup_timeout = 0;
			break;
		case 'f':
			g->nofork = 1;
			break;
		case 'I':
			g->invisible = 1;
			break;
		case 'K':
			g->kill_on_connect = strtoul(optarg, NULL, 0);
			break;
		default:
			usage();
			exit(1);
		}
	}
	if (g->domid<=0) {
		fprintf(stderr, "domid<=0?");
		exit(1);
	}

	if (g->nofork) {
		/* -K (kill on connect) doesn't make much sense in case of foreground
		 * process, clear that flag. This will prevent killing innocent process
		 * in case of guid restart (-f is appended there).
		 */
		g->kill_on_connect = 0;
	}

	/* default target_domid to domid */
	if (!g->target_domid)
		g->target_domid = g->domid;
	if (!g->vmname) {
		fprintf(stderr, "domain name?");
		exit(1);
	}
}

static void load_default_config_values(Ghandles * g)
{
	g->pointer_distance = 128;
	g->allow_utf8_titles = 0;
	g->copy_seq_mask = ControlMask | ShiftMask;
	g->copy_seq_key = XK_c;
	g->paste_seq_mask = ControlMask | ShiftMask;
	g->paste_seq_key = XK_v;
	g->allow_fullscreen = 0;
	g->startup_timeout = 45;
	g->private_mode = 1;
}

// parse string describing key sequence like Ctrl-Alt-c
static void parse_key_sequence(const char *seq, int *mask, KeySym * key)
{
	const char *seqp = seq;
	int found_modifier;

	// ignore null string
	if (seq == NULL)
		return;
	*mask = 0;
	do {
		found_modifier = 1;
		if (strncasecmp(seqp, "Ctrl-", 5) == 0) {
			*mask |= ControlMask;
			seqp += 5;
		} else if (strncasecmp(seqp, "Mod1-", 5) == 0) {
			*mask |= Mod1Mask;
			seqp += 5;
		} else if (strncasecmp(seqp, "Mod3-", 5) == 0) {
			*mask |= Mod3Mask;
			seqp += 5;
		} else if (strncasecmp(seqp, "Mod4-", 5) == 0) {
			*mask |= Mod4Mask;
			seqp += 5;
			/* second name just for convenience */
		} else if (strncasecmp(seqp, "Alt-", 4) == 0) {
			*mask |= Mod1Mask;
			seqp += 4;
		} else if (strncasecmp(seqp, "Shift-", 6) == 0) {
			*mask |= ShiftMask;
			seqp += 6;
		} else
			found_modifier = 0;
	} while (found_modifier);

	*key = XStringToKeysym(seqp);
	if (*key == NoSymbol) {
		fprintf(stderr,
			"Warning: key sequence (%s) is invalid (will be disabled)\n",
			seq);
	}
}

static void parse_vm_config(Ghandles * g, config_setting_t * group)
{
	config_setting_t *setting;

	if ((setting =
	     config_setting_get_member(group, "secure_copy_sequence"))) {
		parse_key_sequence(config_setting_get_string(setting),
				   &g->copy_seq_mask, &g->copy_seq_key);
	}
	if ((setting =
	     config_setting_get_member(group, "secure_paste_sequence"))) {
		parse_key_sequence(config_setting_get_string(setting),
				   &g->paste_seq_mask, &g->paste_seq_key);
	}

	if ((setting =
	     config_setting_get_member(group, "allow_utf8_titles"))) {
		g->allow_utf8_titles = config_setting_get_bool(setting);
	}

	if ((setting =
	     config_setting_get_member(group, "log_level"))) {
		g->log_level = config_setting_get_int(setting);
	}

	if ((setting =
	     config_setting_get_member(group, "allow_fullscreen"))) {
		g->allow_fullscreen = config_setting_get_bool(setting);
	}

	if ((setting =
	     config_setting_get_member(group, "audio_low_latency"))) {
		g->audio_low_latency = config_setting_get_bool(setting);
	}
}

static void parse_config(Ghandles * g)
{
	config_t config;
	config_setting_t *setting;
	char buf[128];

	config_init(&config);
#if (((LIBCONFIG_VER_MAJOR == 1) && (LIBCONFIG_VER_MINOR > 5)) \
		|| (LIBCONFIG_VER_MAJOR > 1))
	config_set_include_dir(&config, GUID_CONFIG_DIR);
#endif
	if (config_read_file(&config, GUID_CONFIG_FILE) == CONFIG_FALSE) {
#if (((LIBCONFIG_VER_MAJOR == 1) && (LIBCONFIG_VER_MINOR >= 4)) \
		|| (LIBCONFIG_VER_MAJOR > 1))
		if (config_error_type(&config) == CONFIG_ERR_FILE_IO) {
#else
		if (strcmp(config_error_text(&config), "file I/O error") ==
		    0) {
#endif
			fprintf(stderr,
				"Warning: cannot read config file (%s): %s\n",
				GUID_CONFIG_FILE,
				config_error_text(&config));
		} else {
			fprintf(stderr,
				"Critical: error reading config (%s:%d): %s\n",
#if (((LIBCONFIG_VER_MAJOR == 1) && (LIBCONFIG_VER_MINOR >= 4)) \
		|| (LIBCONFIG_VER_MAJOR > 1))
				config_error_file(&config),
#else
				GUID_CONFIG_FILE,
#endif
				config_error_line(&config),
				config_error_text(&config));
			exit(1);
		}
	}
	// first load global settings
	if ((setting = config_lookup(&config, "global"))) {
		parse_vm_config(g, setting);
	}
	// then try to load per-VM settings
	snprintf(buf, sizeof(buf), "VM/%s", g->vmname);
	if ((setting = config_lookup(&config, buf))) {
		parse_vm_config(g, setting);
	}
}

/* helper to get a file flag path */
static char *guid_fs_flag(const char *type, int domid)
{
	static char buf[256];
	snprintf(buf, sizeof(buf), "/var/run/qubes/guid-%s.%d",
		 type, domid);
	return buf;
}

static int guid_boot_lock = -1;

/* create guid_running file when connected to VM */
static void set_alive_flag(int domid)
{
	char pid_buf[10];
	int fd = open(guid_fs_flag("running", domid),
		      O_WRONLY | O_CREAT | O_NOFOLLOW, 0600);
	snprintf(pid_buf, sizeof(pid_buf), "%d\n", getpid());
	write(fd, pid_buf, strlen(pid_buf));
	close(fd);
	unlink(guid_fs_flag("booting", domid));
	close(guid_boot_lock);

}

/* remove guid_running file at exit */
static void unset_alive_flag(void)
{
	unlink(guid_fs_flag("running", ghandles.domid));
}

static void kill_pacat(void) {
	pid_t pid = ghandles.pulseaudio_pid;
	if (pid > 0) {
		kill(pid, SIGTERM);
	}
}

static void wait_for_pacat(int UNUSED(signum)) {
	int status;

	if (ghandles.pulseaudio_pid > 0) {
		if (waitpid(ghandles.pulseaudio_pid, &status, WNOHANG) > 0) {
			ghandles.pulseaudio_pid = -1;
			if (status != 0 && ghandles.log_level > 0) {
				fprintf(stderr, "pacat exited with %d status\n", status);
			}
		}
	}
}

void vchan_close()
{
	libvchan_close(ghandles.vchan);
}

static void get_boot_lock(int domid)
{
	struct stat st;
	int fd = open(guid_fs_flag("booting", domid),
		      O_WRONLY | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
	if (fd < 0) {
		perror("cannot get boot lock ???\n");
		exit(1);
	}
	if (flock(fd, LOCK_EX) < 0) {
		unlink(guid_fs_flag("booting", domid));
		perror("lock");
		exit(1);
	}
	if (!stat(guid_fs_flag("running", domid), &st)) {
		/* guid running, nothing to do */
		unlink(guid_fs_flag("booting", domid));
		exit(0);
	}
	guid_boot_lock = fd;
}

static void cleanup() {
	release_all_mapped_mfns();
	XCloseDisplay(ghandles.display);
	kill_pacat();
	wait_for_pacat(SIGCHLD);
	unset_alive_flag();
	close(ghandles.inter_appviewer_lock_fd);
}

static char** restart_argv;
void restart_guid() {
	cleanup();
	execv("/usr/bin/qubes-guid", restart_argv);
	perror("execv");
}

int main(int argc, char **argv)
{
	int xfd;
	FILE *f;
	int childpid;
	int pipe_notify[2];
	char dbg_log[256];
	char dbg_log_old[256];
	int logfd;
	char cmd_tmp[256];
	struct stat stat_buf;

	load_default_config_values(&ghandles);
	/* get the VM name to read the right section in config file */
	parse_cmdline_vmname(&ghandles, argc, argv);
	/* load config file */
	parse_config(&ghandles);
	/* parse cmdline, possibly overriding values from config */
	parse_cmdline(&ghandles, argc, argv);
	get_boot_lock(ghandles.domid);

	if (!ghandles.nofork) {
		// daemonize...
		if (pipe(pipe_notify) < 0) {
			perror("canot create pipe:");
			exit(1);
		}

		childpid = fork();
		if (childpid < 0) {
			fprintf(stderr, "Cannot fork :(\n");
			exit(1);
		} else if (childpid > 0) {
			wait_for_connection_in_parent(pipe_notify);
			exit(0);
		}
		close(pipe_notify[0]);
	}

	// inside the daemonized process...
	if (!ghandles.invisible) {
		f = fopen("/var/run/shm.id", "r");
		if (!f) {
			fprintf(stderr,
					"Missing /var/run/shm.id; run X with preloaded shmoverride\n");
			exit(1);
		}
		fscanf(f, "%d", &ghandles.cmd_shmid);
		fclose(f);
		ghandles.shmcmd = shmat(ghandles.cmd_shmid, NULL, 0);
		if (ghandles.shmcmd == (void *) (-1UL)) {
			fprintf(stderr,
					"Invalid or stale shm id 0x%x in /var/run/shm.id\n",
					ghandles.cmd_shmid);
			exit(1);
		}
	}

	/* prepare argv for possible restarts */
	if (ghandles.nofork) {
		/* "-f" option already given, use the same argv */
		restart_argv = argv;
	} else {
		/* append "-f" option */
		int i;

		restart_argv = malloc((argc+2) * sizeof(char*));
		for (i=0;i<argc;i++)
			restart_argv[i] = argv[i];
		restart_argv[argc] = strdup("-f");
		restart_argv[argc+1] = (char*)NULL;
	}

	if (!ghandles.nofork) {
		/* output redirection only when started as daemon, if "nofork" option
		 * is set as part of guid restart, output is already redirected */
		close(0);
		open("/dev/null", O_RDONLY);
		snprintf(dbg_log, sizeof(dbg_log),
				"/var/log/qubes/guid.%s.log", ghandles.vmname);
		snprintf(dbg_log_old, sizeof(dbg_log_old),
				"/var/log/qubes/guid.%s.log.old", ghandles.vmname);
		if (stat(dbg_log, &stat_buf) == 0) {
			if (rename(dbg_log, dbg_log_old) < 0) {
				perror("Rename old logfile");
			}
		}
		umask(0007);
		logfd = open(dbg_log, O_WRONLY | O_CREAT | O_TRUNC, 0640);
		umask(0077);
		if (logfd < 0) {
			fprintf(stderr,
					"Failed to open log file: %s\n", strerror (errno));
			exit(1);
		}
		dup2(logfd, 1);
		dup2(logfd, 2);
		if (logfd > 2)
			close(logfd);
	}

	chdir("/var/run/qubes");
	errno = 0;
	if (!ghandles.nofork && setsid() < 0) {
		perror("setsid()");
		exit(1);
	}
	mkghandles(&ghandles);
	XSetErrorHandler(x11_error_handler);
	double_buffer_init();
	ghandles.vchan = libvchan_client_init(ghandles.domid, 6000);
	if (!ghandles.vchan) {
		fprintf(stderr, "Failed to connect to gui-agent\n");
		exit(1);
	}
	atexit(vchan_close);
	signal(SIGCHLD, wait_for_pacat);
	exec_pacat(&ghandles);
	atexit(kill_pacat);
	/* drop root privileges */
	if (setgid(getgid()) < 0) {
		perror("setgid()");
		exit(1);
	}
	if (setuid(getuid()) < 0) {
		perror("setuid()");
		exit(1);
	}
	set_alive_flag(ghandles.domid);
	atexit(unset_alive_flag);

	if (!ghandles.nofork) {
		write(pipe_notify[1], "Q", 1);	// let the parent know we connected sucessfully
		close (pipe_notify[1]);
	}

	signal(SIGTERM, dummy_signal_handler);
	signal(SIGHUP, sighup_signal_handler);
	atexit(release_all_mapped_mfns);

	if (ghandles.kill_on_connect) {
		kill(ghandles.kill_on_connect, SIGUSR1);
	}


	xfd = ConnectionNumber(ghandles.display);

	/* provide keyboard map before VM Xserver starts */

	/* cast return value to unsigned, so (unsigned)-1 > sizeof(cmd_tmp) */
	if ((unsigned)snprintf(cmd_tmp, sizeof(cmd_tmp), "/usr/bin/qubesdb-write -d %s "
		     "/qubes-keyboard \"`/usr/bin/setxkbmap -print`\"",
		     ghandles.vmname) < sizeof(cmd_tmp)) {
		/* intentionally ignore return value - don't fail gui-daemon if only
		 * keyboard layout fails */
		system(cmd_tmp);
	}
	vchan_register_at_eof(restart_guid);

	XRRSelectInput(ghandles.display, ghandles.root_win, RRScreenChangeNotifyMask);

	get_protocol_version(&ghandles);
	send_xconf(&ghandles);

	update_monitor_layout(&ghandles);

	for (;;) {
		int select_fds[2] = { xfd };
		fd_set retset;
		int busy;
		if (ghandles.reload_requested) {
			fprintf(stderr, "got request to reload X server parameters, now done automatically\n");
			ghandles.reload_requested = 0;
		}
		do {
			busy = 0;
			if (XPending(ghandles.display)) {
				process_xevent(&ghandles);
				busy = 1;
			}
			if (libvchan_data_ready(ghandles.vchan)) {
				handle_message(&ghandles);
				busy = 1;
			}
		} while (busy);
		wait_for_vchan_or_argfd(ghandles.vchan, 1, select_fds, &retset);
	}
	return 0;
}

// vim:ts=4:sw=4:noet:
