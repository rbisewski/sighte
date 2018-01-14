#
# Production project
#
project('sighte','c',
    default_options : ['c_std=c99'])

#
# Version
#
version_raw = run_command('date','+%y.%m')

# If unable to grab the version, default to N/A
if version_raw.returncode() != 0
    version_raw = 'n/a'
endif
version = '-D VERSION="' + version_raw.stdout().strip() + '"'

#
# Variables to handle debug modes
#
debug_mode_off = 0
debug_mode_on  = 1
debug_mode = '-D DEBUG_MODE=0'

#
# Variables to handle verbose debug output messages modes
#
verbose_mode_off = 0
verbose_mode_on  = 1
verbose_mode = '-D VERBOSE_MODE=0'

#
# C flags
#
flags = ['-fpic',
         '-Wall',
         '-Wextra',
         '-Wpedantic',
         '-Wno-missing-braces',
         '-Wformat=2',
         '-Wformat-signedness',
         '-Wnull-dereference',
         '-Winit-self',
         '-Wmissing-include-dirs',
         '-Wshift-overflow=2',
         '-Wswitch-default',
         '-Wswitch-enum',
         '-Wunused-const-variable=2',
         '-Wuninitialized',
         '-Wunknown-pragmas',
         '-Wstrict-overflow=5',
         '-Warray-bounds=2',
         '-Wduplicated-cond',
         '-Wfloat-equal',
         '-Wundef',
         '-Wshadow',
         '-Wbad-function-cast',
         '-Wcast-qual',
         '-Wcast-align',
         '-Wwrite-strings',
         '-Wconversion',
         '-Wjump-misses-init',
         '-Wlogical-op',
         '-Waggregate-return',
         '-Wcast-align',
         '-Wstrict-prototypes',
         '-Wold-style-definition',
         '-Wmissing-prototypes',
         '-Wmissing-declarations',
         '-Wpacked',
         '-Wredundant-decls',
         '-Wnested-externs',
         '-Winline',
         '-Winvalid-pch',
         '-Wstack-protector',
         '-D_DEFAULT_SOURCE',
         version,
         debug_mode,
         verbose_mode]

#
# Dependencies
#
atkdep       = dependency('atk')
cairodep     = dependency('cairo')
gdkdep       = dependency('gdk-3.0')
gdkpixbufdep = dependency('gdk-pixbuf-2.0')
gtkdep       = dependency('gtk+-3.0')
giounixdep   = dependency('gio-unix-2.0')
glibdep      = dependency('glib-2.0')
pangodep     = dependency('pango')
libsoupdep   = dependency('libsoup-2.4')
threaddep    = dependency('threads')
webkit2      = dependency('webkit2gtk-4.0')
x11dep       = dependency('x11')

#
# Executable
#
executable('sighte','sighte.c',
    c_args : flags,
    dependencies : [atkdep,
                   cairodep,
                   gdkdep,
                   gtkdep,
                   giounixdep,
                   glibdep,
                   pangodep,
                   libsoupdep,
                   threaddep,
                   webkit2])
