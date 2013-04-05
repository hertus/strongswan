
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/libhydra \
	-I$(top_srcdir)/src/libcharon

AM_CFLAGS = -rdynamic

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-gspm-pace.la
else
plugin_LTLIBRARIES = libstrongswan-gspm-pace.la
endif

libstrongswan_gspm_pace_la_SOURCES = gspm_pace_plugin.h gspm_pace_plugin.c \
	gspm_pace_listener.c gspm_pace_listener.h

libstrongswan_gspm_pace_la_LDFLAGS = -module -avoid-version