include $(APPDIR)/Make.defs

PROGNAME  = orting
PRIORITY  = $(CONFIG_TESTING_ORTIMG_PRIORITY)
STACKSIZE = $(CONFIG_TESTING_ORTIMG_STACKSIZE)
MODULE    = $(CONFIG_TESTING_ORTIMG)
MAINSRC   = ortimg_main.c
CSRCS     = ort_json.c ort_http.c ort_sha256.c

include $(APPDIR)/Application.mk
