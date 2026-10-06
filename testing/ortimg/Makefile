include $(APPDIR)/Make.defs

PROGNAME  = orting
PRIORITY  = $(CONFIG_TESTING_ORTIMG_PRIORITY)
STACKSIZE = $(CONFIG_TESTING_ORTIMG_STACKSIZE)
MODULE    = $(CONFIG_TESTING_ORTIMG)
MAINSRC   = ortimg_main.c
CSRCS     = ort_json.c ort_http.c ort_sha256.c ort_tar.c

# ort_tar.c 的 gzip 支持经 zlib（apps/system/zlib，见 Kconfig select）
CFLAGS   += ${INCDIR_PREFIX}$(APPDIR)/system/zlib/zlib

include $(APPDIR)/Application.mk
