NDK_BUILD:=/workspace/android-ndk/android-ndk-r10e/ndk-build

#CFLAGS += -Wextra -Wwrite-strings -Wno-unused-parameter -Wno-error=cpp -MD -Wshadow -Wno-error=deprecated-declarations --std=gnu99 -Werror
ifeq ($(CC),cc)
CC=${CROSS_COMPILE}gcc
endif

#linux: clean
#	${CC} -g -Wall -s ${CFLAGS} firehose_protocol.c meig_firehose.c  sahara_protocol.c usb_linux.c stream_download_protocol.c md5.c usb2tcp.c -o Meig_firehose -lpthread -ldl

debug: clean
	${CC} -Wall -g -DFH_DEBUG -s firehose_protocol.c  getdevinfo.c meig_firehose.c  sahara_protocol.c usb_linux.c stream_download_protocol.c md5.c usb2tcp.c -o Meig_firehose -lpthread -ldl
	
#android: clean
#	$(NDK_BUILD) V=0 APP_BUILD_SCRIPT=Android.mk NDK_PROJECT_PATH=`pwd` NDK_DEBUG=0 APP_ABI='armeabi-v7a,arm64-v8a'
#	rm -rf obj
#	mv libs android

clean:
	rm -rf Meig_firehose obj libs android usb2tcp *~
