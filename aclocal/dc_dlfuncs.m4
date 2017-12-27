AC_DEFUN([DC_DLFUNCS], [
	dnl Check for dl headers and functions
	AC_CHECK_HEADERS(dlfcn.h)
	if test -n "${ac_cv_func_dlsym}"; then
		AC_CHECK_FUNC(dlsym, [
			AC_DEFINE([HAVE_DLSYM], [1], [Have dlsym()])
		])
	else
		SAVE_LIBS="${LIBS}"
		for addlibs in '' '-ldl'; do
			LIBS="${SAVE_LIBS} ${addlibs}"
			unset ac_cv_func_dlsym
			AC_CHECK_FUNC(dlsym, [
				AC_DEFINE([HAVE_DLSYM], [1], [Have dlsym()])
				SAVE_LIBS="${LIBS}"
				break
			])
		done
		LIBS="${SAVE_LIBS}"
	fi
])
