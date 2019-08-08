#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

#include <stdio.h>

/*
 * Create minimal PKCS#11 module interface needed to wrap
 */
#define CK_DEFINE_FUNCTION(type, func) type func

#define CKR_GENERAL_ERROR 0x00000005
#define CKR_OK            0x00000000

typedef void (*CK_CREATEMUTEX)();
typedef void (*CK_DESTROYMUTEX)();
typedef void (*CK_LOCKMUTEX)();
typedef void (*CK_UNLOCKMUTEX)();
typedef unsigned long CK_FLAGS;
typedef unsigned long CK_RV;
typedef void * CK_VOID_PTR;

typedef struct CK_C_INITIALIZE_ARGS {
	CK_CREATEMUTEX CreateMutex;
	CK_DESTROYMUTEX DestroyMutex;
	CK_LOCKMUTEX LockMutex;
	CK_UNLOCKMUTEX UnlockMutex;
	CK_FLAGS flags;
	CK_VOID_PTR pReserved;
} CK_C_INITIALIZE_ARGS;

typedef struct {
	unsigned char major;
	unsigned char minor;
} CK_VERSION;

typedef struct {
	CK_VERSION version;
	CK_RV (*C_Initialize)(CK_VOID_PTR);
	CK_RV (*C_Finalize)(CK_VOID_PTR);
} CK_FUNCTION_LIST;

typedef CK_FUNCTION_LIST* CK_FUNCTION_LIST_PTR;
typedef CK_FUNCTION_LIST** CK_FUNCTION_LIST_PTR_PTR;

/*
 * This is the size of the full PKCS#11 function list structure
 * (CK_FUNCTION_LIST).  We only actually care about wrapping the
 * initialization function, so we have to compute the full size
 *
 * Size is sizeOf(ourFunctionListStruct) + (numberOfFunctions-2 * functionPointerSize)
 */
#define SIZE_OF_PKCS11_FUNCTION_LIST (sizeof(CK_FUNCTION_LIST) + (67 * sizeof(void *)))

/*
 * Real C_Initialize() function for this module
 */
static CK_RV (*Real_C_Initialize)(CK_VOID_PTR) = NULL;

static CK_DEFINE_FUNCTION(CK_RV, Proxy_C_Initialize)(CK_VOID_PTR pInitArgs) {
	char nssConfig[1024];
	char *nssDBDir = NULL;
	CK_C_INITIALIZE_ARGS *InitArgs = NULL;

	InitArgs = pInitArgs;

	if (InitArgs == NULL) {
		InitArgs = malloc(sizeof(*InitArgs));

		InitArgs->CreateMutex = NULL;
		InitArgs->DestroyMutex = NULL;
		InitArgs->LockMutex = NULL;
		InitArgs->UnlockMutex = NULL;
		InitArgs->flags = 0;
		InitArgs->pReserved = NULL;
	}

	if (InitArgs->pReserved == NULL) {
		nssDBDir = getenv("SOFTOKN3_NSS_DIR");

		if (nssDBDir) {
			snprintf(nssConfig, sizeof(nssConfig),
			         "configdir='%s' certPrefix='' keyPrefix='' secmod='secmod.db' flags=readOnly",
				 nssDBDir
			);

			InitArgs->pReserved = (void *) nssConfig;
		}
	}

	if (Real_C_Initialize == NULL) {
		return(CKR_GENERAL_ERROR);
	}

	return(Real_C_Initialize(InitArgs));
}

CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR ppFunctionList) {
	CK_RV (*Real_C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR);
	CK_FUNCTION_LIST_PTR copyFunctionList;
	void *handle;
	CK_RV retval;
	char *module;

	module = getenv("SOFTOKN3_MODULE");
	if (!module) {
		module = "/usr/lib64/libsoftokn3.so";
	}

	/* handle = dlmopen(LM_ID_NEWLM, module, RTLD_NOW | RTLD_LOCAL); */
	handle = dlopen(module, RTLD_NOW | RTLD_LOCAL);
	if (handle == NULL) {
		fprintf(stderr, "Unable to open \"%s\": %s\n", module, dlerror());

		return(CKR_GENERAL_ERROR);
	}

	Real_C_GetFunctionList = dlsym(handle, "C_GetFunctionList");

	if (Real_C_GetFunctionList == NULL) {
		return(CKR_GENERAL_ERROR);
	}

	retval = Real_C_GetFunctionList(ppFunctionList);

	if (retval != CKR_OK) {
		return(retval);
	}

        copyFunctionList = malloc(SIZE_OF_PKCS11_FUNCTION_LIST);
        memcpy(copyFunctionList, *ppFunctionList, SIZE_OF_PKCS11_FUNCTION_LIST);
        *ppFunctionList = copyFunctionList;

	Real_C_Initialize = (*ppFunctionList)->C_Initialize;
	(*ppFunctionList)->C_Initialize = Proxy_C_Initialize;

	return(retval);
}
