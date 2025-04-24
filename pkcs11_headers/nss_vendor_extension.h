#include "3.1/pkcs11.h"

#define CKK_ML_KEM 0xCE534380 /* Custom key type for ML-based KEM */
#define CKM_ML_KEM_KEYGEN 0xCE534380 /* Custom mechanism for ML-based KEM */
#define CKM_ML_KEM 0xCE534381 /* Custom mechanism for ML-based KEM */
#define NSSCK_VENDOR_NSS 0x4E534350 /* NSCP */
#define CKM_NSS (CKM_VENDOR_DEFINED | NSSCK_VENDOR_NSS)
#define CKM_NSS_KYBER (CKM_NSS + 46)
#define CKM_NSS_ML_KEM (CKM_NSS + 49)
#define CKP_NSS (CKM_VENDOR_DEFINED | NSSCK_VENDOR_NSS)
#define CKP_NSS_ML_KEM_768 (CKP_NSS + 2)
#define KYBER768_CIPHERTEXT_BYTES 1088U


typedef CK_ULONG CK_NSS_KEM_PARAMETER_SET_TYPE;


/* KEM interface. This may move to the normal PKCS #11 table in the future. For
 * now it's called "Vendor NSS KEM Interface" */
typedef CK_RV (*CK_NSS_Encapsulate)(CK_SESSION_HANDLE hSession,
                                    CK_MECHANISM_PTR pMechanism,
                                    CK_OBJECT_HANDLE hPublicKey,
                                    CK_ATTRIBUTE_PTR pTemplate,
                                    CK_ULONG ulAttributeCount,
                                    CK_OBJECT_HANDLE_PTR phKey,
                                    CK_BYTE_PTR pCiphertext,
                                    CK_ULONG_PTR pulCiphertextLen);

typedef CK_RV (*CK_NSS_Decapsulate)(CK_SESSION_HANDLE hSession,
                                    CK_MECHANISM_PTR pMechanism,
                                    CK_OBJECT_HANDLE hPrivateKey,
                                    CK_BYTE_PTR pCiphertext,
                                    CK_ULONG ulCiphertextLen,
                                    CK_ATTRIBUTE_PTR pTemplate,
                                    CK_ULONG ulAttributeCount,
                                    CK_OBJECT_HANDLE_PTR phKey);

typedef struct CK_NSS_KEM_FUNCTIONS {
    CK_VERSION version;
    CK_NSS_Encapsulate C_Encapsulate;
    CK_NSS_Decapsulate C_Decapsulate;
} CK_NSS_KEM_FUNCTIONS;