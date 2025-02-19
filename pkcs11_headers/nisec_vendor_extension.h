#include "3.1/pkcs11.h"

#define NISEC_VENDOR_NSS 0x4E534543 /* NSEC */

#define CKM_NISEC (CKM_VENDOR_DEFINED | NISEC_VENDOR_NSS)
#define CKP_NISEC (CKP_VENDOR_DEFINED | NISEC_VENDOR_NSS)
#define CKK_NISEC (CKK_VENDOR_DEFINED | NISEC_VENDOR_NSS)


#define CKK_ML_DSA (CKK_NISEC + 1) /* Custom key type for ML-based DSA */
#define CKM_ML_DSA_KEYGEN (CKM_NISEC + 2) /* Custom mechanism for ML-based DSA */
#define CKM_ML_DSA (CKM_NISEC + 3) /* Custom mechanism for ML-based DSA */

