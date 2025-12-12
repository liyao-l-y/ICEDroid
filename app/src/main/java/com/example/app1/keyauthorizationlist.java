package com.example.app1;

import static com.google.common.base.Functions.forMap;
import static com.google.common.collect.Collections2.transform;

import android.security.keystore.KeyProperties;
import android.util.Log;

import com.google.common.base.Joiner;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Lists;
import com.google.common.io.BaseEncoding;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateParsingException;
import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.Set;

public class keyauthorizationlist {
    //------------------------------------字段---------------------------------------
    private Set<Integer> purposes;
    private Integer algorithm;
    private Integer keySize;
    private Set<Integer> digests;
    private Set<Integer> paddingModes;
    private Integer ecCurve;
    private Long rsaPublicExponent;
    private Set<Integer> mgfDigests;
    private Boolean rollbackResistance;
    private Boolean earlyBootOnly;
    private Date activeDateTime;
    private Date originationExpireDateTime;
    private Date usageExpireDateTime;
    private Integer usageCountLimit;
    private Boolean noAuthRequired;
    private Integer userAuthType;
    private Integer authTimeout;
    private Boolean allowWhileOnBody;
    private Boolean trustedUserPresenceReq;
    private Boolean trustedConfirmationReq;
    private Boolean unlockedDeviceReq;
    private Boolean allApplications;
    private String applicationId;
    private Date creationDateTime;
    private Integer origin;
    private Boolean rollbackResistant;
    private String rootOfTrust;
    private Integer osVersion;
    private Integer osPatchLevel;
    private String attestationApplicationId;
    private String brand;
    private String device;
    private String product;
    private String serialNumber;
    private String imei;
    private String meid;
    private String manufacturer;
    private String model;
    private Integer vendorPatchLevel;
    private Integer bootPatchLevel;
    private Boolean deviceUniqueAttestation;
    private Boolean identityCredentialKey;
    private String secondImei;
    //------------------------------------------------AuthorizationList------------------------------------------------------
    public String AuthorizationList(ASN1Sequence seq) throws CertificateParsingException {
        final int SW_ENFORCED_INDEX = 6;
        final int TEE_ENFORCED_INDEX = 7;
        setAuthorizationList(seq.getObjectAt(SW_ENFORCED_INDEX));
        setAuthorizationList(seq.getObjectAt(TEE_ENFORCED_INDEX));
        return authorizationListToString();
    }

    public boolean isdevicelocked;

    private void setAuthorizationList(ASN1Encodable asn1Encodable) throws CertificateParsingException {
        if (!(asn1Encodable instanceof ASN1Sequence sequence)) {
            throw new CertificateParsingException("Expected sequence for authorization list, found " + asn1Encodable.getClass().getName());
        }
        for (var entry : sequence) {
            if (!(entry instanceof ASN1TaggedObject taggedObject)) {
                throw new CertificateParsingException(
                        "Expected tagged object, found " + entry.getClass().getName());
            }
            int tag = taggedObject.getTagNo();
            var value = taggedObject.getBaseObject().toASN1Primitive();
            Log.d("AuthorizationList", "Parsing tag: [" + tag + "], value: [" + value + "]");
            //-------------------------------------mask-----------------------------------------
            int KEYMASTER_TAG_TYPE_MASK = 0x0FFFFFFF;
            //-------------------------------------classes--------------------------------------
            int KM_ENUM = 1 << 28;
            int KM_ENUM_REP = 2 << 28;
            int KM_UINT = 3 << 28;
            int KM_ULONG = 5 << 28;
            int KM_BOOL = 7 << 28;
            int KM_DATE = 6 << 28;
            int KM_BYTES = 9 << 28;
            //-------------------------------------tags-----------------------------------------
            int KM_TAG_PURPOSE = KM_ENUM_REP | 1;
            int KM_TAG_ALGORITHM = KM_ENUM | 2;
            int KM_TAG_KEY_SIZE = KM_UINT | 3;
            int KM_TAG_DIGEST = KM_ENUM_REP | 5;
            int KM_TAG_PADDING = KM_ENUM_REP | 6;
            int KM_TAG_EC_CURVE = KM_ENUM | 10;
            int KM_TAG_RSA_PUBLIC_EXPONENT = KM_ULONG | 200;
            int KM_TAG_RSA_OAEP_MGF_DIGEST = KM_ENUM_REP | 203;
            int KM_TAG_ROLLBACK_RESISTANCE = KM_BOOL | 303;
            int KM_TAG_EARLY_BOOT_ONLY = KM_BOOL | 305;
            int KM_TAG_ACTIVE_DATETIME = KM_DATE | 400;
            int KM_TAG_ORIGINATION_EXPIRE_DATETIME = KM_DATE | 401;
            int KM_TAG_USAGE_EXPIRE_DATETIME = KM_DATE | 402;
            int KM_TAG_USAGE_COUNT_LIMIT = KM_UINT | 405;
            int KM_TAG_NO_AUTH_REQUIRED = KM_BOOL | 503;
            final int KM_TAG_USER_AUTH_TYPE = KM_ENUM | 504;
            final int KM_TAG_AUTH_TIMEOUT = KM_UINT | 505;
            final int KM_TAG_ALLOW_WHILE_ON_BODY = KM_BOOL | 506;
            final int KM_TAG_TRUSTED_USER_PRESENCE_REQUIRED = KM_BOOL | 507;
            final int KM_TAG_TRUSTED_CONFIRMATION_REQUIRED = KM_BOOL | 508;
            final int KM_TAG_UNLOCKED_DEVICE_REQUIRED = KM_BOOL | 509;
            final int KM_TAG_ALL_APPLICATIONS = KM_BOOL | 600;
            final int KM_TAG_APPLICATION_ID = KM_BYTES | 601;
            final int KM_TAG_CREATION_DATETIME = KM_DATE | 701;
            final int KM_TAG_ORIGIN = KM_ENUM | 702;
            final int KM_TAG_ROLLBACK_RESISTANT = KM_BOOL | 703;
            final int KM_TAG_ROOT_OF_TRUST = KM_BYTES | 704;
            final int KM_TAG_OS_VERSION = KM_UINT | 705;
            final int KM_TAG_OS_PATCHLEVEL = KM_UINT | 706;
            final int KM_TAG_ATTESTATION_APPLICATION_ID = KM_BYTES | 709;
            final int KM_TAG_ATTESTATION_ID_BRAND = KM_BYTES | 710;
            final int KM_TAG_ATTESTATION_ID_DEVICE = KM_BYTES | 711;
            final int KM_TAG_ATTESTATION_ID_PRODUCT = KM_BYTES | 712;
            final int KM_TAG_ATTESTATION_ID_SERIAL = KM_BYTES | 713;
            final int KM_TAG_ATTESTATION_ID_IMEI = KM_BYTES | 714;
            final int KM_TAG_ATTESTATION_ID_MEID = KM_BYTES | 715;
            final int KM_TAG_ATTESTATION_ID_MANUFACTURER = KM_BYTES | 716;
            final int KM_TAG_ATTESTATION_ID_MODEL = KM_BYTES | 717;
            final int KM_TAG_VENDOR_PATCHLEVEL = KM_UINT | 718;
            final int KM_TAG_BOOT_PATCHLEVEL = KM_UINT | 719;
            final int KM_TAG_DEVICE_UNIQUE_ATTESTATION = KM_BOOL | 720;
            final int KM_TAG_IDENTITY_CREDENTIAL_KEY = KM_BOOL | 721;
            final int KM_TAG_ATTESTATION_ID_SECOND_IMEI = KM_BYTES | 723;
            if (tag == (KM_TAG_PURPOSE & KEYMASTER_TAG_TYPE_MASK)) {
                purposes = getIntegersFromAsn1Set(value);
            } else if (tag == (KM_TAG_ALGORITHM & KEYMASTER_TAG_TYPE_MASK)) {
                algorithm = getIntegerFromAsn1(value);
            } else if (tag == (KM_TAG_KEY_SIZE & KEYMASTER_TAG_TYPE_MASK)) {
                keySize = getIntegerFromAsn1(value);
            } else if (tag == (KM_TAG_DIGEST & KEYMASTER_TAG_TYPE_MASK)) {
                digests = getIntegersFromAsn1Set(value);
            } else if (tag == (KM_TAG_PADDING & KEYMASTER_TAG_TYPE_MASK)) {
                paddingModes = getIntegersFromAsn1Set(value);
            } else if (tag == (KM_TAG_EC_CURVE & KEYMASTER_TAG_TYPE_MASK)) {
                ecCurve = getIntegerFromAsn1(value);
            } else if (tag == (KM_TAG_RSA_PUBLIC_EXPONENT & KEYMASTER_TAG_TYPE_MASK)) {
                rsaPublicExponent = getLongFromAsn1(value);
            } else if (tag == (KM_TAG_RSA_OAEP_MGF_DIGEST & KEYMASTER_TAG_TYPE_MASK)) {
                mgfDigests = getIntegersFromAsn1Set(value);
            } else if (tag == (KM_TAG_ROLLBACK_RESISTANCE & KEYMASTER_TAG_TYPE_MASK)) {
                rollbackResistance = true;
            } else if (tag == (KM_TAG_EARLY_BOOT_ONLY & KEYMASTER_TAG_TYPE_MASK)) {
                earlyBootOnly = true;
            } else if (tag == (KM_TAG_ACTIVE_DATETIME & KEYMASTER_TAG_TYPE_MASK)) {
                activeDateTime = getDateFromAsn1(value);
            } else if (tag == (KM_TAG_ORIGINATION_EXPIRE_DATETIME & KEYMASTER_TAG_TYPE_MASK)) {
                originationExpireDateTime = getDateFromAsn1(value);
            } else if (tag == (KM_TAG_USAGE_EXPIRE_DATETIME & KEYMASTER_TAG_TYPE_MASK)) {
                usageExpireDateTime = getDateFromAsn1(value);
            } else if (tag == (KM_TAG_USAGE_COUNT_LIMIT & KEYMASTER_TAG_TYPE_MASK)) {
                usageCountLimit = getIntegerFromAsn1(value);
            } else if (tag == (KM_TAG_NO_AUTH_REQUIRED & KEYMASTER_TAG_TYPE_MASK)) {
                noAuthRequired = true;
            } else if (tag == (KM_TAG_USER_AUTH_TYPE & KEYMASTER_TAG_TYPE_MASK)) {
                userAuthType = getIntegerFromAsn1(value);
            } else if (tag == (KM_TAG_AUTH_TIMEOUT & KEYMASTER_TAG_TYPE_MASK)) {
                authTimeout = getIntegerFromAsn1(value);
            } else if (tag == (KM_TAG_ALLOW_WHILE_ON_BODY & KEYMASTER_TAG_TYPE_MASK)) {
                allowWhileOnBody = true;
            } else if (tag == (KM_TAG_TRUSTED_USER_PRESENCE_REQUIRED & KEYMASTER_TAG_TYPE_MASK)) {
                trustedUserPresenceReq = true;
            } else if (tag == (KM_TAG_TRUSTED_CONFIRMATION_REQUIRED & KEYMASTER_TAG_TYPE_MASK)) {
                trustedConfirmationReq = true;
            } else if (tag == (KM_TAG_UNLOCKED_DEVICE_REQUIRED & KEYMASTER_TAG_TYPE_MASK)) {
                unlockedDeviceReq = true;
            } else if (tag == (KM_TAG_ALL_APPLICATIONS & KEYMASTER_TAG_TYPE_MASK)) {
                allApplications = true;
            } else if (tag == (KM_TAG_APPLICATION_ID & KEYMASTER_TAG_TYPE_MASK)) {
                applicationId = getStringFromAsn1OctetStreamAssumingUTF8(value);
            } else if (tag == (KM_TAG_CREATION_DATETIME & KEYMASTER_TAG_TYPE_MASK)) {
                creationDateTime = getDateFromAsn1(value);
            } else if (tag == (KM_TAG_ORIGIN & KEYMASTER_TAG_TYPE_MASK)) {
                origin = getIntegerFromAsn1(value);
            } else if (tag == (KM_TAG_ROLLBACK_RESISTANT & KEYMASTER_TAG_TYPE_MASK)) {
                rollbackResistant = true;
            } else if (tag == (KM_TAG_ROOT_OF_TRUST & KEYMASTER_TAG_TYPE_MASK)) {
                rootOfTrust = RootOfTrust(value);
            } else if (tag == (KM_TAG_OS_VERSION & KEYMASTER_TAG_TYPE_MASK)) {
                osVersion = getIntegerFromAsn1(value);
            } else if (tag == (KM_TAG_OS_PATCHLEVEL & KEYMASTER_TAG_TYPE_MASK)) {
                osPatchLevel = getIntegerFromAsn1(value);
            } else if (tag == (KM_TAG_ATTESTATION_APPLICATION_ID & KEYMASTER_TAG_TYPE_MASK)) {
                attestationApplicationId = AttestationApplicationId(getAsn1EncodableFromBytes(getByteArrayFromAsn1(value)));
            } else if (tag == (KM_TAG_ATTESTATION_ID_BRAND & KEYMASTER_TAG_TYPE_MASK)) {
                brand = getStringFromAsn1OctetStreamAssumingUTF8(value);
            } else if (tag == (KM_TAG_ATTESTATION_ID_DEVICE & KEYMASTER_TAG_TYPE_MASK)) {
                device = getStringFromAsn1OctetStreamAssumingUTF8(value);
            } else if (tag == (KM_TAG_ATTESTATION_ID_PRODUCT & KEYMASTER_TAG_TYPE_MASK)) {
                product = getStringFromAsn1OctetStreamAssumingUTF8(value);
            } else if (tag == (KM_TAG_ATTESTATION_ID_SERIAL & KEYMASTER_TAG_TYPE_MASK)) {
                serialNumber = getStringFromAsn1OctetStreamAssumingUTF8(value);
            } else if (tag == (KM_TAG_ATTESTATION_ID_IMEI & KEYMASTER_TAG_TYPE_MASK)) {
                imei = getStringFromAsn1OctetStreamAssumingUTF8(value);
            } else if (tag == (KM_TAG_ATTESTATION_ID_MEID & KEYMASTER_TAG_TYPE_MASK)) {
                meid = getStringFromAsn1OctetStreamAssumingUTF8(value);
            } else if (tag == (KM_TAG_ATTESTATION_ID_MANUFACTURER & KEYMASTER_TAG_TYPE_MASK)) {
                manufacturer = getStringFromAsn1OctetStreamAssumingUTF8(value);
            } else if (tag == (KM_TAG_ATTESTATION_ID_MODEL & KEYMASTER_TAG_TYPE_MASK)) {
                model = getStringFromAsn1OctetStreamAssumingUTF8(value);
            } else if (tag == (KM_TAG_VENDOR_PATCHLEVEL & KEYMASTER_TAG_TYPE_MASK)) {
                vendorPatchLevel = getIntegerFromAsn1(value);
            } else if (tag == (KM_TAG_BOOT_PATCHLEVEL & KEYMASTER_TAG_TYPE_MASK)) {
                bootPatchLevel = getIntegerFromAsn1(value);
            } else if (tag == (KM_TAG_DEVICE_UNIQUE_ATTESTATION & KEYMASTER_TAG_TYPE_MASK)) {
                deviceUniqueAttestation = true;
            } else if (tag == (KM_TAG_IDENTITY_CREDENTIAL_KEY & KEYMASTER_TAG_TYPE_MASK)) {
                identityCredentialKey = true;
            } else if (tag == (KM_TAG_ATTESTATION_ID_SECOND_IMEI & KEYMASTER_TAG_TYPE_MASK)) {
                secondImei = getStringFromAsn1OctetStreamAssumingUTF8(value);
            } else {
                System.out.println("Unknown tag:" + tag);
            }
        }
    }
    private String authorizationListToString(){
        StringBuilder s = new StringBuilder("AuthorizationList");
        if (purposes != null && !purposes.isEmpty()) {
            s.append("\nPurposes: ").append(transform(purposes, forMap(purposeMap, "Unknown")));
        }
        if (algorithm != null) {
            s.append("\nAlgorithm: ").append(algorithmToString(algorithm));
        }
        if (keySize != null) {
            s.append("\nKeySize: ").append(keySize);
        }
        if (digests != null && !digests.isEmpty()) {
            s.append("\nDigests: ").append(transform(digests, forMap(digestMap, "Unknown")));
        }
        if (paddingModes != null && !paddingModes.isEmpty()) {
            s.append("\nPadding modes: ").append(transform(paddingModes, forMap(paddingMap, "Unknown")));
        }
        if (ecCurve != null) {
            s.append("\nEC Curve: ").append(ecCurveToString(ecCurve));
        }
        if (rsaPublicExponent != null) {
            s.append("\nRSA exponent: ").append(rsaPublicExponent);
        }
        if (mgfDigests != null && !mgfDigests.isEmpty()) {
            s.append("\nRsa Oaep Mgf Digest: ").append(transform(digests, forMap(digestMap, "Unknown")));
        }
        if (rollbackResistance != null) {
            s.append("\nRollback resistance");
        }
        if (earlyBootOnly != null) {
            s.append("\nEarly boot only");
        }
        if (activeDateTime != null) {
            s.append("\nActive: ").append(formatDate(activeDateTime));
        }
        if (originationExpireDateTime != null) {
            s.append("\nOrigination expire: ").append(formatDate(originationExpireDateTime));
        }
        if (usageExpireDateTime != null) {
            s.append("\nUsage expire: ").append(formatDate(usageExpireDateTime));
        }
        if (usageCountLimit != null) {
            s.append("\nUsage count limit: ").append(usageCountLimit);
        }
        if (noAuthRequired != null) {
            s.append("\nNo Auth Required");
        }
        if (userAuthType != null) {
            s.append("\nAuth types: ").append(userAuthTypeToString(userAuthType));
        }
        if (authTimeout != null) {
            s.append("\nAuth timeout: ").append(authTimeout);
        }
        if (allowWhileOnBody != null) {
            s.append("\nAllow While On Body");
        }
        if (trustedUserPresenceReq != null) {
            s.append("\nUser presence required");
        }
        if (trustedConfirmationReq != null) {
            s.append("\nConfirmation required");
        }
        if (unlockedDeviceReq != null) {
            s.append("\nUnlocked Device Required");
        }
        if (allApplications != null) {
            s.append("\nAll Applications");
        }
        if (applicationId != null) {
            s.append("\nApplication ID: ").append(applicationId);
        }
        if (creationDateTime != null) {
            s.append("\nCreated: ").append(formatDate(creationDateTime));
        }
        if (origin != null) {
            s.append("\nOrigin: ").append(originToString(origin));
        }
        if (rollbackResistant != null) {
            s.append("\nRollback resistant");
        }
        if (rootOfTrust != null) {
            s.append("\nRoot of Trust:\n");
            s.append(rootOfTrust);
        }
        if (osVersion != null) {
            s.append("\nOS Version: ").append(osVersion);
        }
        if (osPatchLevel != null) {
            s.append("\nOS Patchlevel: ").append(osPatchLevel);
        }
        if (attestationApplicationId != null) {
            s.append("\nAttestation Application Id:\n").append(attestationApplicationId);
        }
        if (brand != null) {
            s.append("\nBrand: ").append(brand);
        }
        if (device != null) {
            s.append("\nDevice type: ").append(device);
        }
        if (product != null) {
            s.append("\nProduct: ").append(product);
        }
        if (serialNumber != null) {
            s.append("\nSerial: ").append(serialNumber);
        }
        if (imei != null) {
            s.append("\nIMEI: ").append(imei);
        }
        if (meid != null) {
            s.append("\nMEID: ").append(meid);
        }
        if (manufacturer != null) {
            s.append("\nManufacturer: ").append(manufacturer);
        }
        if (model != null) {
            s.append("\nModel: ").append(model);
        }
        if (vendorPatchLevel != null) {
            s.append("\nVendor Patchlevel: ").append(vendorPatchLevel);
        }
        if (bootPatchLevel != null) {
            s.append("\nBoot Patchlevel: ").append(bootPatchLevel);
        }
        if (deviceUniqueAttestation != null) {
            s.append("\nDevice unique attestation");
        }
        if (identityCredentialKey != null) {
            s.append("\nIdentity Credential Key");
        }
        if (secondImei != null) {
            s.append("\nSecond IMEI:").append(secondImei);
        }
        return s.toString();
    }
    //---------------------------------------------------toString-------------------------------------------------------
    //purpose
    private final int KM_PURPOSE_ENCRYPT = 0;
    private final int KM_PURPOSE_DECRYPT = 1;
    private final int KM_PURPOSE_SIGN = 2;
    private final int KM_PURPOSE_VERIFY = 3;
    private final int KM_PURPOSE_WRAP = 5;
    private final int KM_PURPOSE_AGREE_KEY = 6;
    private final int KM_PURPOSE_ATTEST_KEY = 7;
    private final ImmutableMap<Integer, String> purposeMap = ImmutableMap
            .<Integer, String>builder()
            .put(KM_PURPOSE_DECRYPT, "DECRYPT")
            .put(KM_PURPOSE_ENCRYPT, "ENCRYPT")
            .put(KM_PURPOSE_SIGN, "SIGN")
            .put(KM_PURPOSE_VERIFY, "VERIFY")
            .put(KM_PURPOSE_WRAP, "WRAP")
            .put(KM_PURPOSE_AGREE_KEY, "AGREE KEY")
            .put(KM_PURPOSE_ATTEST_KEY, "ATTEST KEY")
            .build();
    //algorithm
    private String algorithmToString(int algorithm) {
        final int KM_ALGORITHM_RSA = 1;
        final int KM_ALGORITHM_EC = 3;
        final int KM_ALGORITHM_AES = 32;
        final int KM_ALGORITHM_3DES = 33;
        final int KM_ALGORITHM_HMAC = 128;
        if (algorithm == KM_ALGORITHM_RSA) {
            return "RSA";
        } else if (algorithm == KM_ALGORITHM_EC) {
            return "ECDSA";
        } else if (algorithm == KM_ALGORITHM_AES) {
            return "AES";
        } else if (algorithm == KM_ALGORITHM_3DES) {
            return "3DES";
        } else if (algorithm == KM_ALGORITHM_HMAC) {
            return "HMAC";
        }
        return "Unknown (" + algorithm + ")";
    }
    //keysize
    //digests
    private final int KM_DIGEST_NONE = 0;
    private final int KM_DIGEST_MD5 = 1;
    private final int KM_DIGEST_SHA1 = 2;
    private final int KM_DIGEST_SHA_2_224 = 3;
    private final int KM_DIGEST_SHA_2_256 = 4;
    private final int KM_DIGEST_SHA_2_384 = 5;
    private final int KM_DIGEST_SHA_2_512 = 6;
    private final ImmutableMap<Integer, String> digestMap = ImmutableMap
            .<Integer, String>builder()
            .put(KM_DIGEST_NONE, KeyProperties.DIGEST_NONE)
            .put(KM_DIGEST_MD5, KeyProperties.DIGEST_MD5)
            .put(KM_DIGEST_SHA1, KeyProperties.DIGEST_SHA1)
            .put(KM_DIGEST_SHA_2_224, KeyProperties.DIGEST_SHA224)
            .put(KM_DIGEST_SHA_2_256, KeyProperties.DIGEST_SHA256)
            .put(KM_DIGEST_SHA_2_384, KeyProperties.DIGEST_SHA384)
            .put(KM_DIGEST_SHA_2_512, KeyProperties.DIGEST_SHA512)
            .build();
    //paddingmodes
    private final int KM_PAD_NONE = 1;
    private final int KM_PAD_RSA_OAEP = 2;
    private final int KM_PAD_RSA_PSS = 3;
    private final int KM_PAD_RSA_PKCS1_1_5_ENCRYPT = 4;
    private final int KM_PAD_RSA_PKCS1_1_5_SIGN = 5;
    private final int KM_PAD_PKCS7 = 64;
    private final ImmutableMap<Integer, String> paddingMap = ImmutableMap
            .<Integer, String>builder()
            .put(KM_PAD_NONE, KeyProperties.ENCRYPTION_PADDING_NONE)
            .put(KM_PAD_RSA_OAEP, KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
            .put(KM_PAD_RSA_PSS, KeyProperties.SIGNATURE_PADDING_RSA_PSS)
            .put(KM_PAD_RSA_PKCS1_1_5_ENCRYPT, KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
            .put(KM_PAD_RSA_PKCS1_1_5_SIGN, KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
            .put(KM_PAD_PKCS7, KeyProperties.ENCRYPTION_PADDING_PKCS7)
            .build();
    //eccurve
    private String ecCurveToString(Integer ecCurve) {
        final int KM_EC_CURVE_P224 = 0;
        final int KM_EC_CURVE_P256 = 1;
        final int KM_EC_CURVE_P384 = 2;
        final int KM_EC_CURVE_P521 = 3;
        final int KM_EC_CURVE_CURVE_25519 = 4;
        if (ecCurve == KM_EC_CURVE_P224) {
            return "secp224r1";
        } else if (ecCurve == KM_EC_CURVE_P256) {
            return "secp256r1";
        } else if (ecCurve == KM_EC_CURVE_P384) {
            return "secp384r1";
        } else if (ecCurve == KM_EC_CURVE_P521) {
            return "secp521r1";
        } else if (ecCurve == KM_EC_CURVE_CURVE_25519) {
            return "CURVE_25519";
        }
        return "unknown (" + ecCurve + ")";
    }
    //rsapublicexponent
    //mgfdigests
    //rollbackresistance
    //activedatetime
    private String formatDate(Date date) {
        return DateFormat.getDateTimeInstance().format(date);
    }
    //originationexpiredatetime
    //usageexpiredatetime
    //usageCountLimit
    //noAuthRequired
    private String userAuthTypeToString(int userAuthType) {
        final int HW_AUTH_PASSWORD = 1;
        final int HW_AUTH_BIOMETRIC = 1 << 1;
        List<String> types = Lists.newArrayList();
        if ((userAuthType & HW_AUTH_BIOMETRIC) != 0)
            types.add("Biometric");
        if ((userAuthType & HW_AUTH_PASSWORD) != 0)
            types.add("Password");
        return "[" + Joiner.on(", ").join(types) + "]";
    }
    //authTimeout
    //allowWhileOnBody
    //trustedUserPresenceReq
    //trustedConfirmationReq
    //unlockedDeviceReq
    //allApplications
    //applicationId
    //creationDateTime
    //origin
    private String originToString(int origin) {
        final int KM_ORIGIN_GENERATED = 0;
        final int KM_ORIGIN_DERIVED = 1;
        final int KM_ORIGIN_IMPORTED = 2;
        final int KM_ORIGIN_UNKNOWN = 3;
        final int KM_ORIGIN_SECURELY_IMPORTED = 4;
        if (origin == KM_ORIGIN_GENERATED) {
            return "Generated";
        } else if (origin == KM_ORIGIN_DERIVED) {
            return "Derived";
        } else if (origin == KM_ORIGIN_IMPORTED) {
            return "Imported";
        } else if (origin == KM_ORIGIN_UNKNOWN) {
            return "Unknown (KM0)";
        } else if (origin == KM_ORIGIN_SECURELY_IMPORTED) {
            return "Securely Imported";
        }
        return "Unknown (" + origin + ")";
    }
    //rollbackResistant
    //rootOfTrust
    private String RootOfTrust(ASN1Encodable asn1Encodable) throws CertificateParsingException {
        final int VERIFIED_BOOT_KEY_INDEX = 0;
        final int DEVICE_LOCKED_INDEX = 1;
        final int VERIFIED_BOOT_STATE_INDEX = 2;
        final int VERIFIED_BOOT_HASH_INDEX = 3;
        StringBuilder s = new StringBuilder();
        if (!(asn1Encodable instanceof ASN1Sequence sequence)) {
            throw new CertificateParsingException("Expected sequence for root of trust, found "
                    + asn1Encodable.getClass().getName());
        }
        byte[] verifiedBootKey = getByteArrayFromAsn1(sequence.getObjectAt(VERIFIED_BOOT_KEY_INDEX));
        boolean deviceLocked = getBooleanFromAsn1(sequence.getObjectAt(DEVICE_LOCKED_INDEX));
        isdevicelocked = deviceLocked;
        int verifiedBootState = getIntegerFromAsn1(sequence.getObjectAt(VERIFIED_BOOT_STATE_INDEX));
        byte[] verifiedBootHash;
        if (sequence.size() == 3){
            verifiedBootHash = null;
        }else{
            verifiedBootHash = getByteArrayFromAsn1(sequence.getObjectAt(VERIFIED_BOOT_HASH_INDEX));
        }
        s.append("\tverifiedBootKey: ")
                .append(BaseEncoding.base16().encode(verifiedBootKey))
                .append("\n\tdeviceLocked: ")
                .append(deviceLocked)
                .append("\n\tverifiedBootState: ")
                .append(verifiedBootStateToString(verifiedBootState));
        if (verifiedBootHash != null) {
            s.append("\n\tverifiedBootHash: ")
                    .append(BaseEncoding.base16().encode(verifiedBootHash));
        }
        return s.toString();
    }
    private String verifiedBootStateToString(int verifiedBootState) {
        final int KM_VERIFIED_BOOT_VERIFIED = 0;
        final int KM_VERIFIED_BOOT_SELF_SIGNED = 1;
        final int KM_VERIFIED_BOOT_UNVERIFIED = 2;
        final int KM_VERIFIED_BOOT_FAILED = 3;
        if (verifiedBootState == KM_VERIFIED_BOOT_VERIFIED) {
            return "Verified";
        } else if (verifiedBootState == KM_VERIFIED_BOOT_SELF_SIGNED) {
            return "Self-signed";
        } else if (verifiedBootState == KM_VERIFIED_BOOT_UNVERIFIED) {
            return "Unverified";
        } else if (verifiedBootState == KM_VERIFIED_BOOT_FAILED) {
            return "Failed";
        }
        return "Unknown (" + verifiedBootState + ")";
    }
    //osVersion
    //osPatchLevel
    //attestationApplicationId
    private String AttestationApplicationId(ASN1Encodable asn1Encodable) throws CertificateParsingException {
        final int PACKAGE_INFOS_INDEX = 0;
        final int SIGNATURE_DIGESTS_INDEX = 1;
        if (!(asn1Encodable instanceof ASN1Sequence sequence)) {
            throw new CertificateParsingException(
                    "Expected sequence for AttestationApplicationId, found "
                            + asn1Encodable.getClass().getName());
        }
        List<String> packageInfos = parseAttestationPackageInfos(sequence.getObjectAt(PACKAGE_INFOS_INDEX));
        packageInfos.sort(null);
        List<byte[]> signatureDigests = parseSignatures(sequence.getObjectAt(SIGNATURE_DIGESTS_INDEX));
        signatureDigests.sort(new ByteArrayComparator());
        StringBuilder sb = new StringBuilder();
        int noOfInfos = packageInfos.size();
        int i = 1;
        for (String info : packageInfos) {
            sb.append("\tPackage info ").append(i++).append("/").append(noOfInfos).append(":\n\t");
            sb.append(info);
            sb.append('\n');
        }
        i = 1;
        int noOfSigs = signatureDigests.size();
        for (byte[] sig : signatureDigests) {
            sb.append("\tCertificate sha256 digest ").append(i++).append("/").append(noOfSigs).append(":\n");
            sb.append(BaseEncoding.base16().encode(sig));
            sb.append('\n');
        }
        return sb.toString();
    }
    private List<String> parseAttestationPackageInfos(ASN1Encodable asn1Encodable) throws CertificateParsingException {
        if (!(asn1Encodable instanceof ASN1Set set)) {
            throw new CertificateParsingException(
                    "Expected set for AttestationApplicationsInfos, found "
                            + asn1Encodable.getClass().getName());
        }
        List<String> result = new ArrayList<>();
        for (ASN1Encodable e : set) {
            result.add(AttestationPackageInfo(e));
        }
        return result;
    }
    private String AttestationPackageInfo(ASN1Encodable asn1Encodable) throws CertificateParsingException {
        final int PACKAGE_NAME_INDEX = 0;
        final int VERSION_INDEX = 1;
        if (!(asn1Encodable instanceof ASN1Sequence sequence)) {
            throw new CertificateParsingException(
                    "Expected sequence for AttestationPackageInfo, found "
                            + asn1Encodable.getClass().getName());
        }
        String packageName = getStringFromAsn1OctetStreamAssumingUTF8(
                sequence.getObjectAt(PACKAGE_NAME_INDEX));
        long version = getLongFromAsn1(sequence.getObjectAt(VERSION_INDEX));
        return "\t" + packageName + "(version:" + version + ")";
    }
    private List<byte[]> parseSignatures(ASN1Encodable asn1Encodable)
            throws CertificateParsingException {
        if (!(asn1Encodable instanceof ASN1Set set)) {
            throw new CertificateParsingException("Expected set for Signature digests, found "
                    + asn1Encodable.getClass().getName());
        }
        List<byte[]> result = new ArrayList<>();
        for (ASN1Encodable e : set) {
            result.add(getByteArrayFromAsn1(e));
        }
        return result;
    }
    private static class ByteArrayComparator implements java.util.Comparator<byte[]> {
        @Override
        public int compare(byte[] a, byte[] b) {
            int res = Integer.compare(a.length, b.length);
            if (res != 0) return res;
            for (int i = 0; i < a.length; ++i) {
                res = Byte.compare(a[i], b[i]);
                if (res != 0) return res;
            }
            return res;
        }
    }
    //brand
    //device
    //product
    //serialNumber
    //imei
    //meid
    //manufacturer
    //model
    //vendorPatchLevel
    //bootPatchLevel
    //deviceUniqueAttestation
    //identityCredentialKey
    //secondImei
    //---------------------------------------------------getdataFromAsn1------------------------------------------------
    private byte[] getByteArrayFromAsn1(ASN1Encodable asn1Encodable)
            throws CertificateParsingException {
        if (!(asn1Encodable instanceof DEROctetString derOctectString)) {
            throw new CertificateParsingException("Expected DEROctetString");
        }
        return derOctectString.getOctets();
    }
    private int getIntegerFromAsn1(ASN1Encodable asn1Value)
            throws CertificateParsingException {
        if (asn1Value instanceof ASN1Integer) {
            return bigIntegerToInt(((ASN1Integer) asn1Value).getValue());
        } else if (asn1Value instanceof ASN1Enumerated) {
            return bigIntegerToInt(((ASN1Enumerated) asn1Value).getValue());
        } else {
            throw new CertificateParsingException(
                    "Integer value expected, " + asn1Value.getClass().getName() + " found.");
        }
    }
    private Long getLongFromAsn1(ASN1Encodable asn1Value) throws CertificateParsingException {
        if (asn1Value instanceof ASN1Integer) {
            return bigIntegerToLong(((ASN1Integer) asn1Value).getValue());
        } else {
            throw new CertificateParsingException(
                    "Integer value expected, " + asn1Value.getClass().getName() + " found.");
        }
    }
    private int bigIntegerToInt(BigInteger bigInt) throws CertificateParsingException {
        if (bigInt.compareTo(BigInteger.valueOf(Integer.MAX_VALUE)) > 0
                || bigInt.compareTo(BigInteger.ZERO) < 0) {
            throw new CertificateParsingException("INTEGER out of bounds");
        }
        return bigInt.intValue();
    }
    private long bigIntegerToLong(BigInteger bigInt) throws CertificateParsingException {
        if (bigInt.compareTo(BigInteger.valueOf(Long.MAX_VALUE)) > 0
                || bigInt.compareTo(BigInteger.ZERO) < 0) {
            throw new CertificateParsingException("INTEGER out of bounds");
        }
        return bigInt.longValue();
    }
    private Date getDateFromAsn1(ASN1Primitive value) throws CertificateParsingException {
        return new Date(getLongFromAsn1(value));
    }
    private Set<Integer> getIntegersFromAsn1Set(ASN1Encodable set)
            throws CertificateParsingException {
        if (!(set instanceof ASN1Set)) {
            throw new CertificateParsingException(
                    "Expected set, found " + set.getClass().getName());
        }
        ImmutableSet.Builder<Integer> builder = ImmutableSet.builder();
        for (Enumeration<?> e = ((ASN1Set) set).getObjects(); e.hasMoreElements();) {
            builder.add(getIntegerFromAsn1((ASN1Integer) e.nextElement()));
        }
        return builder.build();
    }
    private String getStringFromAsn1OctetStreamAssumingUTF8(ASN1Encodable encodable)
            throws CertificateParsingException {
        if (!(encodable instanceof ASN1OctetString octetString)) {
            throw new CertificateParsingException(
                    "Expected octet string, found " + encodable.getClass().getName());
        }
        return new String(octetString.getOctets(), StandardCharsets.UTF_8);
    }
    private boolean getBooleanFromAsn1(ASN1Encodable value)
            throws CertificateParsingException {
        if (!(value instanceof ASN1Boolean booleanValue)) {
            throw new CertificateParsingException(
                    "Expected boolean, found " + value.getClass().getName());
        }
        if (booleanValue.equals(ASN1Boolean.TRUE)) {
            return true;
        } else if (booleanValue.equals((ASN1Boolean.FALSE))) {
            return false;
        }
        throw new CertificateParsingException(
                "DER-encoded boolean values must contain either 0x00 or 0xFF");
    }
    private ASN1Encodable getAsn1EncodableFromBytes(byte[] bytes)
            throws CertificateParsingException {
        try (ASN1InputStream asn1InputStream = new ASN1InputStream(bytes)) {
            return asn1InputStream.readObject();
        } catch (IOException e) {
            throw new CertificateParsingException("Failed to parse Encodable", e);
        }
    }
}
