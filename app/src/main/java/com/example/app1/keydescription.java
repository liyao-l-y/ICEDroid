package com.example.app1;

import com.google.common.base.CharMatcher;
import com.google.common.io.BaseEncoding;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;

import java.math.BigInteger;
import java.security.cert.CertificateParsingException;

public class keydescription {
    public String keyDescriptionResult(ASN1Sequence seq) throws CertificateParsingException {
        final int ATTESTATION_VERSION_INDEX = 0;
        final int ATTESTATION_SECURITY_LEVEL_INDEX = 1;
        final int KEYMASTER_VERSION_INDEX = 2;
        final int KEYMASTER_SECURITY_LEVEL_INDEX = 3;
        final int ATTESTATION_CHALLENGE_INDEX = 4;
        final int UNIQUE_ID_INDEX = 5;
        StringBuilder KeyDescription = new StringBuilder("KeyDescription");
        String attestationVersion = attestationVersionToString(getIntegerFromAsn1(seq.getObjectAt(ATTESTATION_VERSION_INDEX)));
        String attestationSecurityLevel = securityLevelToString(getIntegerFromAsn1(seq.getObjectAt(ATTESTATION_SECURITY_LEVEL_INDEX)));
        String keymasterVersion = keymasterVersionToString(getIntegerFromAsn1(seq.getObjectAt(KEYMASTER_VERSION_INDEX)));
        String keymasterSecurityLevel = securityLevelToString(getIntegerFromAsn1(seq.getObjectAt(KEYMASTER_SECURITY_LEVEL_INDEX)));

        KeyDescription.append("\nattestationVersion:").append(attestationVersion);
        KeyDescription.append("\nattestationSecurityLevel:").append(attestationSecurityLevel);
        KeyDescription.append("\nkeymasterVersion:").append(keymasterVersion);
        KeyDescription.append("\nkeymasterSecurityLevel:").append(keymasterSecurityLevel);

        byte[] attestationChallenge = getByteArrayFromAsn1(seq.getObjectAt(ATTESTATION_CHALLENGE_INDEX));
        byte[] uniqueId = getByteArrayFromAsn1(seq.getObjectAt(UNIQUE_ID_INDEX));

        String stringChallenge = attestationChallenge != null ? new String(attestationChallenge) : "null";
        if (CharMatcher.ascii().matchesAllOf(stringChallenge)) {
            KeyDescription.append("\nattestationChallenge:").append(stringChallenge);
        } else {
            assert attestationChallenge != null;
            KeyDescription.append("\nattestationChallenge:").append(BaseEncoding.base64().encode(attestationChallenge));
        }
        if (uniqueId != null) {
            KeyDescription.append("\nUnique ID:").append(BaseEncoding.base64().encode(uniqueId));
        }

        return KeyDescription.toString();
    }
    private String attestationVersionToString(int version) {
        if (version == 1) {
            return "Keymaster 2.0";
        } else if (version == 2) {
            return "Keymaster 3.0";
        } else if (version == 3) {
            return "Keymaster 4.0";
        } else if (version == 4) {
            return "Keymaster 4.1";
        } else if (version == 100) {
            return "KeyMint 1.0";
        } else if (version == 200) {
            return "KeyMint 2.0";
        } else if (version == 300) {
            return "KeyMint 3.0";
        }
        return "Unknown (" + version + ")";
    }
    private String keymasterVersionToString(int version) {
        if (version == 0) {
            return "Keymaster 0.2 or 0.3";
        } else if (version == 1) {
            return "Keymaster 1.0";
        } else if (version == 2) {
            return "Keymaster 2.0";
        } else if (version == 3) {
            return "Keymaster 3.0";
        } else if (version == 4) {
            return "Keymaster 4.0";
        } else if (version == 41) {
            return "Keymaster 4.1";
        } else if (version == 100) {
            return "KeyMint 1.0";
        } else if (version == 200) {
            return "KeyMint 2.0";
        } else if (version == 300) {
            return "KeyMint 3.0";
        }
        return "Unknown (" + version + ")";
    }
    private String securityLevelToString(int attestationSecurityLevel) {
        if (attestationSecurityLevel == 0) {
            return "Software";
        } else if (attestationSecurityLevel == 1) {
            return "TEE";
        } else if (attestationSecurityLevel == 2) {
            return "StrongBox";
        }
        return "Unknown (" + attestationSecurityLevel + ")";
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
    private byte[] getByteArrayFromAsn1(ASN1Encodable asn1Encodable)
            throws CertificateParsingException {
        if (!(asn1Encodable instanceof DEROctetString derOctectString)) {
            throw new CertificateParsingException("Expected DEROctetString");
        }
        return derOctectString.getOctets();
    }
    private int bigIntegerToInt(BigInteger bigInt) throws CertificateParsingException {
        if (bigInt.compareTo(BigInteger.valueOf(Integer.MAX_VALUE)) > 0
                || bigInt.compareTo(BigInteger.ZERO) < 0) {
            throw new CertificateParsingException("INTEGER out of bounds");
        }
        return bigInt.intValue();
    }

}
