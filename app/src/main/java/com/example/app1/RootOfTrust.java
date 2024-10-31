package com.example.app1;


import com.google.common.io.BaseEncoding;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;

import java.security.cert.CertificateParsingException;


public class RootOfTrust {
    private static final int VERIFIED_BOOT_KEY_INDEX = 0;
    private static final int DEVICE_LOCKED_INDEX = 1;
    private static final int VERIFIED_BOOT_STATE_INDEX = 2;
    private static final int VERIFIED_BOOT_HASH_INDEX = 3;

    public static final int KM_VERIFIED_BOOT_VERIFIED = 0;
    public static final int KM_VERIFIED_BOOT_SELF_SIGNED = 1;
    public static final int KM_VERIFIED_BOOT_UNVERIFIED = 2;
    public static final int KM_VERIFIED_BOOT_FAILED = 3;

    private final byte[] verifiedBootKey;
    private final boolean deviceLocked;
    private final int verifiedBootState;
    private final byte[] verifiedBootHash;

    public RootOfTrust(ASN1Encodable asn1Encodable) throws CertificateParsingException {
        if (!(asn1Encodable instanceof ASN1Sequence sequence)) {
            throw new CertificateParsingException("Expected sequence for root of trust, found "
                    + asn1Encodable.getClass().getName());
        }

        verifiedBootKey =
                bl.getByteArrayFromAsn1(sequence.getObjectAt(VERIFIED_BOOT_KEY_INDEX));
        deviceLocked = bl.getBooleanFromAsn1(sequence.getObjectAt(DEVICE_LOCKED_INDEX));
        verifiedBootState =
                bl.getIntegerFromAsn1(sequence.getObjectAt(VERIFIED_BOOT_STATE_INDEX));
        if (sequence.size() == 3) verifiedBootHash = null;
        else verifiedBootHash =
                bl.getByteArrayFromAsn1(sequence.getObjectAt(VERIFIED_BOOT_HASH_INDEX));
    }

    RootOfTrust(byte[] verifiedBootKey, boolean deviceLocked,
                int verifiedBootState, byte[] verifiedBootHash) {
        this.verifiedBootKey = verifiedBootKey;
        this.deviceLocked = deviceLocked;
        this.verifiedBootState = verifiedBootState;
        this.verifiedBootHash = verifiedBootHash;
    }

    public static String verifiedBootStateToString(int verifiedBootState) {
        switch (verifiedBootState) {
            case KM_VERIFIED_BOOT_VERIFIED:
                return "Verified";
            case KM_VERIFIED_BOOT_SELF_SIGNED:
                return "Self-signed";
            case KM_VERIFIED_BOOT_UNVERIFIED:
                return "Unverified";
            case KM_VERIFIED_BOOT_FAILED:
                return "Failed";
            default:
                return "Unknown (" + verifiedBootState + ")";
        }
    }

    public byte[] getVerifiedBootKey() {
        return verifiedBootKey;
    }

    public boolean isDeviceLocked() {
        return deviceLocked;
    }

    public int getVerifiedBootState() {
        return verifiedBootState;
    }

    public byte[] getVerifiedBootHash() {
        return verifiedBootHash;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder()
                .append("verifiedBootKey: ")
                .append(BaseEncoding.base16().encode(verifiedBootKey))
                .append("\ndeviceLocked: ")
                .append(deviceLocked)
                .append("\nverifiedBootState: ")
                .append(verifiedBootStateToString(verifiedBootState));
        if (verifiedBootHash != null) {
            sb.append("\nverifiedBootHash: ")
                    .append(BaseEncoding.base16().encode(verifiedBootHash));
        }
        return sb.toString();
    }

    public static class Builder {
        private byte[] verifiedBootKey;
        private boolean deviceLocked = false;
        private int verifiedBootState = -1;
        private byte[] verifiedBootHash;

        public Builder setVerifiedBootKey(byte[] verifiedBootKey) {
            this.verifiedBootKey = verifiedBootKey;
            return this;
        }

        public Builder setDeviceLocked(boolean deviceLocked) {
            this.deviceLocked = deviceLocked;
            return this;
        }

        public Builder setVerifiedBootState(int verifiedBootState) {
            this.verifiedBootState = verifiedBootState;
            return this;
        }

        public Builder setVerifiedBootHash(byte[] verifiedBootHash) {
            this.verifiedBootHash = verifiedBootHash;
            return this;
        }

        public RootOfTrust build() {
            return new RootOfTrust(verifiedBootKey, deviceLocked,
                    verifiedBootState, verifiedBootHash);
        }
    }


}
