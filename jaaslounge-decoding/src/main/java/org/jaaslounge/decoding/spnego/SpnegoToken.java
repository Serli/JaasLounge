package org.jaaslounge.decoding.spnego;

import org.jaaslounge.decoding.DecodingException;

public abstract class SpnegoToken {

    protected byte[] mechanismToken;
    protected byte[] mechanismList;
    protected String mechanism;

    public static SpnegoToken parse(byte[] token) throws DecodingException {
        SpnegoToken spnegoToken = null;

        if(token.length <= 0)
            throw new DecodingException("spnego.token.empty", null, null);

        switch (token[0]) {
        case (byte)0x60:
            spnegoToken = new SpnegoInitToken(token);
            break;
        case (byte)0xa1:
            spnegoToken = new SpnegoTargToken(token);
            break;
        default:
            spnegoToken = null;
            Object[] args = new Object[]{token[0]};
            throw new DecodingException("spnego.token.invalid", args, null);
        }

        return spnegoToken;
    }

    public byte[] getMechanismToken() {
        return mechanismToken;
    }

    public byte[] getMechanismList() {
        return mechanismList;
    }

    public String getMechanism() {
        return mechanism;
    }

}
