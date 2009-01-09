package org.jaaslounge.decoding.pac;

@Deprecated
public final class PacUtil {

    private static final String FORMAT = "%1$02x";

    private PacUtil() {}

    public static final String asHexString(byte[] bytes) {
        StringBuilder builder = new StringBuilder();
        for(byte b : bytes)
            builder.append(String.format(FORMAT, b));

        return builder.toString();
    }

    public static final byte[] asBytes(int integer) {
        byte[] bytes = new byte[]{(byte)integer, (byte)(integer >>> 8), (byte)(integer >>> 16),
                (byte)(integer >>> 24)};

        return bytes;
    }
}
