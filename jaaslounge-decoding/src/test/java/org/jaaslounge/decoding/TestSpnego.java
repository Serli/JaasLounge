package org.jaaslounge.decoding;

import java.io.IOException;
import java.io.InputStream;

import junit.framework.TestCase;

import org.jaaslounge.decoding.spnego.SpnegoConstants;
import org.jaaslounge.decoding.spnego.SpnegoInitToken;
import org.jaaslounge.decoding.spnego.SpnegoToken;
import org.junit.Before;
import org.junit.Test;

public class TestSpnego extends TestCase {

    private byte[] rc4Token;
    private byte[] desToken;
    private byte[] aes128Token;
    private byte[] aes256Token;
    private byte[] corruptToken;

    @Before
    public void setUp() throws IOException {
        InputStream file;

        file = this.getClass().getClassLoader().getResourceAsStream("rc4-spnego-data");
        rc4Token = new byte[file.available()];
        file.read(rc4Token);
        file.close();

        file = this.getClass().getClassLoader().getResourceAsStream("des-spnego-data");
        desToken = new byte[file.available()];
        file.read(desToken);
        file.close();

        file = this.getClass().getClassLoader().getResourceAsStream("aes128-spnego-data");
        aes128Token = new byte[file.available()];
        file.read(aes128Token);
        file.close();

        file = this.getClass().getClassLoader().getResourceAsStream("aes256-spnego-data");
        aes256Token = new byte[file.available()];
        file.read(aes256Token);
        file.close();

        corruptToken = new byte[]{5, 4, 2, 1};
    }

    @Test
    public void testRc4Token() {
        try {
            SpnegoToken spnegoToken = SpnegoToken.parse(rc4Token);

            assertNotNull(spnegoToken);
            assertTrue(spnegoToken instanceof SpnegoInitToken);
            assertNotNull(spnegoToken.getMechanismToken());
            assertTrue(spnegoToken.getMechanismToken().length < rc4Token.length);
            assertNotNull(spnegoToken.getMechanism());
            assertEquals(SpnegoConstants.LEGACY_KERBEROS_MECHANISM, spnegoToken.getMechanism());
        } catch(DecodingException e) {
            e.printStackTrace();
            fail(e.getMessage());
        }
    }

    @Test
    public void testDesToken() {
        try {
            SpnegoToken spnegoToken = SpnegoToken.parse(desToken);

            assertNotNull(spnegoToken);
            assertTrue(spnegoToken instanceof SpnegoInitToken);
            assertNotNull(spnegoToken.getMechanismToken());
            assertTrue(spnegoToken.getMechanismToken().length < desToken.length);
            assertNotNull(spnegoToken.getMechanism());
            assertEquals(SpnegoConstants.LEGACY_KERBEROS_MECHANISM, spnegoToken.getMechanism());
        } catch(DecodingException e) {
            e.printStackTrace();
            fail(e.getMessage());
        }
    }

    @Test
    public void testAes128Token() {
        try {
            SpnegoToken spnegoToken = SpnegoToken.parse(aes128Token);

            assertNotNull(spnegoToken);
            assertTrue(spnegoToken instanceof SpnegoInitToken);
            assertNotNull(spnegoToken.getMechanismToken());
            assertTrue(spnegoToken.getMechanismToken().length < aes128Token.length);
            assertNotNull(spnegoToken.getMechanism());
            assertEquals(SpnegoConstants.LEGACY_KERBEROS_MECHANISM, spnegoToken.getMechanism());
        } catch(DecodingException e) {
            e.printStackTrace();
            fail(e.getMessage());
        }
    }

    @Test
    public void testAes256Token() {
        try {
            SpnegoToken spnegoToken = SpnegoToken.parse(aes256Token);

            assertNotNull(spnegoToken);
            assertTrue(spnegoToken instanceof SpnegoInitToken);
            assertNotNull(spnegoToken.getMechanismToken());
            assertTrue(spnegoToken.getMechanismToken().length < aes256Token.length);
            assertNotNull(spnegoToken.getMechanism());
            assertEquals(SpnegoConstants.LEGACY_KERBEROS_MECHANISM, spnegoToken.getMechanism());
        } catch(DecodingException e) {
            e.printStackTrace();
            fail(e.getMessage());
        }
    }

    @Test
    public void testEmptyToken() {
        SpnegoToken spnegoToken = null;
        try {
            spnegoToken = SpnegoToken.parse(new byte[0]);
            fail("Should have thrown DecodingException.");
        } catch(DecodingException e) {
            assertNotNull(e);
            assertNull(spnegoToken);
        }
    }

    @Test
    public void testCorruptToken() {
        SpnegoToken spnegoToken = null;
        try {
            spnegoToken = SpnegoToken.parse(corruptToken);
            fail("Should have thrown DecodingException.");
        } catch(DecodingException e) {
            assertNotNull(e);
            assertNull(spnegoToken);
        }
    }

    @Test
    public void testNullToken() {
        SpnegoToken spnegoToken = null;
        try {
            spnegoToken = SpnegoToken.parse(null);
            fail("Should have thrown NullPointerException.");
        } catch(DecodingException e) {
            e.printStackTrace();
            fail(e.getMessage());
        } catch(NullPointerException e) {
            assertNotNull(e);
            assertNull(spnegoToken);
        }
    }

}
