package com.sparrowwallet.drongo.crypto;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.security.KeyPair;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.NamedParameterSpec;

public class X25519KeyTest {
    
    // Standard size for X25519 private keys (256 bits / 8 = 32 bytes)
    private static final int X25519_KEY_SIZE = 32;
    
    /**
     * Tests the basic key generation functionality of X25519Key.
     * Verifies that random key generation creates valid key pairs
     * with the correct algorithm type.
     */
    @Test
    public void testKeyGeneration() {
        // Setup
        X25519Key randomKey = new X25519Key();
        
        // Verification
        assertNotNull(randomKey.getKeyPair());
        assertNotNull(randomKey.getKeyPair().getPublic());
        assertNotNull(randomKey.getKeyPair().getPrivate());
        assertEquals("X25519", randomKey.getKeyPair().getPrivate().getAlgorithm());
        assertEquals("X25519", randomKey.getKeyPair().getPublic().getAlgorithm());
    }
    
    /**
     * Tests creating an X25519Key from an existing private key.
     * Verifies that the key is properly initialized and the private key
     * material is accessible.
     */
    @Test
    public void testKeyCreationFromPrivateKey() {
        // Setup
        byte[] privateKeyBytes = new byte[X25519_KEY_SIZE];
        // Fill with some non-zero values to make a valid test key
        for (int i = 0; i < privateKeyBytes.length; i++) {
            privateKeyBytes[i] = (byte)(i + 1);
        }
        
        // Action
        X25519Key key = new X25519Key(privateKeyBytes);
        
        // Verification
        assertNotNull(key.getKeyPair());
        assertArrayEquals(privateKeyBytes, key.getRawPrivateKeyBytes());
    }
    
    /**
     * Tests that the private key correctly implements the XECPrivateKey interface.
     */
    @Test
    public void testPrivateKeyImplementsCorrectInterface() {
        // Setup
        X25519Key key = new X25519Key();
        KeyPair keyPair = key.getKeyPair();
        
        // Verification
        assertTrue(keyPair.getPrivate() instanceof XECPrivateKey);
        XECPrivateKey privateKey = (XECPrivateKey) keyPair.getPrivate();
        assertEquals("X25519", privateKey.getAlgorithm());
        assertEquals("RAW", privateKey.getFormat());
    }
    
    /**
     * Tests that the public key correctly implements the XECPublicKey interface.
     */
    @Test
    public void testPublicKeyImplementsCorrectInterface() {
        // Setup
        X25519Key key = new X25519Key();
        KeyPair keyPair = key.getKeyPair();
        
        // Verification
        assertTrue(keyPair.getPublic() instanceof XECPublicKey);
        XECPublicKey publicKey = (XECPublicKey) keyPair.getPublic();
        assertEquals("X25519", publicKey.getAlgorithm());
        assertEquals("X.509", publicKey.getFormat());
    }
    
    /**
     * Tests that the key parameter specifications are correctly set.
     */
    @Test
    public void testParameterSpecifications() {
        // Setup
        X25519Key key = new X25519Key();
        KeyPair keyPair = key.getKeyPair();
        XECPrivateKey privateKey = (XECPrivateKey) keyPair.getPrivate();
        XECPublicKey publicKey = (XECPublicKey) keyPair.getPublic();
        
        // Verification - Parameter specs
        assertNotNull(privateKey.getParams());
        assertTrue(privateKey.getParams() instanceof NamedParameterSpec);
        assertEquals("X25519", ((NamedParameterSpec)privateKey.getParams()).getName());
        
        assertNotNull(publicKey.getParams());
        assertTrue(publicKey.getParams() instanceof NamedParameterSpec);
        assertEquals("X25519", ((NamedParameterSpec)publicKey.getParams()).getName());
    }
    
    /**
     * Tests that the key components are valid and accessible.
     */
    @Test
    public void testKeyComponents() {
        // Setup
        X25519Key key = new X25519Key();
        KeyPair keyPair = key.getKeyPair();
        XECPrivateKey privateKey = (XECPrivateKey) keyPair.getPrivate();
        XECPublicKey publicKey = (XECPublicKey) keyPair.getPublic();
        
        // Verification - Key components
        assertTrue(privateKey.getScalar().isPresent());
        assertNotNull(privateKey.getScalar().get());
        
        assertNotNull(publicKey.getU());
        assertNotEquals(0, publicKey.getU().signum());
    }
}
