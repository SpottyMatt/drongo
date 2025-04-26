package com.sparrowwallet.drongo.bip47;

import com.sparrowwallet.drongo.KeyPurpose;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.address.Address;
import com.sparrowwallet.drongo.crypto.ChildNumber;
import com.sparrowwallet.drongo.crypto.DeterministicKey;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.policy.Policy;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.*;
import com.sparrowwallet.drongo.wallet.*;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

public class MorePaymentCodeTest {
    
    // Constants for entropy sizes as per BIP-39 specification
    private static final int ENTROPY_SIZE_12_WORDS = 16; // 128 bits
    private static final int ENTROPY_SIZE_24_WORDS = 32; // 256 bits
    
    // Standard amount used for test transaction outputs (in satoshis)
    private static final long STANDARD_OUTPUT_AMOUNT = 10000;
    
    // Dummy transaction hash used for test inputs
    private static final byte[] DUMMY_TX_HASH = Utils.hexToBytes("7bac25892e87fa41dcbef00d93c7b1c0b20999e85604d2ff8c87a3df4d6541cd");
    
    // Placeholder for witness signature in test transactions
    private static final byte WITNESS_SIGNATURE_PLACEHOLDER = 0x01;
    
    // Fixed 12-word mnemonics for consistent test results
    private static final List<String> SENDER_12_WORDS = List.of(
        "tiger", "banana", "jungle", "rocket", "whale", "dance", 
        "potato", "elephant", "umbrella", "magic", "pioneer", "wisdom"
    );

    private static final List<String> RECEIVER_12_WORDS = List.of(
        "digital", "mystery", "robot", "casino", "tornado", "discover", 
        "dragon", "piano", "goddess", "harvest", "crazy", "media"
    );

    // Fixed 24-word mnemonics for word count testing
    private static final List<String> SENDER_24_WORDS = List.of(
        "ocean", "prefer", "camera", "lonely", "warrior", "journey", 
        "pelican", "blossom", "physical", "champion", "dolphin", "glance",
        "tonight", "whisper", "liberty", "bridge", "royal", "school",
        "ordinary", "ghost", "helmet", "ticket", "pumpkin", "glove"
    );

    private static final List<String> RECEIVER_24_WORDS = List.of(
        "mountain", "kingdom", "bamboo", "fossil", "panic", "essay", 
        "garbage", "party", "sketch", "giraffe", "ancient", "muffin",
        "weapon", "category", "lobster", "mansion", "census", "tourist",
        "wonder", "perfect", "lottery", "lecture", "comfort", "divorce"
    );
    
    /**
     * Tests BIP47 payment code functionality when both sender and receiver wallets have no passphrase.
     * <p>
     * This test establishes the baseline for proper functioning of BIP47 payments in the simplest case,
     * where neither wallet uses a BIP39 passphrase for seed derivation. This is the most common usage
     * scenario and should work reliably regardless of script type.
     *
     * @param scriptType The script type to use for the test (P2PKH or P2WPKH)
     * @see #scriptTypeProvider()
     */
    @ParameterizedTest
    @MethodSource("scriptTypeProvider")
    void testNoPassphraseToNoPassphrase(ScriptType scriptType) throws Exception {
        // Create sender wallet with no passphrase
        Wallet senderWallet = createWallet("", scriptType, SENDER_12_WORDS);
        Keystore senderKeystore = senderWallet.getKeystores().get(0);
        
        // Create receiver wallet with no passphrase
        Wallet receiverWallet = createWallet("", scriptType, RECEIVER_12_WORDS);
        Keystore receiverKeystore = receiverWallet.getKeystores().get(0);
        
        // Get payment codes from wallets
        PaymentCode senderPaymentCode = senderWallet.getPaymentCode();
        PaymentCode receiverPaymentCode = receiverWallet.getPaymentCode();
        
        // Verify payment codes are valid
        Assertions.assertNotNull(senderPaymentCode);
        Assertions.assertNotNull(receiverPaymentCode);
        
        // Create notification transaction
        Transaction notificationTx = createNotificationTransaction(
                senderWallet, senderKeystore, senderPaymentCode, receiverPaymentCode, scriptType);
        
        // Receiver processes notification transaction
        Wallet receiverNotificationWallet = receiverWallet.getNotificationWallet();
        PaymentCode recoveredPaymentCode = PaymentCode.getPaymentCode(
                notificationTx,
                receiverNotificationWallet.getKeystores().get(0));
        
        // Verify the recovered payment code matches the sender's
        Assertions.assertEquals(senderPaymentCode, recoveredPaymentCode);
        
        // Create BIP47 payment child wallets
        WalletPair childWallets = createChildWallets(
                senderWallet, receiverWallet, recoveredPaymentCode, receiverPaymentCode, 
                scriptType, "Sender", "Receiver");
        
        // Verify address derivation
        WalletNode[] nodes = verifyAddressDerivation(
                childWallets.senderChildWallet, childWallets.receiverChildWallet, 
                3, "Addresses");
        
        // Verify key access for receiver
        verifyKeyAccess(receiverKeystore, nodes[1], 3, "Public key mismatch");
    }
    
    /**
     * Tests BIP47 payment code functionality when both sender and receiver wallets use the same passphrase.
     * <p>
     * This test verifies that BIP47 payments work correctly when both wallets use identical BIP39 passphrases.
     * It isolates the effect of having passphrases in the seed derivation process without introducing the
     * complexity of different passphrase values. This serves as an important baseline for understanding how
     * passphrases affect BIP47 payment address derivation.
     *
     * @param scriptType The script type to use for the test (P2PKH or P2WPKH)
     * @see #scriptTypeProvider()
     */
    @ParameterizedTest
    @MethodSource("scriptTypeProvider")
    void testSamePassphrase(ScriptType scriptType) throws Exception {
        // Common passphrase used by both wallets
        final String sharedPassphrase = "test passphrase";
        
        // Create sender wallet with passphrase
        Wallet senderWallet = createWallet(sharedPassphrase, scriptType, SENDER_12_WORDS);
        Keystore senderKeystore = senderWallet.getKeystores().get(0);
        
        // Create receiver wallet with the same passphrase
        Wallet receiverWallet = createWallet(sharedPassphrase, scriptType, RECEIVER_12_WORDS);
        Keystore receiverKeystore = receiverWallet.getKeystores().get(0);
        
        // Get payment codes from wallets
        PaymentCode senderPaymentCode = senderWallet.getPaymentCode();
        PaymentCode receiverPaymentCode = receiverWallet.getPaymentCode();
        
        // Verify payment codes are valid
        Assertions.assertNotNull(senderPaymentCode);
        Assertions.assertNotNull(receiverPaymentCode);
        
        // Create notification transaction
        Transaction notificationTx = createNotificationTransaction(
                senderWallet, senderKeystore, senderPaymentCode, receiverPaymentCode, scriptType);
        
        // Receiver processes notification transaction
        Wallet receiverNotificationWallet = receiverWallet.getNotificationWallet();
        PaymentCode recoveredPaymentCode = PaymentCode.getPaymentCode(
                notificationTx,
                receiverNotificationWallet.getKeystores().get(0));
        
        // Verify the recovered payment code matches the sender's
        Assertions.assertEquals(senderPaymentCode, recoveredPaymentCode);
        
        // Create BIP47 payment child wallets
        WalletPair childWallets = createChildWallets(
                senderWallet, receiverWallet, recoveredPaymentCode, receiverPaymentCode, 
                scriptType, "Sender", "Receiver");
        
        // Verify address derivation
        WalletNode[] nodes = verifyAddressDerivation(
                childWallets.senderChildWallet, childWallets.receiverChildWallet, 
                3, "Addresses");
        
        // Verify key access for receiver
        verifyKeyAccess(receiverKeystore, nodes[1], 3, "Public key mismatch");
    }
    
    /**
     * Tests BIP47 payment code functionality when sender and receiver wallets have different passphrases.
     * <p>
     * This test addresses a scenario where payments could potentially be affected when wallets use different 
     * passphrases. Different passphrases lead to different seed derivations, which could impact how
     * payment addresses are derived between sender and receiver.
     * <p>
     * This test verifies that payment addresses are still correctly derived and matched despite the 
     * different passphrases.
     *
     * @param scriptType The script type to use for the test (P2PKH or P2WPKH)
     * @see #scriptTypeProvider()
     */
    @ParameterizedTest
    @MethodSource("scriptTypeProvider")
    void testDifferentPassphrases(ScriptType scriptType) throws Exception {
        // Create sender wallet with first passphrase
        final String senderPassphrase = "sender specific passphrase";
        Wallet senderWallet = createWallet(senderPassphrase, scriptType, SENDER_12_WORDS);
        Keystore senderKeystore = senderWallet.getKeystores().get(0);
        
        // Create receiver wallet with different passphrase
        final String receiverPassphrase = "completely different receiver passphrase";
        Wallet receiverWallet = createWallet(receiverPassphrase, scriptType, RECEIVER_12_WORDS);
        Keystore receiverKeystore = receiverWallet.getKeystores().get(0);
        
        // Get payment codes from wallets
        PaymentCode senderPaymentCode = senderWallet.getPaymentCode();
        PaymentCode receiverPaymentCode = receiverWallet.getPaymentCode();
        
        // Verify payment codes are valid
        Assertions.assertNotNull(senderPaymentCode);
        Assertions.assertNotNull(receiverPaymentCode);
        
        // Create notification transaction
        Transaction notificationTx = createNotificationTransaction(
                senderWallet, senderKeystore, senderPaymentCode, receiverPaymentCode, scriptType);
        
        // Receiver processes notification transaction
        Wallet receiverNotificationWallet = receiverWallet.getNotificationWallet();
        PaymentCode recoveredPaymentCode = PaymentCode.getPaymentCode(
                notificationTx,
                receiverNotificationWallet.getKeystores().get(0));
        
        // Verify the recovered payment code matches the sender's
        Assertions.assertEquals(senderPaymentCode, recoveredPaymentCode);
        
        // Create BIP47 payment child wallets
        WalletPair childWallets = createChildWallets(
                senderWallet, receiverWallet, recoveredPaymentCode, receiverPaymentCode, 
                scriptType, "Sender with Different Passphrase", "Receiver with Different Passphrase");
        
        // Verify address derivation
        WalletNode[] nodes = verifyAddressDerivation(
                childWallets.senderChildWallet, childWallets.receiverChildWallet, 
                3, "Addresses");
        
        // Verify key access for receiver
        verifyKeyAccess(receiverKeystore, nodes[1], 3, "Public key mismatch");
    }
    
    /**
     * Tests BIP47 payment code functionality when the sender wallet has a passphrase but the receiver doesn't.
     * <p>
     * This test covers an asymmetric configuration where only the sender uses a BIP39 passphrase.
     * It verifies that this configuration doesn't affect the correct derivation and matching of 
     * payment addresses between sender and receiver.
     *
     * @param scriptType The script type to use for the test (P2PKH or P2WPKH)
     * @see #scriptTypeProvider()
     */
    @ParameterizedTest
    @MethodSource("scriptTypeProvider")
    void testWithPassphraseToNoPassphrase(ScriptType scriptType) throws Exception {
        // Setup
        // Create sender wallet with a passphrase
        final String senderPassphrase = "sender passphrase";
        Wallet senderWallet = createWallet(senderPassphrase, scriptType, SENDER_12_WORDS);
        Keystore senderKeystore = senderWallet.getKeystores().get(0);
        
        // Create receiver wallet with no passphrase
        Wallet receiverWallet = createWallet("", scriptType, RECEIVER_12_WORDS);
        Keystore receiverKeystore = receiverWallet.getKeystores().get(0);
        
        // Get payment codes from wallets
        PaymentCode senderPaymentCode = senderWallet.getPaymentCode();
        PaymentCode receiverPaymentCode = receiverWallet.getPaymentCode();
        
        // Verify payment codes are valid
        Assertions.assertNotNull(senderPaymentCode, "Sender payment code should not be null");
        Assertions.assertNotNull(receiverPaymentCode, "Receiver payment code should not be null");
        
        // Action
        // Create notification transaction
        Transaction notificationTx = createNotificationTransaction(
                senderWallet, senderKeystore, senderPaymentCode, receiverPaymentCode, scriptType);
        
        // Receiver processes notification transaction
        Wallet receiverNotificationWallet = receiverWallet.getNotificationWallet();
        PaymentCode recoveredPaymentCode = PaymentCode.getPaymentCode(
                notificationTx,
                receiverNotificationWallet.getKeystores().get(0));
        
        // Create BIP47 payment child wallets
        WalletPair childWallets = createChildWallets(
                senderWallet, receiverWallet, recoveredPaymentCode, receiverPaymentCode, 
                scriptType, "Sender with Passphrase", "Receiver without Passphrase");
        
        // Verification
        // Verify the recovered payment code matches the sender's
        Assertions.assertEquals(senderPaymentCode, recoveredPaymentCode, 
                "Recovered payment code should match sender's payment code");
        
        // Verify address derivation
        WalletNode[] nodes = verifyAddressDerivation(
                childWallets.senderChildWallet, childWallets.receiverChildWallet, 
                3, "Addresses in passphrase->no passphrase scenario");
        
        // Verify key access for receiver
        verifyKeyAccess(receiverKeystore, nodes[1], 3, "Public key mismatch in passphrase->no passphrase scenario");
    }
    
    /**
     * Tests BIP47 payment code functionality when the sender wallet has no passphrase but the receiver does.
     * <p>
     * This test covers the opposite asymmetric configuration where only the receiver uses a BIP39 passphrase.
     * This test ensures that payment address derivation works correctly in this scenario, as
     * differences in passphrase usage shouldn't affect the ability to derive matching payment addresses.
     *
     * @param scriptType The script type to use for the test (P2PKH or P2WPKH)
     * @see #scriptTypeProvider()
     */
    @ParameterizedTest
    @MethodSource("scriptTypeProvider")
    void testNoPassphraseToWithPassphrase(ScriptType scriptType) throws Exception {
        // Setup
        // Create sender wallet with no passphrase
        Wallet senderWallet = createWallet("", scriptType, SENDER_12_WORDS);
        Keystore senderKeystore = senderWallet.getKeystores().get(0);
        
        // Create receiver wallet with a passphrase
        final String receiverPassphrase = "receiver passphrase";
        Wallet receiverWallet = createWallet(receiverPassphrase, scriptType, RECEIVER_12_WORDS);
        Keystore receiverKeystore = receiverWallet.getKeystores().get(0);
        
        // Get payment codes from wallets
        PaymentCode senderPaymentCode = senderWallet.getPaymentCode();
        PaymentCode receiverPaymentCode = receiverWallet.getPaymentCode();
        
        // Verify payment codes are valid
        Assertions.assertNotNull(senderPaymentCode, "Sender payment code should not be null");
        Assertions.assertNotNull(receiverPaymentCode, "Receiver payment code should not be null");
        
        // Action
        // Create notification transaction
        Transaction notificationTx = createNotificationTransaction(
                senderWallet, senderKeystore, senderPaymentCode, receiverPaymentCode, scriptType);
        
        // Receiver processes notification transaction
        Wallet receiverNotificationWallet = receiverWallet.getNotificationWallet();
        PaymentCode recoveredPaymentCode = PaymentCode.getPaymentCode(
                notificationTx,
                receiverNotificationWallet.getKeystores().get(0));
        
        // Create BIP47 payment child wallets
        WalletPair childWallets = createChildWallets(
                senderWallet, receiverWallet, recoveredPaymentCode, receiverPaymentCode, 
                scriptType, "Sender without Passphrase", "Receiver with Passphrase");
        
        // Verification
        // Verify the recovered payment code matches the sender's
        Assertions.assertEquals(senderPaymentCode, recoveredPaymentCode, 
                "Recovered payment code should match sender's payment code");
        
        // Verify address derivation
        WalletNode[] nodes = verifyAddressDerivation(
                childWallets.senderChildWallet, childWallets.receiverChildWallet, 
                3, "Addresses in no passphrase->passphrase scenario");
        
        // Verify key access for receiver
        verifyKeyAccess(receiverKeystore, nodes[1], 3, "Public key mismatch in no passphrase->passphrase scenario");
    }
    
    /**
     * Tests BIP47 payment code functionality with passphrases containing special characters.
     * <p>
     * This test ensures that special characters in passphrases (e.g., symbols, non-ASCII characters)
     * don't cause issues with BIP47 payment address derivation. Special characters can affect how
     * the passphrase is processed during key derivation, potentially causing compatibility issues.
     *
     * @param scriptType The script type to use for the test (P2PKH or P2WPKH)
     * @param specialPassphrase The passphrase containing special characters to test
     * @see #specialCharactersPassphraseProvider()
     */
    @ParameterizedTest
    @MethodSource("specialCharactersPassphraseProvider")
    void testSpecialCharactersInPassphrase(ScriptType scriptType, String specialPassphrase) throws Exception {
        // Setup
        // Create sender wallet with special character passphrase
        Wallet senderWallet = createWallet(specialPassphrase, scriptType, SENDER_12_WORDS);
        Keystore senderKeystore = senderWallet.getKeystores().get(0);
        
        // Create receiver wallet with the same special character passphrase
        Wallet receiverWallet = createWallet(specialPassphrase, scriptType, RECEIVER_12_WORDS);
        Keystore receiverKeystore = receiverWallet.getKeystores().get(0);
        
        // Get payment codes from wallets
        PaymentCode senderPaymentCode = senderWallet.getPaymentCode();
        PaymentCode receiverPaymentCode = receiverWallet.getPaymentCode();
        
        // Verify payment codes are valid
        Assertions.assertNotNull(senderPaymentCode, "Sender payment code should not be null");
        Assertions.assertNotNull(receiverPaymentCode, "Receiver payment code should not be null");
        
        // Action
        // Create notification transaction
        Transaction notificationTx = createNotificationTransaction(
                senderWallet, senderKeystore, senderPaymentCode, receiverPaymentCode, scriptType);
        
        // Receiver processes notification transaction
        Wallet receiverNotificationWallet = receiverWallet.getNotificationWallet();
        PaymentCode recoveredPaymentCode = PaymentCode.getPaymentCode(
                notificationTx,
                receiverNotificationWallet.getKeystores().get(0));
        
        // Create BIP47 payment child wallets
        WalletPair childWallets = createChildWallets(
                senderWallet, receiverWallet, recoveredPaymentCode, receiverPaymentCode, 
                scriptType, "Sender with Special Characters", "Receiver with Special Characters");
        
        // Verification
        // Verify the recovered payment code matches the sender's
        Assertions.assertEquals(senderPaymentCode, recoveredPaymentCode, 
                "Recovered payment code should match sender's payment code with special character passphrase");
        
        // Verify address derivation for multiple indices
        WalletNode[] nodes = verifyAddressDerivation(
                childWallets.senderChildWallet, childWallets.receiverChildWallet, 
                3, "Addresses with special character passphrase");
        
        // Verify key access for receiver
        verifyKeyAccess(receiverKeystore, nodes[1], 3, "Public key mismatch with special character passphrase");
    }
    
    /**
     * Tests the difference between empty string and null passphrases in BIP47 payment code functionality.
     * <p>
     * This test verifies that there's no functional difference between using an empty string ("") and
     * a null value as a passphrase. Both should be treated identically in terms of key derivation,
     * otherwise it could lead to incompatible payment addresses.
     *
     * @param scriptType The script type to use for the test (P2PKH or P2WPKH)
     * @see #scriptTypeProvider()
     */
    @ParameterizedTest
    @MethodSource("scriptTypeProvider")
    void testEmptyStringVsNullPassphrase(ScriptType scriptType) throws Exception {
        // Setup
        // Create first wallet with empty string passphrase
        Wallet emptyStringWallet = createWallet("", scriptType, SENDER_12_WORDS);
        Keystore emptyStringKeystore = emptyStringWallet.getKeystores().get(0);

        // Create second wallet with null passphrase 
        Wallet nullWallet = createWallet(null, scriptType, SENDER_12_WORDS);
        Keystore nullKeystore = nullWallet.getKeystores().get(0);
        
        // Action
        // Get payment codes from wallets
        PaymentCode emptyStringPaymentCode = emptyStringWallet.getPaymentCode();
        PaymentCode nullPaymentCode = nullWallet.getPaymentCode();

        // Verify payment codes are valid
        Assertions.assertNotNull(emptyStringPaymentCode, "Empty string payment code should not be null");
        Assertions.assertNotNull(nullPaymentCode, "Null payment code should not be null");

        // Generate addresses from both wallets
        Address emptyStringAddress = emptyStringWallet.getNode(KeyPurpose.RECEIVE).getAddress();
        Address nullAddress = nullWallet.getNode(KeyPurpose.RECEIVE).getAddress();
        
        // Verification
        // Compare payment codes - should be identical
        Assertions.assertEquals(emptyStringPaymentCode, nullPaymentCode, 
                "Payment codes should be identical regardless of empty string vs null passphrase");

        // Compare address derivation - should be identical
        Assertions.assertEquals(emptyStringAddress, nullAddress,
                "Addresses should be identical regardless of empty string vs null passphrase");

        // Compare multiple derived addresses
        WalletNode emptyStringNode = emptyStringWallet.getFreshNode(KeyPurpose.RECEIVE);
        WalletNode nullNode = nullWallet.getFreshNode(KeyPurpose.RECEIVE);
        for (int i = 0; i < 3; i++) {
            Assertions.assertEquals(emptyStringNode.getAddress(), nullNode.getAddress(),
                    "Derived address at index " + i + " should be identical");
            
            emptyStringNode = emptyStringWallet.getFreshNode(KeyPurpose.RECEIVE, emptyStringNode);
            nullNode = nullWallet.getFreshNode(KeyPurpose.RECEIVE, nullNode);
        }

        // Compare key derivation - should be identical
        ECKey emptyStringKey = emptyStringKeystore.getKey(emptyStringWallet.getNode(KeyPurpose.RECEIVE));
        ECKey nullKey = nullKeystore.getKey(nullWallet.getNode(KeyPurpose.RECEIVE));
        Assertions.assertArrayEquals(emptyStringKey.getPubKey(), nullKey.getPubKey(),
                "Public keys should be identical regardless of empty string vs null passphrase");
    }
    
    /**
     * Tests BIP47 payment code functionality with different mnemonic word counts and passphrase presence.
     * <p>
     * This test verifies that BIP47 payments work correctly with both 12-word and 24-word mnemonics,
     * with and without passphrases, across different script types. The word count affects the entropy 
     * of the seed, which could potentially interact with passphrase handling in ways that affect 
     * payment address derivation.
     *
     * @param mnemonic The mnemonic words to use for the wallet
     * @param hasPassphrase Whether to include a passphrase or not
     * @param scriptType The script type to use for the test (P2PKH or P2WPKH)
     * @see #mnemonicConfigurationsProvider()
     */
    @ParameterizedTest
    @MethodSource("mnemonicConfigurationsProvider")
    void testPaymentCodeWithVariousMnemonicConfigurations(
            List<String> mnemonic, boolean hasPassphrase, ScriptType scriptType) throws Exception {
        // Setup
        // Create wallets with provided mnemonic and passphrase configuration
        String passphrase = hasPassphrase ? "test passphrase" : "";
        Wallet senderWallet = createWallet(passphrase, scriptType, mnemonic);
        Keystore senderKeystore = senderWallet.getKeystores().get(0);

        // Create receiver wallet with the same mnemonic length but different words
        List<String> receiverMnemonic = mnemonic.size() == 12 ? RECEIVER_12_WORDS : RECEIVER_24_WORDS;
        Wallet receiverWallet = createWallet(passphrase, scriptType, receiverMnemonic);
        Keystore receiverKeystore = receiverWallet.getKeystores().get(0);
        
        // Action
        // Get payment codes from wallets
        PaymentCode senderPaymentCode = senderWallet.getPaymentCode();
        PaymentCode receiverPaymentCode = receiverWallet.getPaymentCode();

        // Verify payment codes are valid
        Assertions.assertNotNull(senderPaymentCode, "Sender payment code should not be null");
        Assertions.assertNotNull(receiverPaymentCode, "Receiver payment code should not be null");

        // Create notification transaction
        Transaction notificationTx = createNotificationTransaction(
                senderWallet, senderKeystore, senderPaymentCode, receiverPaymentCode, scriptType);

        // Receiver processes notification transaction
        Wallet receiverNotificationWallet = receiverWallet.getNotificationWallet();
        PaymentCode recoveredPaymentCode = PaymentCode.getPaymentCode(
                notificationTx,
                receiverNotificationWallet.getKeystores().get(0));
        
        // Verification
        // Create descriptive label reflecting the configuration
        String configDescription = mnemonic.size() + "-word mnemonic, " + 
                                  (hasPassphrase ? "with" : "without") + " passphrase, " +
                                  scriptType.name();

        // Verify the recovered payment code matches the sender's
        Assertions.assertEquals(senderPaymentCode, recoveredPaymentCode, 
                "Recovered payment code should match sender's with " + configDescription);

        // Create BIP47 payment child wallets
        WalletPair childWallets = createChildWallets(
                senderWallet, receiverWallet, recoveredPaymentCode, receiverPaymentCode, 
                scriptType, "Sender " + configDescription, "Receiver " + configDescription);

        // Verify address derivation
        WalletNode[] nodes = verifyAddressDerivation(
                childWallets.senderChildWallet, childWallets.receiverChildWallet, 
                3, "Addresses with " + configDescription);

        // Verify key access
        verifyKeyAccess(receiverKeystore, nodes[1], 3, "Public key mismatch with " + configDescription);
    }
    
    /**
     * Tests wallet recreation when changing an existing passphrase.
     * <p>
     * This test verifies that when a wallet is recreated with a different passphrase than 
     * its original one, the payment codes and derived addresses change accordingly. This ensures
     * that changing a passphrase provides proper cryptographic isolation from the previous state,
     * while still maintaining proper BIP47 functionality within the new passphrase environment.
     *
     * @param scriptType The script type to use for the test (P2PKH or P2WPKH)
     * @throws Exception If there's an error during wallet creation or transaction processing
     */
    @ParameterizedTest
    @MethodSource("scriptTypeProvider")
    void testWalletRecreation_ChangingPassphrase(ScriptType scriptType) throws Exception {
        // Setup - Initial wallet with original passphrase
        String originalPassphrase = "original passphrase";
        String newPassphrase = "new passphrase";
        
        // Create original wallets with initial passphrase
        Wallet originalSenderWallet = createWallet(originalPassphrase, scriptType, SENDER_12_WORDS);
        Keystore originalSenderKeystore = originalSenderWallet.getKeystores().get(0);
        
        Wallet originalReceiverWallet = createWallet(originalPassphrase, scriptType, RECEIVER_12_WORDS);
        Keystore originalReceiverKeystore = originalReceiverWallet.getKeystores().get(0);
        
        // Get payment codes from original wallets
        PaymentCode originalSenderPaymentCode = originalSenderWallet.getPaymentCode();
        PaymentCode originalReceiverPaymentCode = originalReceiverWallet.getPaymentCode();
        
        // Create notification transaction with original wallets
        Transaction originalNotificationTx = createNotificationTransaction(
                originalSenderWallet, 
                originalSenderKeystore, 
                originalSenderPaymentCode, 
                originalReceiverPaymentCode, 
                scriptType);
        
        // Process original notification transaction
        Wallet originalReceiverNotificationWallet = originalReceiverWallet.getNotificationWallet();
        PaymentCode originalRecoveredPaymentCode = PaymentCode.getPaymentCode(
                originalNotificationTx,
                originalReceiverNotificationWallet.getKeystores().get(0));
        
        // Create BIP47 payment child wallets with original configuration
        WalletPair originalChildWallets = createChildWallets(
                originalSenderWallet, 
                originalReceiverWallet, 
                originalRecoveredPaymentCode, 
                originalReceiverPaymentCode, 
                scriptType, 
                "Original Sender", 
                "Original Receiver");
        
        // Verify address derivation with original wallets
        WalletNode[] originalNodes = verifyAddressDerivation(
                originalChildWallets.senderChildWallet, 
                originalChildWallets.receiverChildWallet, 
                3, 
                "Original addresses");
        
        // Action - Recreate wallets with new passphrase
        Wallet recreatedSenderWallet = createWallet(newPassphrase, scriptType, SENDER_12_WORDS);
        Keystore recreatedSenderKeystore = recreatedSenderWallet.getKeystores().get(0);
        
        Wallet recreatedReceiverWallet = createWallet(newPassphrase, scriptType, RECEIVER_12_WORDS);
        Keystore recreatedReceiverKeystore = recreatedReceiverWallet.getKeystores().get(0);
        
        // Get payment codes from recreated wallets
        PaymentCode recreatedSenderPaymentCode = recreatedSenderWallet.getPaymentCode();
        PaymentCode recreatedReceiverPaymentCode = recreatedReceiverWallet.getPaymentCode();
        
        // Create notification transaction with recreated wallets
        Transaction recreatedNotificationTx = createNotificationTransaction(
                recreatedSenderWallet, 
                recreatedSenderKeystore, 
                recreatedSenderPaymentCode, 
                recreatedReceiverPaymentCode, 
                scriptType);
        
        // Process recreated notification transaction
        Wallet recreatedReceiverNotificationWallet = recreatedReceiverWallet.getNotificationWallet();
        PaymentCode recreatedRecoveredPaymentCode = PaymentCode.getPaymentCode(
                recreatedNotificationTx,
                recreatedReceiverNotificationWallet.getKeystores().get(0));
        
        // Create BIP47 payment child wallets with recreated configuration
        WalletPair recreatedChildWallets = createChildWallets(
                recreatedSenderWallet, 
                recreatedReceiverWallet, 
                recreatedRecoveredPaymentCode, 
                recreatedReceiverPaymentCode, 
                scriptType, 
                "Recreated Sender", 
                "Recreated Receiver");
        
        // Verification - Payment codes must change when passphrase changes
        Assertions.assertNotEquals(originalSenderPaymentCode, recreatedSenderPaymentCode,
                "Sender payment code must change after changing passphrase as key derivation depends on passphrase");
        Assertions.assertNotEquals(originalReceiverPaymentCode, recreatedReceiverPaymentCode,
                "Receiver payment code must change after changing passphrase as key derivation depends on passphrase");
        
        // Verify that address derivation works within the recreated wallets
        WalletNode[] recreatedNodes = verifyAddressDerivation(
                recreatedChildWallets.senderChildWallet, 
                recreatedChildWallets.receiverChildWallet, 
                3, 
                "Recreated addresses");
        
        // Verify key access for recreated wallet
        verifyKeyAccess(recreatedReceiverKeystore, recreatedNodes[1], 3, 
                "Recreated key mismatch");
                
        // Cross wallet verification - addresses from different passphrase environments must differ
        Address originalAddress = originalNodes[0].getAddress();
        Address recreatedAddress = recreatedNodes[0].getAddress();
        
        Assertions.assertNotEquals(originalAddress, recreatedAddress,
                "Addresses must differ after changing passphrase as they're derived from different seeds");
        
        // Verify that original payment code is incompatible with recreated wallet environment
        Wallet crossWallet = recreatedSenderWallet.addChildWallet(
                originalReceiverPaymentCode,
                scriptType,
                "Cross Wallet Test");
                
        // Generate addresses from both wallets
        WalletNode originalNode = originalChildWallets.senderChildWallet.getFreshNode(KeyPurpose.SEND);
        WalletNode crossNode = crossWallet.getFreshNode(KeyPurpose.SEND);
        
        // Addresses must be different
        Assertions.assertNotEquals(originalNode.getAddress(), crossNode.getAddress(),
                "Cross wallet addresses must differ after changing passphrase as they use different wallet seeds");
    }
    
    /**
     * Tests wallet recreation when adding a passphrase where none existed before.
     * <p>
     * This test verifies that when a wallet originally created without a passphrase is recreated with
     * a new passphrase, the payment codes and derived addresses change appropriately. This ensures that
     * adding a passphrase provides cryptographic isolation from the previous state, which is important
     * for security and privacy in BIP47 payment channels.
     *
     * @param scriptType The script type to use for the test (P2PKH or P2WPKH)
     * @throws Exception If there's an error during wallet creation or transaction processing
     */
    @ParameterizedTest
    @MethodSource("scriptTypeProvider")
    void testWalletRecreation_AddingPassphrase(ScriptType scriptType) throws Exception {
        // Setup - Initial wallet with no passphrase
        String originalPassphrase = ""; // No passphrase initially
        String newPassphrase = "new passphrase";
        
        // Create original wallets with no passphrase
        Wallet originalSenderWallet = createWallet(originalPassphrase, scriptType, SENDER_12_WORDS);
        Keystore originalSenderKeystore = originalSenderWallet.getKeystores().get(0);
        
        Wallet originalReceiverWallet = createWallet(originalPassphrase, scriptType, RECEIVER_12_WORDS);
        Keystore originalReceiverKeystore = originalReceiverWallet.getKeystores().get(0);
        
        // Get payment codes from original wallets
        PaymentCode originalSenderPaymentCode = originalSenderWallet.getPaymentCode();
        PaymentCode originalReceiverPaymentCode = originalReceiverWallet.getPaymentCode();
        
        // Create notification transaction with original wallets
        Transaction originalNotificationTx = createNotificationTransaction(
                originalSenderWallet, 
                originalSenderKeystore, 
                originalSenderPaymentCode, 
                originalReceiverPaymentCode, 
                scriptType);
        
        // Process original notification transaction
        Wallet originalReceiverNotificationWallet = originalReceiverWallet.getNotificationWallet();
        PaymentCode originalRecoveredPaymentCode = PaymentCode.getPaymentCode(
                originalNotificationTx,
                originalReceiverNotificationWallet.getKeystores().get(0));
        
        // Create BIP47 payment child wallets with original configuration
        WalletPair originalChildWallets = createChildWallets(
                originalSenderWallet, 
                originalReceiverWallet, 
                originalRecoveredPaymentCode, 
                originalReceiverPaymentCode, 
                scriptType, 
                "Original Sender", 
                "Original Receiver");
        
        // Verify address derivation with original wallets
        WalletNode[] originalNodes = verifyAddressDerivation(
                originalChildWallets.senderChildWallet, 
                originalChildWallets.receiverChildWallet, 
                3, 
                "Original addresses");
        
        // Action - Recreate wallets with added passphrase
        Wallet recreatedSenderWallet = createWallet(newPassphrase, scriptType, SENDER_12_WORDS);
        Keystore recreatedSenderKeystore = recreatedSenderWallet.getKeystores().get(0);
        
        Wallet recreatedReceiverWallet = createWallet(newPassphrase, scriptType, RECEIVER_12_WORDS);
        Keystore recreatedReceiverKeystore = recreatedReceiverWallet.getKeystores().get(0);
        
        // Get payment codes from recreated wallets
        PaymentCode recreatedSenderPaymentCode = recreatedSenderWallet.getPaymentCode();
        PaymentCode recreatedReceiverPaymentCode = recreatedReceiverWallet.getPaymentCode();
        
        // Create notification transaction with recreated wallets
        Transaction recreatedNotificationTx = createNotificationTransaction(
                recreatedSenderWallet, 
                recreatedSenderKeystore, 
                recreatedSenderPaymentCode, 
                recreatedReceiverPaymentCode, 
                scriptType);
        
        // Process recreated notification transaction
        Wallet recreatedReceiverNotificationWallet = recreatedReceiverWallet.getNotificationWallet();
        PaymentCode recreatedRecoveredPaymentCode = PaymentCode.getPaymentCode(
                recreatedNotificationTx,
                recreatedReceiverNotificationWallet.getKeystores().get(0));
        
        // Create BIP47 payment child wallets with recreated configuration
        WalletPair recreatedChildWallets = createChildWallets(
                recreatedSenderWallet, 
                recreatedReceiverWallet, 
                recreatedRecoveredPaymentCode, 
                recreatedReceiverPaymentCode, 
                scriptType, 
                "Recreated Sender", 
                "Recreated Receiver");
        
        // Verification - Payment codes must change when passphrase is added
        Assertions.assertNotEquals(originalSenderPaymentCode, recreatedSenderPaymentCode,
                "Sender payment code must change after adding passphrase as key derivation depends on passphrase");
        Assertions.assertNotEquals(originalReceiverPaymentCode, recreatedReceiverPaymentCode,
                "Receiver payment code must change after adding passphrase as key derivation depends on passphrase");
        
        // Verify that address derivation works within the recreated wallets
        WalletNode[] recreatedNodes = verifyAddressDerivation(
                recreatedChildWallets.senderChildWallet, 
                recreatedChildWallets.receiverChildWallet, 
                3, 
                "Recreated addresses");
        
        // Verify key access for recreated wallet
        verifyKeyAccess(recreatedReceiverKeystore, recreatedNodes[1], 3, 
                "Recreated key mismatch");
                
        // Cross wallet verification - addresses from different passphrase environments must differ
        Address originalAddress = originalNodes[0].getAddress();
        Address recreatedAddress = recreatedNodes[0].getAddress();
        
        Assertions.assertNotEquals(originalAddress, recreatedAddress,
                "Addresses must differ after adding passphrase as they're derived from different seeds");
        
        // Verify that original payment code is incompatible with recreated wallet environment
        Wallet crossWallet = recreatedSenderWallet.addChildWallet(
                originalReceiverPaymentCode,
                scriptType,
                "Cross Wallet Test");
                
        // Generate addresses from both wallets
        WalletNode originalNode = originalChildWallets.senderChildWallet.getFreshNode(KeyPurpose.SEND);
        WalletNode crossNode = crossWallet.getFreshNode(KeyPurpose.SEND);
        
        // Addresses must be different
        Assertions.assertNotEquals(originalNode.getAddress(), crossNode.getAddress(),
                "Cross wallet addresses must differ after adding passphrase as they use different wallet seeds");
    }
    
    /**
     * Tests wallet recreation when removing an existing passphrase.
     * <p>
     * This test verifies that when a wallet originally created with a passphrase is recreated
     * without one, the payment codes and derived addresses change. This ensures that removing
     * a passphrase provides cryptographic isolation from the previous state, which affects
     * all derived keys and addresses in BIP47 payment channels.
     *
     * @param scriptType The script type to use for the test (P2PKH or P2WPKH)
     * @throws Exception If there's an error during wallet creation or transaction processing
     */
    @ParameterizedTest
    @MethodSource("scriptTypeProvider")
    void testWalletRecreation_RemovingPassphrase(ScriptType scriptType) throws Exception {
        // Setup - Initial wallet with passphrase
        String originalPassphrase = "original passphrase";
        String newPassphrase = ""; // Removed passphrase (empty string)
        
        // Create original wallets with passphrase
        Wallet originalSenderWallet = createWallet(originalPassphrase, scriptType, SENDER_12_WORDS);
        Keystore originalSenderKeystore = originalSenderWallet.getKeystores().get(0);
        
        Wallet originalReceiverWallet = createWallet(originalPassphrase, scriptType, RECEIVER_12_WORDS);
        Keystore originalReceiverKeystore = originalReceiverWallet.getKeystores().get(0);
        
        // Get payment codes from original wallets
        PaymentCode originalSenderPaymentCode = originalSenderWallet.getPaymentCode();
        PaymentCode originalReceiverPaymentCode = originalReceiverWallet.getPaymentCode();
        
        // Create notification transaction with original wallets
        Transaction originalNotificationTx = createNotificationTransaction(
                originalSenderWallet, 
                originalSenderKeystore, 
                originalSenderPaymentCode, 
                originalReceiverPaymentCode, 
                scriptType);
        
        // Process original notification transaction
        Wallet originalReceiverNotificationWallet = originalReceiverWallet.getNotificationWallet();
        PaymentCode originalRecoveredPaymentCode = PaymentCode.getPaymentCode(
                originalNotificationTx,
                originalReceiverNotificationWallet.getKeystores().get(0));
        
        // Create BIP47 payment child wallets with original configuration
        WalletPair originalChildWallets = createChildWallets(
                originalSenderWallet, 
                originalReceiverWallet, 
                originalRecoveredPaymentCode, 
                originalReceiverPaymentCode, 
                scriptType, 
                "Original Sender", 
                "Original Receiver");
        
        // Verify address derivation with original wallets
        WalletNode[] originalNodes = verifyAddressDerivation(
                originalChildWallets.senderChildWallet, 
                originalChildWallets.receiverChildWallet, 
                3, 
                "Original addresses");
        
        // Action - Recreate wallets without passphrase
        Wallet recreatedSenderWallet = createWallet(newPassphrase, scriptType, SENDER_12_WORDS);
        Keystore recreatedSenderKeystore = recreatedSenderWallet.getKeystores().get(0);
        
        Wallet recreatedReceiverWallet = createWallet(newPassphrase, scriptType, RECEIVER_12_WORDS);
        Keystore recreatedReceiverKeystore = recreatedReceiverWallet.getKeystores().get(0);
        
        // Get payment codes from recreated wallets
        PaymentCode recreatedSenderPaymentCode = recreatedSenderWallet.getPaymentCode();
        PaymentCode recreatedReceiverPaymentCode = recreatedReceiverWallet.getPaymentCode();
        
        // Create notification transaction with recreated wallets
        Transaction recreatedNotificationTx = createNotificationTransaction(
                recreatedSenderWallet, 
                recreatedSenderKeystore, 
                recreatedSenderPaymentCode, 
                recreatedReceiverPaymentCode, 
                scriptType);
        
        // Process recreated notification transaction
        Wallet recreatedReceiverNotificationWallet = recreatedReceiverWallet.getNotificationWallet();
        PaymentCode recreatedRecoveredPaymentCode = PaymentCode.getPaymentCode(
                recreatedNotificationTx,
                recreatedReceiverNotificationWallet.getKeystores().get(0));
        
        // Create BIP47 payment child wallets with recreated configuration
        WalletPair recreatedChildWallets = createChildWallets(
                recreatedSenderWallet, 
                recreatedReceiverWallet, 
                recreatedRecoveredPaymentCode, 
                recreatedReceiverPaymentCode, 
                scriptType, 
                "Recreated Sender", 
                "Recreated Receiver");
        
        // Verification - Payment codes must change when passphrase is removed
        Assertions.assertNotEquals(originalSenderPaymentCode, recreatedSenderPaymentCode,
                "Sender payment code must change after removing passphrase as key derivation depends on passphrase");
        Assertions.assertNotEquals(originalReceiverPaymentCode, recreatedReceiverPaymentCode,
                "Receiver payment code must change after removing passphrase as key derivation depends on passphrase");
        
        // Verify that address derivation works within the recreated wallets
        WalletNode[] recreatedNodes = verifyAddressDerivation(
                recreatedChildWallets.senderChildWallet, 
                recreatedChildWallets.receiverChildWallet, 
                3, 
                "Recreated addresses");
        
        // Verify key access for recreated wallet
        verifyKeyAccess(recreatedReceiverKeystore, recreatedNodes[1], 3, 
                "Recreated key mismatch");
                
        // Cross wallet verification - addresses from different passphrase environments must differ
        Address originalAddress = originalNodes[0].getAddress();
        Address recreatedAddress = recreatedNodes[0].getAddress();
        
        Assertions.assertNotEquals(originalAddress, recreatedAddress,
                "Addresses must differ after removing passphrase as they're derived from different seeds");
        
        // Verify that original payment code is incompatible with recreated wallet environment
        Wallet crossWallet = recreatedSenderWallet.addChildWallet(
                originalReceiverPaymentCode,
                scriptType,
                "Cross Wallet Test");
                
        // Generate addresses from both wallets
        WalletNode originalNode = originalChildWallets.senderChildWallet.getFreshNode(KeyPurpose.SEND);
        WalletNode crossNode = crossWallet.getFreshNode(KeyPurpose.SEND);
        
        // Addresses must be different
        Assertions.assertNotEquals(originalNode.getAddress(), crossNode.getAddress(),
                "Cross wallet addresses must differ after removing passphrase as they use different wallet seeds");
    }
    
    /**
     * Tests BIP47 payment code functionality with different payment address indices after a passphrase change.
     * <p>
     * This test verifies the consistency of payment addresses across different indices (0, 10, 100)
     * after a passphrase change. BIP47 allows for an unlimited number of payment addresses to be derived,
     * and this test ensures that address derivation remains consistent or is properly detected as
     * inconsistent at different indices when passphrases change.
     *
     * @param index The payment address index to test
     * @throws Exception If there's an error during wallet creation or transaction processing
     */
    @ParameterizedTest
    @ValueSource(ints = {0, 10, 100})
    void testPaymentAddressIndex_PassphraseChange(int index) throws Exception {
        // Setup - Script type doesn't affect index-related behavior, so we use P2PKH for simplicity
        ScriptType scriptType = ScriptType.P2PKH;
        
        // Create wallets with original passphrase
        String originalPassphrase = "original passphrase";
        Wallet originalSenderWallet = createWallet(originalPassphrase, scriptType, SENDER_12_WORDS);
        Keystore originalSenderKeystore = originalSenderWallet.getKeystores().get(0);
        
        Wallet originalReceiverWallet = createWallet(originalPassphrase, scriptType, RECEIVER_12_WORDS);
        Keystore originalReceiverKeystore = originalReceiverWallet.getKeystores().get(0);
        
        // Get payment codes from original wallets
        PaymentCode originalSenderPaymentCode = originalSenderWallet.getPaymentCode();
        PaymentCode originalReceiverPaymentCode = originalReceiverWallet.getPaymentCode();
        
        // Create notification transaction with original wallets
        Transaction originalNotificationTx = createNotificationTransaction(
                originalSenderWallet, 
                originalSenderKeystore, 
                originalSenderPaymentCode, 
                originalReceiverPaymentCode, 
                scriptType);
        
        // Process original notification transaction
        Wallet originalReceiverNotificationWallet = originalReceiverWallet.getNotificationWallet();
        PaymentCode originalRecoveredPaymentCode = PaymentCode.getPaymentCode(
                originalNotificationTx,
                originalReceiverNotificationWallet.getKeystores().get(0));
        
        // Create BIP47 payment child wallets with original configuration
        WalletPair originalChildWallets = createChildWallets(
                originalSenderWallet, 
                originalReceiverWallet, 
                originalRecoveredPaymentCode, 
                originalReceiverPaymentCode, 
                scriptType, 
                "Original Sender", 
                "Original Receiver");
        
        // Create wallets with changed passphrase
        String newPassphrase = "new passphrase";
        Wallet changedSenderWallet = createWallet(newPassphrase, scriptType, SENDER_12_WORDS);
        Keystore changedSenderKeystore = changedSenderWallet.getKeystores().get(0);
        
        Wallet changedReceiverWallet = createWallet(newPassphrase, scriptType, RECEIVER_12_WORDS);
        Keystore changedReceiverKeystore = changedReceiverWallet.getKeystores().get(0);
        
        // Get payment codes from changed wallets
        PaymentCode changedSenderPaymentCode = changedSenderWallet.getPaymentCode();
        PaymentCode changedReceiverPaymentCode = changedReceiverWallet.getPaymentCode();
        
        // Create notification transaction with changed wallets
        Transaction changedNotificationTx = createNotificationTransaction(
                changedSenderWallet, 
                changedSenderKeystore, 
                changedSenderPaymentCode, 
                changedReceiverPaymentCode, 
                scriptType);
        
        // Process changed notification transaction
        Wallet changedReceiverNotificationWallet = changedReceiverWallet.getNotificationWallet();
        PaymentCode changedRecoveredPaymentCode = PaymentCode.getPaymentCode(
                changedNotificationTx,
                changedReceiverNotificationWallet.getKeystores().get(0));
        
        // Create BIP47 payment child wallets with changed configuration
        WalletPair changedChildWallets = createChildWallets(
                changedSenderWallet, 
                changedReceiverWallet, 
                changedRecoveredPaymentCode, 
                changedReceiverPaymentCode, 
                scriptType, 
                "Changed Sender", 
                "Changed Receiver");
        
        // Action - Derive addresses at the specified index
        // Get the nodes at the specified index for original wallets
        WalletNode originalSendNode = getNodeAtIndex(originalChildWallets.senderChildWallet, KeyPurpose.SEND, index);
        WalletNode originalReceiveNode = getNodeAtIndex(originalChildWallets.receiverChildWallet, KeyPurpose.RECEIVE, index);
        
        // Get the nodes at the specified index for changed wallets
        WalletNode changedSendNode = getNodeAtIndex(changedChildWallets.senderChildWallet, KeyPurpose.SEND, index);
        WalletNode changedReceiveNode = getNodeAtIndex(changedChildWallets.receiverChildWallet, KeyPurpose.RECEIVE, index);
        
        // Get addresses from the nodes
        Address originalSendAddress = originalSendNode.getAddress();
        Address originalReceiveAddress = originalReceiveNode.getAddress();
        Address changedSendAddress = changedSendNode.getAddress();
        Address changedReceiveAddress = changedReceiveNode.getAddress();
        
        // Verification
        // 1. Addresses must match within each passphrase environment
        Assertions.assertEquals(originalSendAddress, originalReceiveAddress,
                String.format("Original wallet addresses at index %d must match within the same passphrase environment", index));
        
        Assertions.assertEquals(changedSendAddress, changedReceiveAddress,
                String.format("Changed wallet addresses at index %d must match within the same passphrase environment", index));
        
        // 2. Addresses must differ between original and changed passphrase environments
        Assertions.assertNotEquals(originalSendAddress, changedSendAddress,
                String.format("Addresses at index %d must differ between different passphrase environments", index));
        
        // 3. Verify key derivation works correctly at this index in both environments
        ECKey originalPrivKey = originalReceiverKeystore.getKey(originalReceiveNode);
        ECKey originalPubKey = originalReceiverKeystore.getPubKey(originalReceiveNode);
        Assertions.assertArrayEquals(originalPrivKey.getPubKey(), originalPubKey.getPubKey(),
                String.format("Original wallet key derivation at index %d should be consistent", index));
        
        ECKey changedPrivKey = changedReceiverKeystore.getKey(changedReceiveNode);
        ECKey changedPubKey = changedReceiverKeystore.getPubKey(changedReceiveNode);
        Assertions.assertArrayEquals(changedPrivKey.getPubKey(), changedPubKey.getPubKey(),
                String.format("Changed wallet key derivation at index %d should be consistent", index));
    }
    
    /**
     * Tests notification transaction processing with different passphrases.
     * <p>
     * This test verifies that the notification transaction (the first transaction sent in BIP47 to
     * establish a payment channel) is correctly processed even when sender and receiver have different
     * passphrases. The notification transaction contains a blinded payment code that must be correctly
     * unblinded by the receiver.
     *
     * @param scriptType The script type to use for the test (P2PKH or P2WPKH)
     * @see #scriptTypeProvider()
     */
    @ParameterizedTest
    @MethodSource("scriptTypeProvider")
    void testNotificationTransaction_DifferentPassphrases(ScriptType scriptType) {
        // Test implementation will be added later
    }
    
    /**
     * Tests the scenario where a passphrase is changed between generating a notification transaction
     * and receiving/interpreting it.
     * <p>
     * This test simulates a critical edge case that could explain the GitHub issue #1642: a user
     * changes their passphrase after someone has already sent them a notification transaction but
     * before they've processed it. This could cause the notification transaction to be unreadable
     * or the derived payment addresses to be different from what the sender expects.
     * <p>
     * This test verifies whether such a change is correctly handled or if it leads to "missing" payments.
     *
     * @param scriptType The script type to use for the test (P2PKH or P2WPKH)
     * @see #scriptTypeProvider()
     */
    @ParameterizedTest
    @MethodSource("scriptTypeProvider")
    void testNotificationTransactionProcessingAfterPassphraseChange(ScriptType scriptType) {
        // Test implementation will be added later
    }
    
    /**
     * Tests BIP47 payment code functionality with extremely long passphrases.
     * <p>
     * This test ensures that very long passphrases (e.g., multiple sentences or paragraphs)
     * don't cause issues with payment address derivation. Long passphrases might stress
     * string handling, hashing functions, and memory usage in ways that could potentially
     * cause address derivation problems.
     *
     * @param scriptType The script type to use for the test (P2PKH or P2WPKH)
     * @see #scriptTypeProvider()
     */
    @ParameterizedTest
    @MethodSource("scriptTypeProvider")
    void testLongPassphrase(ScriptType scriptType) throws Exception {
        // Setup
        // Create long passphrase (multiple paragraphs)
        String longPassphrase = generateLongPassphrase();

        // Create sender wallet with long passphrase
        Wallet senderWallet = createWallet(longPassphrase, scriptType, SENDER_12_WORDS);
        Keystore senderKeystore = senderWallet.getKeystores().get(0);

        // Create receiver wallet with same long passphrase
        Wallet receiverWallet = createWallet(longPassphrase, scriptType, RECEIVER_12_WORDS);
        Keystore receiverKeystore = receiverWallet.getKeystores().get(0);
        
        // Action
        // Get payment codes from wallets
        PaymentCode senderPaymentCode = senderWallet.getPaymentCode();
        PaymentCode receiverPaymentCode = receiverWallet.getPaymentCode();

        // Verify payment codes are valid
        Assertions.assertNotNull(senderPaymentCode, "Sender payment code should not be null");
        Assertions.assertNotNull(receiverPaymentCode, "Receiver payment code should not be null");

        // Create notification transaction
        Transaction notificationTx = createNotificationTransaction(
                senderWallet, senderKeystore, senderPaymentCode, receiverPaymentCode, scriptType);

        // Receiver processes notification transaction
        Wallet receiverNotificationWallet = receiverWallet.getNotificationWallet();
        PaymentCode recoveredPaymentCode = PaymentCode.getPaymentCode(
                notificationTx,
                receiverNotificationWallet.getKeystores().get(0));
        
        // Verification
        // Verify the recovered payment code matches the sender's
        Assertions.assertEquals(senderPaymentCode, recoveredPaymentCode, 
                "Recovered payment code should match sender's payment code with long passphrase");

        // Create BIP47 payment child wallets
        WalletPair childWallets = createChildWallets(
                senderWallet, receiverWallet, recoveredPaymentCode, receiverPaymentCode, 
                scriptType, "Sender with Long Passphrase", "Receiver with Long Passphrase");

        // Verify address derivation for multiple indices
        WalletNode[] nodes = verifyAddressDerivation(
                childWallets.senderChildWallet, childWallets.receiverChildWallet, 
                3, "Addresses with long passphrase");

        // Verify key access for receiver
        verifyKeyAccess(receiverKeystore, nodes[1], 3, "Public key mismatch with long passphrase");
    }
    
    /**
     * Provider for script types used in parameterized tests.
     * 
     * @return A stream of ScriptType values (P2PKH and P2WPKH)
     */
    static Stream<ScriptType> scriptTypeProvider() {
        return Stream.of(ScriptType.P2PKH, ScriptType.P2WPKH);
    }
    
    /**
     * Provider for mnemonic configurations used in parameterized tests.
     * 
     * @return A stream of arguments containing mnemonic word lists, passphrase presence, and script type
     */
    static Stream<Arguments> mnemonicConfigurationsProvider() {
        return Stream.of(
            Arguments.of(SENDER_12_WORDS, false, ScriptType.P2PKH),
            Arguments.of(SENDER_12_WORDS, true, ScriptType.P2PKH),
            Arguments.of(SENDER_24_WORDS, false, ScriptType.P2PKH),
            Arguments.of(SENDER_24_WORDS, true, ScriptType.P2PKH),
            Arguments.of(SENDER_12_WORDS, false, ScriptType.P2WPKH),
            Arguments.of(SENDER_12_WORDS, true, ScriptType.P2WPKH),
            Arguments.of(SENDER_24_WORDS, false, ScriptType.P2WPKH),
            Arguments.of(SENDER_24_WORDS, true, ScriptType.P2WPKH)
        );
    }
    
    /**
     * Provider for special character passphrases used in parameterized tests.
     * Tests a variety of special characters including symbols, Unicode characters, and emojis
     * with both P2PKH and P2WPKH script types.
     * 
     * @return A stream of arguments containing script type and special character passphrase
     */
    static Stream<Arguments> specialCharactersPassphraseProvider() {
        List<ScriptType> scriptTypes = List.of(ScriptType.P2PKH, ScriptType.P2WPKH);
        List<String> specialPassphrases = List.of(
            "password!@#$%^&*()",     // Basic special characters
            "unicode¥€£¥€",           // Unicode symbols directly in the string
            "emojis😀👍"              // Emojis directly in the string
        );
        
        return scriptTypes.stream()
               .flatMap(scriptType -> 
               specialPassphrases.stream().map(passphrase -> Arguments.of(scriptType, passphrase))
               );
    }

    /**
     * Gets a wallet node at a specific derivation index.
     * <p>
     * This helper method derives a wallet node at a specific index by creating
     * intermediate nodes as needed.
     *
     * @param wallet The wallet to derive the node from
     * @param keyPurpose The key purpose (SEND or RECEIVE)
     * @param targetIndex The index to derive to
     * @return The wallet node at the specified index
     */
    private WalletNode getNodeAtIndex(Wallet wallet, KeyPurpose keyPurpose, int targetIndex) {
        WalletNode node = null;
        
        // Start with fresh node
        if (targetIndex == 0) {
            return wallet.getFreshNode(keyPurpose);
        }
        
        // Derive nodes incrementally to reach target index
        for (int i = 0; i <= targetIndex; i++) {
            if (i == 0) {
                node = wallet.getFreshNode(keyPurpose);
            } else {
                node = wallet.getFreshNode(keyPurpose, node);
            }
        }
        
        return node;
    }
    
    /**
     * Creates a new wallet with the specified passphrase and script type.
     * 
     * @param passphrase The BIP39 passphrase to use for the wallet (empty string for no passphrase)
     * @param scriptType The script type for the wallet (P2PKH or P2WPKH)
     * @param entropySizeBytes The size of entropy in bytes (16 for 12 words, 32 for 24 words)
     * @return A newly created wallet with random entropy and the specified passphrase
     * @throws IllegalArgumentException If entropySizeBytes is not valid (must be 16, 20, 24, 28, or 32 bytes)
     * @throws Exception If there's another error during wallet creation
     */
    private Wallet createWallet(String passphrase, ScriptType scriptType, int entropySizeBytes) throws Exception {
        // BIP-39 requires entropy to be between 128-256 bits (16-32 bytes) and a multiple of 32 bits (4 bytes)
        if (entropySizeBytes < 16 || entropySizeBytes > 32 || entropySizeBytes % 4 != 0) {
            throw new IllegalArgumentException("Invalid entropy size: " + entropySizeBytes + 
                    ". Must be 16, 20, 24, 28, or 32 bytes (for 12, 15, 18, 21, or 24 words).");
        }
        
        // Choose appropriate mnemonic based on entropy size
        List<String> words = null;
        if (entropySizeBytes == ENTROPY_SIZE_12_WORDS) {
            words = passphrase.isEmpty() ? SENDER_12_WORDS : RECEIVER_12_WORDS;
        } else if (entropySizeBytes == ENTROPY_SIZE_24_WORDS) {
            words = passphrase.isEmpty() ? SENDER_24_WORDS : RECEIVER_24_WORDS;
        } else {
            // For non-standard sizes, fallback to random generation
            byte[] entropy = new byte[entropySizeBytes];
            new SecureRandom().nextBytes(entropy);
            words = new Bip39MnemonicCode().toMnemonic(entropy);
        }
        
        DeterministicSeed seed = new DeterministicSeed(words, passphrase, 0, DeterministicSeed.Type.BIP39);
        
        Wallet wallet = new Wallet();
        wallet.setPolicyType(PolicyType.SINGLE);
        wallet.setScriptType(scriptType);
        Keystore keystore = Keystore.fromSeed(seed, wallet.getScriptType().getDefaultDerivation());
        wallet.getKeystores().add(keystore);
        wallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE, scriptType, wallet.getKeystores(), 1));
        return wallet;
    }
    
    /**
     * Creates a new wallet with the specified passphrase, script type, and mnemonic words.
     * 
     * @param passphrase The BIP39 passphrase to use for the wallet (empty string for no passphrase)
     * @param scriptType The script type for the wallet (P2PKH or P2WPKH)
     * @param mnemonic The BIP39 mnemonic words to use for the wallet
     * @return A newly created wallet with the specified mnemonic and passphrase
     * @throws Exception If there's an error during wallet creation
     */
    private Wallet createWallet(String passphrase, ScriptType scriptType, List<String> mnemonic) throws Exception {
        DeterministicSeed seed = new DeterministicSeed(mnemonic, passphrase, 0, DeterministicSeed.Type.BIP39);
        
        Wallet wallet = new Wallet();
        wallet.setPolicyType(PolicyType.SINGLE);
        wallet.setScriptType(scriptType);
        Keystore keystore = Keystore.fromSeed(seed, wallet.getScriptType().getDefaultDerivation());
        wallet.getKeystores().add(keystore);
        wallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE, scriptType, wallet.getKeystores(), 1));
        return wallet;
    }
    
    /**
     * Creates a notification transaction for BIP47 payment code exchange.
     * <p>
     * This creates a transaction that includes a blinded payment code in an OP_RETURN output,
     * which is how BIP47 facilitates the initial exchange of payment codes between parties.
     * The method handles both P2PKH and P2WPKH script types for maximum compatibility.
     *
     * @param senderWallet The wallet of the sender
     * @param senderKeystore The keystore of the sender
     * @param senderPaymentCode The payment code of the sender (to be blinded)
     * @param receiverPaymentCode The payment code of the receiver
     * @param scriptType The script type to use for the transaction
     * @return A transaction containing the blinded payment code in an OP_RETURN output
     * @throws InvalidPaymentCodeException If either payment code is malformed and cannot be properly processed
     * @throws Exception If there's an error during transaction creation for reasons not related to input parameters
     */
    private Transaction createNotificationTransaction(
            Wallet senderWallet, 
            Keystore senderKeystore, 
            PaymentCode senderPaymentCode, 
            PaymentCode receiverPaymentCode, 
            ScriptType scriptType) throws Exception {
        
        WalletNode senderInputNode = senderWallet.getNode(KeyPurpose.RECEIVE).getChildren().iterator().next();
        ECKey senderInputKey = senderKeystore.getKey(senderInputNode);
        
        // Use a dummy outpoint for the test
        TransactionOutPoint inputOutpoint = new TransactionOutPoint(
                Sha256Hash.wrapReversed(DUMMY_TX_HASH), 0);
        
        // Create secret point for blinding
        SecretPoint secretPoint = new SecretPoint(
                senderInputKey.getPrivKeyBytes(), 
                receiverPaymentCode.getNotificationKey().getPubKey());
        
        // Generate blinding mask from secret point and outpoint
        byte[] blindingMask = PaymentCode.getMask(
                secretPoint.ECDHSecretAsBytes(), 
                inputOutpoint.bitcoinSerialize());
        
        // Blind the sender's payment code
        byte[] blindedPaymentCode = PaymentCode.blind(
                senderPaymentCode.getPayload(), 
                blindingMask);
        
        // Create notification transaction
        Transaction notificationTx = new Transaction();
        
        // Set appropriate segwit flag based on script type
        if(scriptType == ScriptType.P2WPKH) {
            notificationTx.setSegwitFlag(Transaction.DEFAULT_SEGWIT_FLAG);
            
            // Create TransactionWitness properly
            TransactionSignature signature = TransactionSignature.dummy(TransactionSignature.Type.ECDSA);
            TransactionWitness witness = new TransactionWitness(notificationTx, senderInputKey, signature);
            
            notificationTx.addInput(inputOutpoint.getHash(), inputOutpoint.getIndex(), new Script(new byte[0]), witness);
        } else {
            // Add a DER-encoded dummy signature (R+S values + SIGHASH_ALL flag) for testing purposes
            List<ScriptChunk> inputChunks = List.of(
                    ScriptChunk.fromData(Utils.hexToBytes("3045022100ac8c6dbc482c79e86c18928a8b364923c774bfdbd852059f6b3778f2319b59a7022029d7cc5724e2f41ab1fcfc0ba5a0d4f57ca76f72f19530ba97c860c70a6bf0a801")),
                    ScriptChunk.fromData(senderInputKey.getPubKey()));
            notificationTx.addInput(inputOutpoint.getHash(), inputOutpoint.getIndex(), new Script(inputChunks));
        }
        
        // Add output to receiver's notification address
        notificationTx.addOutput(STANDARD_OUTPUT_AMOUNT, receiverPaymentCode.getNotificationAddress());
        
        // Add OP_RETURN output with blinded payment code
        List<ScriptChunk> opReturnChunks = List.of(
                ScriptChunk.fromOpcode(ScriptOpCodes.OP_RETURN),
                ScriptChunk.fromData(blindedPaymentCode));
        notificationTx.addOutput(STANDARD_OUTPUT_AMOUNT, new Script(opReturnChunks));
        
        return notificationTx;
    }
    
    /**
     * Creates child wallets for both sender and receiver using the appropriate payment codes.
     * <p>
     * This method facilitates the creation of child wallets that use BIP47 payment codes
     * for sending and receiving, which is how BIP47 achieves its privacy-enhancing addressing.
     *
     * @param senderWallet The main wallet of the sender
     * @param receiverWallet The main wallet of the receiver
     * @param senderPaymentCode The sender's payment code (recovered by the receiver)
     * @param receiverPaymentCode The receiver's payment code
     * @param scriptType The script type to use for the child wallets
     * @param senderLabel The label to assign to the sender child wallet
     * @param receiverLabel The label to assign to the receiver child wallet
     * @return A WalletPair containing both created child wallets
     */
    private WalletPair createChildWallets(
            Wallet senderWallet, 
            Wallet receiverWallet, 
            PaymentCode senderPaymentCode, 
            PaymentCode receiverPaymentCode, 
            ScriptType scriptType, 
            String senderLabel, 
            String receiverLabel) {
        
        Wallet receiverChildWallet = receiverWallet.addChildWallet(
                senderPaymentCode, 
                scriptType,
                senderLabel);
        
        Wallet senderChildWallet = senderWallet.addChildWallet(
                receiverPaymentCode,
                scriptType, 
                receiverLabel);
        
        return new WalletPair(senderChildWallet, receiverChildWallet);
    }
    
    /**
     * Verifies that address derivation matches between sender and receiver for multiple indices.
     * <p>
     * This method checks that for each index, the address derived by the sender for sending
     * matches the address derived by the receiver for receiving. This is the core requirement
     * for BIP47 to function correctly - both parties must derive the same payment addresses.
     *
     * @param senderChildWallet The sender's child wallet
     * @param receiverChildWallet The receiver's child wallet
     * @param count The number of consecutive indices to verify
     * @param errorMessagePrefix The prefix to use in assertion error messages
     * @return An array containing the last sender and receiver nodes that were verified
     */
    private WalletNode[] verifyAddressDerivation(
            Wallet senderChildWallet, 
            Wallet receiverChildWallet, 
            int count, 
            String errorMessagePrefix) {
        
        WalletNode sendNode = null;
        WalletNode receiveNode = null;
        
        for (int i = 0; i < count; i++) {
            // Get payment nodes
            if (i == 0) {
                sendNode = senderChildWallet.getFreshNode(KeyPurpose.SEND);
                receiveNode = receiverChildWallet.getFreshNode(KeyPurpose.RECEIVE);
            } else {
                sendNode = senderChildWallet.getFreshNode(KeyPurpose.SEND, sendNode);
                receiveNode = receiverChildWallet.getFreshNode(KeyPurpose.RECEIVE, receiveNode);
            }
            
            Address sendAddress = sendNode.getAddress();
            Address receiveAddress = receiveNode.getAddress();
            
            // Addresses must match for payment to work
            Assertions.assertEquals(sendAddress, receiveAddress, 
                errorMessagePrefix + " at index " + i + " don't match");
        }
        
        // Return the last nodes for further processing if needed
        return new WalletNode[]{sendNode, receiveNode};
    }
    
    /**
     * Verifies that the public keys obtained directly match those derived from private keys.
     * <p>
     * This method ensures that the key derivation process is consistent, by checking that
     * public keys obtained directly from the keystore match those that would be derived
     * from the corresponding private keys.
     *
     * @param keystore The keystore containing the keys
     * @param receiveNode The receiver wallet node to check (for index 0)
     * @param count The number of sequential nodes to verify starting from the given node
     * @param errorMessagePrefix The prefix to use in assertion error messages
     * @throws Exception If there's an error during key access including MnemonicException
     */
    private void verifyKeyAccess(
            Keystore keystore, 
            WalletNode receiveNode, 
            int count, 
            String errorMessagePrefix) throws Exception {
        
        WalletNode currentNode = receiveNode;
        
        for (int i = 0; i < count; i++) {
            // Verify the current node
            ECKey privKey = keystore.getKey(currentNode);
            ECKey pubKey = keystore.getPubKey(currentNode);
            Assertions.assertArrayEquals(privKey.getPubKey(), pubKey.getPubKey(), 
                errorMessagePrefix + " at index " + i);
            
            // Get the next node if we're not at the last iteration
            if (i < count - 1) {
                // Get the next node by generating a fresh node after this one
                currentNode = receiveNode.getWallet().getFreshNode(KeyPurpose.RECEIVE, currentNode);
            }
        }
    }
    
    /**
     * Helper class to hold a pair of sender and receiver child wallets.
     */
    private static class WalletPair {
        final Wallet senderChildWallet;
        final Wallet receiverChildWallet;
        
        WalletPair(Wallet senderChildWallet, Wallet receiverChildWallet) {
            this.senderChildWallet = senderChildWallet;
            this.receiverChildWallet = receiverChildWallet;
        }
    }
    
    /**
     * Generates a very long passphrase for testing.
     * 
     * @return A multi-paragraph passphrase with special characters
     */
    private String generateLongPassphrase() {
        // Generate a passphrase of multiple paragraphs
        StringBuilder sb = new StringBuilder();
        
        // First paragraph - original content for testing
        sb.append("This lengthy passphrase tests the cryptographic implementation of BIP47 with extended input. ");
        sb.append("Security systems must properly handle variable-length inputs without truncation or buffer issues. ");
        sb.append("Users may choose lengthy passphrases for enhanced security against dictionary attacks. ");
        
        // Second paragraph - original content for testing
        sb.append("Implementation systems process this text through key derivation functions to generate seeds. ");
        sb.append("Proper handling ensures that long passphrases provide additional entropy rather than causing problems. ");
        sb.append("Software must validate that extended inputs don't lead to unexpected behavior in address generation. ");
        
        // Third paragraph - original content for testing
        sb.append("BIP47 payment codes depend on correct passphrase handling across different wallet implementations. ");
        sb.append("Compatibility testing ensures that regardless of passphrase length, derived addresses match. ");
        sb.append("This test verifies the system's robustness when processing multi-paragraph inputs. ");
        
        // Add special characters and numbers
        sb.append("Special characters: !@#$%^&*()_+-=[]{}|;':\",./<>? ");
        sb.append("Numbers: 0123456789 ");
        
        // Repeat to make it even longer
        sb.append(sb.toString());
        
        return sb.toString();
    }
} 