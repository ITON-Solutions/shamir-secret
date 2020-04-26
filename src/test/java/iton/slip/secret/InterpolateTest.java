/*
 * The MIT License
 *
 * Copyright 2020 ITON Solutions.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package iton.slip.secret;

import static iton.slip.secret.Common.DIGEST_INDEX;
import static iton.slip.secret.Common.DIGEST_LENGTH_BYTES;
import static iton.slip.secret.Common.MAX_STRENGTH_BITS;
import static iton.slip.secret.Common.SECRET_INDEX;
import iton.slip.secret.util.Crypto;
import iton.slip.secret.util.Utils;
import iton.slip.secret.words.Mnemonic;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author Andrei
 */
public class InterpolateTest {
    
    private static final Logger LOG = LoggerFactory.getLogger(Mnemonic.class);
    
    public InterpolateTest() {
    }
    
    @BeforeClass
    public static void setUpClass() {
    }
    
    @AfterClass
    public static void tearDownClass() {
    }
    
    @Before
    public void setUp() {
    }
    
    @After
    public void tearDown() {
    }

    /**
     * Test of encrypt method, of class Crypto.
     * @throws iton.slip.secret.SharedSecretException
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.security.InvalidKeyException
     */
    @Test
    public void testInterpolate() throws SharedSecretException, NoSuchAlgorithmException, InvalidKeyException  {
        String master_secret = "bb54aac4b89dc868ba37d9cc21b2cece";
        short id = 1;
        byte iteration_exponent = 0;
        byte[] master = master_secret.getBytes();
        String passphrase = "ALCATRAZ";
        byte[] encrypted_master = Crypto.encrypt(id, iteration_exponent, master, passphrase);
        byte[] master_result =  Crypto.decrypt(id, iteration_exponent, encrypted_master, passphrase);
        assertArrayEquals(master_result, master);
        
        Map<Integer, byte[]> points = split(3, 5, encrypted_master);
        Map<Integer, byte[]> shares = new HashMap<>();
        
        for(int i : points.keySet()){
            for(int k : points.keySet()){
                if(k != i){
                    shares.putAll(points);
                    shares.remove(i);
                    shares.remove(k);
                    byte[] shared_secret = interpolate(shares, SECRET_INDEX);
                    assertArrayEquals(shared_secret, encrypted_master);
                }
            }
        }
    }
    
    /**
     * Test of encrypt method, of class Crypto.
     * @throws iton.slip.secret.SharedSecretException
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.security.InvalidKeyException
     */
    @Test
    public void testRecover() throws SharedSecretException, NoSuchAlgorithmException, InvalidKeyException  {
        String master_secret = "bb54aac4b89dc868ba37d9cc21b2cece";
        short id = 1;
        byte iteration_exponent = 0;
        byte[] master = master_secret.getBytes();
        String passphrase = "ALCATRAZ";
        byte[] encrypted_master = Crypto.encrypt(id, iteration_exponent, master, passphrase);
        byte[] master_result =  Crypto.decrypt(id, iteration_exponent, encrypted_master, passphrase);
        assertArrayEquals(master_result, master);
        
        Map<Integer, byte[]> points = split(2, 3, encrypted_master);
        Map<Integer, byte[]> shares = new HashMap<>();
        
        shares.putAll(points);
        shares.remove(2);
        byte[] shared_secret = interpolate(shares, SECRET_INDEX);
        assertArrayEquals(shared_secret, encrypted_master);
        
        byte[] digest_share = interpolate(shares, DIGEST_INDEX);
        byte[] random_part = Arrays.copyOfRange(digest_share, DIGEST_LENGTH_BYTES, shared_secret.length);
        byte[] mac = Crypto.digest(random_part, shared_secret);
        byte[] digest = Arrays.copyOfRange(mac, 0, DIGEST_LENGTH_BYTES);
        assertArrayEquals(digest_share, Utils.concatenate(digest, random_part));
    }    
    
    private Map<Integer, byte[]> split(
            int threshold,
            int share_count,
            byte[] shared_secret) throws SharedSecretException, NoSuchAlgorithmException, InvalidKeyException {

        if (threshold < 1) {
            throw new SharedSecretException("Sharing threshold must be >= 1");
        }

        if (share_count > Common.MAX_SHARE_COUNT) {
            throw new SharedSecretException(String.format("Too many shares (%d)", share_count));
        }

        if (threshold > share_count) {
            throw new SharedSecretException("Number of shares should be at least equal threshold");
        }

        Map<Integer, byte[]> shares = new HashMap<>();
        Map<Integer, byte[]> base = new HashMap<>();

        // If the threshold is 1, then the digest of the shared secret is not used
        if (threshold == 1) {
            for (int i = 0; i < share_count; i++) {
                shares.put(i, shared_secret);
            }
            return shares;
        }

        if (share_count == 1) {
            shares.put(0, shared_secret);
            return shares;
        }

        for (int i = 0; i < threshold - 2; i++) {
            byte[] share = new byte[shared_secret.length];
            Utils.randomBytes(share);
            shares.put(i, share);
        }
        
        byte[] random_part = new byte[shared_secret.length - DIGEST_LENGTH_BYTES];
        Utils.randomBytes(random_part);
        byte[] mac = Crypto.digest(random_part, shared_secret);
        byte[] digest = Arrays.copyOfRange(mac, 0, DIGEST_LENGTH_BYTES);

        base.putAll(shares);
        base.put(DIGEST_INDEX, Utils.concatenate(digest, random_part));
        base.put(SECRET_INDEX, shared_secret);

        for (int i = threshold - 2; i < share_count; i++) {
            shares.put(i, interpolate(base, i));
        }

        return shares;
    }

    /**
     * Returns f(x) given the Shamir shares (x_1, f(x_1)), ... , (x_k, f(x_k)).
     *
     * @param shares: The Shamir shares. type Point[]: A list of pairs (x_i,
     * y_i), where x_i is an integer and y_i is an array of bytes representing
     * the evaluations of the polynomials in x_i.
     * @param x: The x coordinate of the result.
     * @return Evaluations of the polynomials in x. type: bytes[].
     */
    private byte[] interpolate(Map<Integer, byte[]> shares, int x) throws SharedSecretException {

        Set<Integer> x_coord = shares.keySet();
        
        if(x_coord.contains(x)){
            return shares.get(x);
        }

        // Logarithm of the product of (x_i - x) for i = 1, ... , k.
        int log_prod = 0;
        log_prod = shares.keySet().stream().map((i) -> Utils.LOG[i ^ x]).reduce(log_prod, Integer::sum);
        
        byte[] share = new byte[MAX_STRENGTH_BITS / 8];
        
         for (int i : shares.keySet()) {
            int sum = 0;
            sum = shares.keySet().stream().map((k) -> Utils.LOG[i ^ k]).reduce(sum, Integer::sum);
            // The logarithm of the Lagrange basis polynomial evaluated at x
            int log_basis_eval = (log_prod - Utils.LOG[i ^ x] - sum) % 255;
            if (log_basis_eval < 0) {
                log_basis_eval += 255;
            }

            int[] intermediate_sum = new int[share.length];
            for (int k = 0; k < share.length; k++) {
                int share_val = shares.get(i)[k] & 0xFF;
                intermediate_sum[k] = share[k] & 0xFF;
                if (share_val != 0) {
                    intermediate_sum[k] ^= Utils.EXP[(Utils.LOG[share_val] + log_basis_eval) % 255];
                } else {
                    intermediate_sum[k] ^= 0;
                }
                share[k] = (byte) intermediate_sum[k];
            }
            
        }
        return share;
    }
       
}
