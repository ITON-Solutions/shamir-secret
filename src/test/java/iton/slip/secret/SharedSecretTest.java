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

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.spongycastle.util.encoders.Hex;

/**
 *
 * @author Andrei
 */
public class SharedSecretTest {
    
    public SharedSecretTest() {
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

       
    // 1. Mnemonic with insufficient length
    @Test(expected = SharedSecretException.class)
    public void test1() throws SharedSecretException, NoSuchAlgorithmException, InvalidKeyException {
        String[] mnemonics = new String[]{
            "junk necklace academic academic acne isolate join hesitate lunar roster dough calcium chemical ladybug amount mobile glasses verify cylinder"
        };
        
        SharedSecret secret = new  SharedSecret();
        byte[] master_secret = secret.combine(mnemonics, "TREZOR");
        String master = Hex.toHexString(master_secret);
        assertEquals("", master);
    }
    
    // 2. Mnemonic with invalid master secret length
    @Test(expected = SharedSecretException.class)
    public void test2() throws SharedSecretException, NoSuchAlgorithmException, InvalidKeyException {
        String[] mnemonics = new String[]{
            "fraction necklace academic academic award teammate mouse regular testify coding building member verdict purchase blind camera duration email prepare spirit quarter"
        };
        
        SharedSecret secret = new  SharedSecret();
        byte[] master_secret = secret.combine(mnemonics, "TREZOR");
        String master = Hex.toHexString(master_secret);
        assertEquals("", master);
    }
 }
