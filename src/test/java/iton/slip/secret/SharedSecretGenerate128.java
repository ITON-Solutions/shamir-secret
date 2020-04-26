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

import iton.slip.secret.util.Utils;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
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
public class SharedSecretGenerate128 {
    
    public SharedSecretGenerate128() {
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
    
    @Test
    public void testGenerateRestore() throws SharedSecretException, NoSuchAlgorithmException, InvalidKeyException {
        byte iteration_exponent = 0;
        byte groups_threshold = 1;
        String passphrase = "alcatraz";
        byte[] master_secret = new byte[16];
        Utils.randomBytes(master_secret);
        List<Group> groups = new ArrayList<>();
        groups.add(new Group(2, 3));
        groups.add(new Group(3, 4));
        groups.add(new Group(1, 1));
        groups.add(new Group(1, 1));
      
        
        SharedSecret shared = new SharedSecret();
        List<String> mnemonics = shared.generate(master_secret, passphrase, groups_threshold, groups, iteration_exponent);
        assertEquals(mnemonics.size(), 9);
    }
    
    String[] mnemonics_result = new String[]{
            "biology enlarge academic roster drove element aviation package parking luck cylinder darkness company browser install oven game pharmacy silent learn",
            "biology enlarge away shaft blessing staff plastic laser require fraction texture welcome mixed reject trend email dilemma decent regular boring",
            "biology enlarge category romp chest beam pencil retreat desert ticket isolate clothes describe paper furl crucial involve explain taste visual",
            "biology enlarge academic scared canyon worthy spirit evoke blessing fatigue wisdom angel forget artist burning anatomy switch cradle welfare spit",
            "biology enlarge academic shadow divorce cleanup speak lungs maximum desert mayor spend ocean decorate prevent pulse force payment secret moment",
            "biology enlarge away round dream alpha manager company should liquid fangs always rebound suitable parking mansion flexible briefing costume beaver",
            "biology enlarge away scatter describe math glance gesture funding typical midst climate image raspy jacket hanger drift enjoy shadow focus",
            "biology enlarge away skin camera frost easy domestic deadline depend center squeeze fawn spit debut photo fatal hunting flip frozen",
            "biology enlarge deal romp chest beam pencil retreat desert ticket isolate clothes describe paper furl crucial involve funding welfare jury"
        };
    
    @Test
    public void testRestore1() throws SharedSecretException, NoSuchAlgorithmException, InvalidKeyException {

        String passphrase = "alcatraz";
        String secret = "cd87c628f1ef7747db8c19f9c906ce25";
        
        String[] mnemonics = new String[]{
            "biology enlarge deal romp chest beam pencil retreat desert ticket isolate clothes describe paper furl crucial involve funding welfare jury"
        };

        SharedSecret shared = new SharedSecret();
        byte[] master_secret = shared.combine(mnemonics, passphrase);
        String master = Hex.toHexString(master_secret);
        assertEquals(secret, master);
    }
    
    @Test
    public void testRestore2() throws SharedSecretException, NoSuchAlgorithmException, InvalidKeyException {

        String passphrase = "alcatraz";
        String secret = "cd87c628f1ef7747db8c19f9c906ce25";
        
        String[] mnemonics = new String[]{
            "biology enlarge academic scared canyon worthy spirit evoke blessing fatigue wisdom angel forget artist burning anatomy switch cradle welfare spit",
            "biology enlarge academic shadow divorce cleanup speak lungs maximum desert mayor spend ocean decorate prevent pulse force payment secret moment",
        };

        SharedSecret shared = new SharedSecret();
        byte[] master_secret = shared.combine(mnemonics, passphrase);
        String master = Hex.toHexString(master_secret);
        assertEquals(secret, master);
    }
    
    @Test
    public void testRestore3() throws SharedSecretException, NoSuchAlgorithmException, InvalidKeyException {

        String passphrase = "alcatraz";
        String secret = "cd87c628f1ef7747db8c19f9c906ce25";
        
        String[] mnemonics = new String[]{
            "biology enlarge away shaft blessing staff plastic laser require fraction texture welcome mixed reject trend email dilemma decent regular boring",
            "biology enlarge away round dream alpha manager company should liquid fangs always rebound suitable parking mansion flexible briefing costume beaver",
            "biology enlarge away scatter describe math glance gesture funding typical midst climate image raspy jacket hanger drift enjoy shadow focus",
        };

        SharedSecret shared = new SharedSecret();
        byte[] master_secret = shared.combine(mnemonics, passphrase);
        String master = Hex.toHexString(master_secret);
        assertEquals(secret, master);
    }
 }
