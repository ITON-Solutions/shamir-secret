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
public class SharedSecretGenerate256 {
    
    public SharedSecretGenerate256() {
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
        byte iteration_exponent = 1;
        byte groups_threshold = 2;
        String passphrase = "alcatraz";
        byte[] master_secret = new byte[32];
        Utils.randomBytes(master_secret);
        List<Group> groups = new ArrayList<>();
        groups.add(new Group(2, 3));
        groups.add(new Group(2, 2));
      
        
        SharedSecret shared = new SharedSecret();
        List<String> mnemonics = shared.generate(master_secret, passphrase, groups_threshold, groups, iteration_exponent);
        assertEquals(mnemonics.size(), 5);
    }
    
    String[] mnemonics_result = new String[]{
            "fawn regret acrobat echo aide crowd excuse best therapy busy prisoner aluminum cards webcam piece adorn trip robin mixture swimming vitamins trust plan undergo retreat gesture swing frozen fiscal duckling duckling dive jump",
            "fawn regret acrobat email aunt dress craft knife station surprise member frost device puny triumph express mixture emerald desktop soul brother dive soul width maximum luxury frozen making earth taste replace chubby gasoline",
            "fawn regret acrobat entrance activity scout lizard similar deploy olympic ugly payroll fluff platform drug network angel slim scramble scramble lying mayor galaxy secret hairy usual roster voter mouse jury animal dining class",
            "fawn regret beard echo avoid fancy brother orange gasoline similar cargo mortgage ceiling swimming hospital spray ivory swing burning drug temple sidewalk trend adorn group rebound august mineral ruler desert join bulge emerald",
            "fawn regret beard email academic briefing unfair moisture temple floral chest pregnant reaction category step charity arena shrimp detailed suitable round aspect woman angel length reaction evoke trial tenant necklace climate actress listen"
        };
    
    @Test
    public void testRestore1() throws SharedSecretException, NoSuchAlgorithmException, InvalidKeyException {

        String passphrase = "alcatraz";
        String secret = "a7b2bf1689a015fce0056ff980e522496282435bd52f628b5b5450e42a77b29b";
        
        String[] mnemonics = new String[]{
            "fawn regret acrobat email aunt dress craft knife station surprise member frost device puny triumph express mixture emerald desktop soul brother dive soul width maximum luxury frozen making earth taste replace chubby gasoline",
            "fawn regret acrobat entrance activity scout lizard similar deploy olympic ugly payroll fluff platform drug network angel slim scramble scramble lying mayor galaxy secret hairy usual roster voter mouse jury animal dining class",
            "fawn regret beard echo avoid fancy brother orange gasoline similar cargo mortgage ceiling swimming hospital spray ivory swing burning drug temple sidewalk trend adorn group rebound august mineral ruler desert join bulge emerald",
            "fawn regret beard email academic briefing unfair moisture temple floral chest pregnant reaction category step charity arena shrimp detailed suitable round aspect woman angel length reaction evoke trial tenant necklace climate actress listen"
        };

        SharedSecret shared = new SharedSecret();
        byte[] master_secret = shared.combine(mnemonics, passphrase);
        String master = Hex.toHexString(master_secret);
        assertEquals(secret, master);
    }
    
    @Test
    public void testRestore2() throws SharedSecretException, NoSuchAlgorithmException, InvalidKeyException {

        String passphrase = "alcatraz";
        String secret = "a7b2bf1689a015fce0056ff980e522496282435bd52f628b5b5450e42a77b29b";
        
        String[] mnemonics = new String[]{
            "fawn regret acrobat echo aide crowd excuse best therapy busy prisoner aluminum cards webcam piece adorn trip robin mixture swimming vitamins trust plan undergo retreat gesture swing frozen fiscal duckling duckling dive jump",
            "fawn regret acrobat entrance activity scout lizard similar deploy olympic ugly payroll fluff platform drug network angel slim scramble scramble lying mayor galaxy secret hairy usual roster voter mouse jury animal dining class",
            "fawn regret beard echo avoid fancy brother orange gasoline similar cargo mortgage ceiling swimming hospital spray ivory swing burning drug temple sidewalk trend adorn group rebound august mineral ruler desert join bulge emerald",
            "fawn regret beard email academic briefing unfair moisture temple floral chest pregnant reaction category step charity arena shrimp detailed suitable round aspect woman angel length reaction evoke trial tenant necklace climate actress listen"
        };

        SharedSecret shared = new SharedSecret();
        byte[] master_secret = shared.combine(mnemonics, passphrase);
        String master = Hex.toHexString(master_secret);
        assertEquals(secret, master);
    }
    
    @Test
    public void testRestore3() throws SharedSecretException, NoSuchAlgorithmException, InvalidKeyException {

        String passphrase = "alcatraz";
        String secret = "a7b2bf1689a015fce0056ff980e522496282435bd52f628b5b5450e42a77b29b";
        
        String[] mnemonics = new String[]{
            "fawn regret acrobat echo aide crowd excuse best therapy busy prisoner aluminum cards webcam piece adorn trip robin mixture swimming vitamins trust plan undergo retreat gesture swing frozen fiscal duckling duckling dive jump",
            "fawn regret acrobat email aunt dress craft knife station surprise member frost device puny triumph express mixture emerald desktop soul brother dive soul width maximum luxury frozen making earth taste replace chubby gasoline",
            "fawn regret beard echo avoid fancy brother orange gasoline similar cargo mortgage ceiling swimming hospital spray ivory swing burning drug temple sidewalk trend adorn group rebound august mineral ruler desert join bulge emerald",
            "fawn regret beard email academic briefing unfair moisture temple floral chest pregnant reaction category step charity arena shrimp detailed suitable round aspect woman angel length reaction evoke trial tenant necklace climate actress listen"
        };

        SharedSecret shared = new SharedSecret();
        byte[] master_secret = shared.combine(mnemonics, passphrase);
        String master = Hex.toHexString(master_secret);
        assertEquals(secret, master);
    }
 }
