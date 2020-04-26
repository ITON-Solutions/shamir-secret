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
public class SharedSecretTest128 {
    
    public SharedSecretTest128() {
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

    // 1. Valid mnemonic without sharing (128 bits)
    @Test
    public void test1() throws SharedSecretException, NoSuchAlgorithmException, InvalidKeyException {
        String[] mnemonics = new String[]{
            "duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode duke ajar critical decision keyboard"
        };
        
        SharedSecret secret = new  SharedSecret();
        byte[] master_secret = secret.combine(mnemonics, "TREZOR");
        String master = Hex.toHexString(master_secret);
        assertEquals("bb54aac4b89dc868ba37d9cc21b2cece", master);
    }
    
    // 2. Mnemonic with invalid checksum (128 bits)
    @Test(expected = SharedSecretException.class)
    public void test2() throws SharedSecretException, NoSuchAlgorithmException, InvalidKeyException {
        String[] mnemonics = new String[]{
            "duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode duke ajar critical decision kidney"
        };
        
        SharedSecret secret = new  SharedSecret();
        byte[] master_secret = secret.combine(mnemonics, "TREZOR");
        String master = Hex.toHexString(master_secret);
        assertEquals("", master);
    }
    
    // 3. Mnemonic with invalid padding (128 bits)
    @Test(expected = SharedSecretException.class)
    public void test3() throws SharedSecretException, NoSuchAlgorithmException, InvalidKeyException {
        String[] mnemonics = new String[]{
            "duckling enlarge academic academic email result length solution fridge kidney coal piece deal husband erode duke ajar music cargo fitness"
        };
        
        SharedSecret secret = new  SharedSecret();
        byte[] master_secret = secret.combine(mnemonics, "TREZOR");
        String master = Hex.toHexString(master_secret);
        assertEquals("", master);
    }
    
    // 4. Basic sharing 2-of-3 (128 bits)
    @Test
    public void test4() throws SharedSecretException, NoSuchAlgorithmException, InvalidKeyException {
        String[] mnemonics = new String[]{
            "shadow pistol academic always adequate wildlife fancy gross oasis cylinder mustang wrist rescue view short owner flip making coding armed",
            "shadow pistol academic acid actress prayer class unknown daughter sweater depict flip twice unkind craft early superior advocate guest smoking"
        };
        
        SharedSecret secret = new  SharedSecret();
        byte[] master_secret = secret.combine(mnemonics, "TREZOR");
        String master = Hex.toHexString(master_secret);
        assertEquals("b43ceb7e57a0ea8766221624d01b0864", master);
    }
    
     // 5. Basic sharing 2-of-3 with mismatching threshold(128 bits)
    @Test(expected = SharedSecretException.class)
    public void test5() throws SharedSecretException, NoSuchAlgorithmException, InvalidKeyException {
        String[] mnemonics = new String[]{
            "shadow pistol academic always adequate wildlife fancy gross oasis cylinder mustang wrist rescue view short owner flip making coding armed"
        };
        
        SharedSecret secret = new  SharedSecret();
        byte[] master_secret = secret.combine(mnemonics, "TREZOR");
        String master = Hex.toHexString(master_secret);
        assertEquals("", master);
    }
    
    // 6. Mnemonics with different identifiers (128 bits)
    @Test(expected = SharedSecretException.class)
    public void test6() throws SharedSecretException, NoSuchAlgorithmException, InvalidKeyException {
        String[] mnemonics = new String[]{
            "adequate smoking academic acid debut wine petition glen cluster slow rhyme slow simple epidemic rumor junk tracks treat olympic tolerate",
            "adequate stay academic agency agency formal party ting frequent learn upstairs remember smear leaf damage anatomy ladle market hush corner"
        };
        
        SharedSecret secret = new  SharedSecret();
        byte[] master_secret = secret.combine(mnemonics, "TREZOR");
        String master = Hex.toHexString(master_secret);
        assertEquals("", master);
    }
    
    // 7. Mnemonics with different iteration exponents (128 bits)
    @Test(expected = SharedSecretException.class)
    public void test7() throws SharedSecretException, NoSuchAlgorithmException, InvalidKeyException {
        String[] mnemonics = new String[]{
            "peasant leaves academic acid desert exact olympic math alive axle trial tackle drug deny decent smear dominant desert bucket remind",
            "peasant leader academic agency cultural blessing percent network envelope medal junk primary human pumps jacket fragment payroll ticket evoke voice"
        };
        
        SharedSecret secret = new  SharedSecret();
        byte[] master_secret = secret.combine(mnemonics, "TREZOR");
        String master = Hex.toHexString(master_secret);
        assertEquals("", master);
    }
    
    // 8. Mnemonics with mismatching group thresholds (128 bits)
    @Test(expected = SharedSecretException.class)
    public void test8() throws SharedSecretException, NoSuchAlgorithmException, InvalidKeyException {
        String[] mnemonics = new String[]{
            "liberty category beard echo animal fawn temple briefing math username various wolf aviation fancy visual holy thunder yelp helpful payment",
            "liberty category beard email beyond should fancy romp founder easel pink holy hairy romp loyalty material victim owner toxic custody",
            "liberty category academic easy being hazard crush diminish oral lizard reaction cluster force dilemma deploy force club veteran expect photo"
        };
        
        SharedSecret secret = new  SharedSecret();
        byte[] master_secret = secret.combine(mnemonics, "TREZOR");
        String master = Hex.toHexString(master_secret);
        assertEquals("", master);
    }
    
    // 9. Mnemonics with mismatching group counts (128 bits)
    @Test(expected = SharedSecretException.class)
    public void test9() throws SharedSecretException, NoSuchAlgorithmException, InvalidKeyException {
        String[] mnemonics = new String[]{
            "liberty category beard echo animal fawn temple briefing math username various wolf aviation fancy visual holy thunder yelp helpful payment",
            "liberty category beard email beyond should fancy romp founder easel pink holy hairy romp loyalty material victim owner toxic custody",
            "liberty category academic easy being hazard crush diminish oral lizard reaction cluster force dilemma deploy force club veteran expect photo"
        };
        
        SharedSecret secret = new  SharedSecret();
        byte[] master_secret = secret.combine(mnemonics, "TREZOR");
        String master = Hex.toHexString(master_secret);
        assertEquals("", master);
    }
    
    // 10. Mnemonics with greater group threshold than group counts (128 bits)
    @Test(expected = SharedSecretException.class)
    public void test10() throws SharedSecretException, NoSuchAlgorithmException, InvalidKeyException {
        String[] mnemonics = new String[]{
            "music husband acrobat acid artist finance center either graduate swimming object bike medical clothes station aspect spider maiden bulb welcome",
            "music husband acrobat agency advance hunting bike corner density careful material civil evil tactics remind hawk discuss hobo voice rainbow",
            "music husband beard academic black tricycle clock mayor estimate level photo episode exclude ecology papa source amazing salt verify divorce"
        };
        
        SharedSecret secret = new  SharedSecret();
        byte[] master_secret = secret.combine(mnemonics, "TREZOR");
        String master = Hex.toHexString(master_secret);
        assertEquals("", master);
    }
    
    // 11. Mnemonics with duplicate member indices (128 bits)
    @Test(expected = SharedSecretException.class)
    public void test11() throws SharedSecretException, NoSuchAlgorithmException, InvalidKeyException {
        String[] mnemonics = new String[]{
            "device stay academic always dive coal antenna adult black exceed stadium herald advance soldier busy dryer daughter evaluate minister laser",
            "device stay academic always dwarf afraid robin gravity crunch adjust soul branch walnut coastal dream costume scholar mortgage mountain pumps"
        };
        
        SharedSecret secret = new  SharedSecret();
        byte[] master_secret = secret.combine(mnemonics, "TREZOR");
        String master = Hex.toHexString(master_secret);
        assertEquals("", master);
    }
    
    // 12. Mnemonics with mismatching member thresholds (128 bits)
    @Test(expected = SharedSecretException.class)
    public void test12() throws SharedSecretException, NoSuchAlgorithmException, InvalidKeyException {
        String[] mnemonics = new String[]{
            "hour painting academic academic device formal evoke guitar random modern justice filter withdraw trouble identify mailman insect general cover oven",
            "hour painting academic agency artist again daisy capital beaver fiber much enjoy suitable symbolic identify photo editor romp float echo"
        };
        
        SharedSecret secret = new  SharedSecret();
        byte[] master_secret = secret.combine(mnemonics, "TREZOR");
        String master = Hex.toHexString(master_secret);
        assertEquals("", master);
    }
    
    // 13. Mnemonics giving an invalid digest (128 bits)
    @Test(expected = SharedSecretException.class)
    public void test13() throws SharedSecretException, NoSuchAlgorithmException, InvalidKeyException {
        String[] mnemonics = new String[]{
            "guilt walnut academic acid deliver remove equip listen vampire tactics nylon rhythm failure husband fatigue alive blind enemy teaspoon rebound",
            "guilt walnut academic agency brave hamster hobo declare herd taste alpha slim criminal mild arcade formal romp branch pink ambition"
        };
        
        SharedSecret secret = new  SharedSecret();
        byte[] master_secret = secret.combine(mnemonics, "TREZOR");
        String master = Hex.toHexString(master_secret);
        assertEquals("", master);
    }
    
    // 14. Insufficient number of groups (128 bits, case 1)
    @Test(expected = SharedSecretException.class)
    public void test14() throws SharedSecretException, NoSuchAlgorithmException, InvalidKeyException {
        String[] mnemonics = new String[]{
            "eraser senior beard romp adorn nuclear spill corner cradle style ancient family general leader ambition exchange unusual garlic promise voice"
        };
        
        SharedSecret secret = new  SharedSecret();
        byte[] master_secret = secret.combine(mnemonics, "TREZOR");
        String master = Hex.toHexString(master_secret);
        assertEquals("", master);
    }
    
    // 15. Insufficient number of groups (128 bits, case 2)
    @Test(expected = SharedSecretException.class)
    public void test15() throws SharedSecretException, NoSuchAlgorithmException, InvalidKeyException {
        String[] mnemonics = new String[]{
            "eraser senior decision scared cargo theory device idea deliver modify curly include pancake both news skin realize vitamins away join",
            "eraser senior decision roster beard treat identify grumpy salt index fake aviation theater cubic bike cause research dragon emphasis counter"
        };
        
        SharedSecret secret = new  SharedSecret();
        byte[] master_secret = secret.combine(mnemonics, "TREZOR");
        String master = Hex.toHexString(master_secret);
        assertEquals("", master);
    }
    
    // 16. Threshold number of groups, but insufficient number of members in one group (128 bits)
    @Test(expected = SharedSecretException.class)
    public void test16() throws SharedSecretException, NoSuchAlgorithmException, InvalidKeyException {
        String[] mnemonics = new String[]{
            "eraser senior decision shadow artist work morning estate greatest pipeline plan ting petition forget hormone flexible general goat admit surface",
            "eraser senior beard romp adorn nuclear spill corner cradle style ancient family general leader ambition exchange unusual garlic promise voice"
        };
        
        SharedSecret secret = new  SharedSecret();
        byte[] master_secret = secret.combine(mnemonics, "TREZOR");
        String master = Hex.toHexString(master_secret);
        assertEquals("", master);
    }
    
    // 17. Threshold number of groups and members in each group (128 bits, case 1)
    @Test
    public void test17() throws SharedSecretException, NoSuchAlgorithmException, InvalidKeyException {
        String[] mnemonics = new String[]{
            "eraser senior decision roster beard treat identify grumpy salt index fake aviation theater cubic bike cause research dragon emphasis counter",
            "eraser senior ceramic snake clay various huge numb argue hesitate auction category timber browser greatest hanger petition script leaf pickup",
            "eraser senior ceramic shaft dynamic become junior wrist silver peasant force math alto coal amazing segment yelp velvet image paces",
            "eraser senior ceramic round column hawk trust auction smug shame alive greatest sheriff living perfect corner chest sled fumes adequate",
            "eraser senior decision smug corner ruin rescue cubic angel tackle skin skunk program roster trash rumor slush angel flea amazing"
        };
        
        SharedSecret secret = new  SharedSecret();
        byte[] master_secret = secret.combine(mnemonics, "TREZOR");
        String master = Hex.toHexString(master_secret);
        assertEquals("7c3397a292a5941682d7a4ae2d898d11", master);
    }
    
    // 18. Threshold number of groups and members in each group (128 bits, case 2)
    @Test
    public void test18() throws SharedSecretException, NoSuchAlgorithmException, InvalidKeyException {
        
        String[] mnemonics = new String[]{
            "eraser senior decision smug corner ruin rescue cubic angel tackle skin skunk program roster trash rumor slush angel flea amazing",
            "eraser senior beard romp adorn nuclear spill corner cradle style ancient family general leader ambition exchange unusual garlic promise voice",
            "eraser senior decision scared cargo theory device idea deliver modify curly include pancake both news skin realize vitamins away join"
        };
        
        SharedSecret secret = new  SharedSecret();
        byte[] master_secret = secret.combine(mnemonics, "TREZOR");
        String master = Hex.toHexString(master_secret);
        assertEquals("7c3397a292a5941682d7a4ae2d898d11", master);
    }
    
    // 19. Threshold number of groups and members in each group (128 bits, case 3)
    @Test
    public void test19() throws SharedSecretException, NoSuchAlgorithmException, InvalidKeyException {
        String[] mnemonics = new String[]{
            "eraser senior beard romp adorn nuclear spill corner cradle style ancient family general leader ambition exchange unusual garlic promise voice",
            "eraser senior acrobat romp bishop medical gesture pumps secret alive ultimate quarter priest subject class dictate spew material endless market"
        };
        
        SharedSecret secret = new  SharedSecret();
        byte[] master_secret = secret.combine(mnemonics, "TREZOR");
        String master = Hex.toHexString(master_secret);
        assertEquals("7c3397a292a5941682d7a4ae2d898d11", master);
    }
 }
