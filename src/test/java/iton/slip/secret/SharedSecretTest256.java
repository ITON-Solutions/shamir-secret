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
public class SharedSecretTest256 {
    
    public SharedSecretTest256() {
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

    // 1. Valid mnemonic without sharing (256 bits)
    @Test
    public void test1() throws SharedSecretException, NoSuchAlgorithmException, InvalidKeyException {
        String[] mnemonics = new String[]{
            "theory painting academic academic armed sweater year military elder discuss acne wildlife boring employer fused large satoshi bundle carbon diagnose anatomy hamster leaves tracks paces beyond phantom capital marvel lips brave detect luck"
        };
        
        SharedSecret secret = new  SharedSecret();
        byte[] master_secret = secret.combine(mnemonics, "TREZOR");
        String master = Hex.toHexString(master_secret);
        assertEquals("989baf9dcaad5b10ca33dfd8cc75e42477025dce88ae83e75a230086a0e00e92", master);
    }
    
    // 2. Mnemonic with invalid checksum (256 bits)
    @Test(expected = SharedSecretException.class)
    public void test2() throws SharedSecretException, NoSuchAlgorithmException, InvalidKeyException {
        String[] mnemonics = new String[]{
            "theory painting academic academic armed sweater year military elder discuss acne wildlife boring employer fused large satoshi bundle carbon diagnose anatomy hamster leaves tracks paces beyond phantom capital marvel lips brave detect lunar"
        };
        
        SharedSecret secret = new  SharedSecret();
        byte[] master_secret = secret.combine(mnemonics, "TREZOR");
        String master = Hex.toHexString(master_secret);
        assertEquals("", master);
    }
    
    // 3. Mnemonic with invalid padding (256 bits)
    @Test(expected = SharedSecretException.class)
    public void test3() throws SharedSecretException, NoSuchAlgorithmException, InvalidKeyException {
        String[] mnemonics = new String[]{
            "theory painting academic academic campus sweater year military elder discuss acne wildlife boring employer fused large satoshi bundle carbon diagnose anatomy hamster leaves tracks paces beyond phantom capital marvel lips facility obtain sister"
        };
        
        SharedSecret secret = new  SharedSecret();
        byte[] master_secret = secret.combine(mnemonics, "TREZOR");
        String master = Hex.toHexString(master_secret);
        assertEquals("", master);
    }
    
    // 4. Basic sharing 2-of-3 (256 bits)
    @Test
    public void test4() throws SharedSecretException, NoSuchAlgorithmException, InvalidKeyException {
        String[] mnemonics = new String[]{
            "humidity disease academic always aluminum jewelry energy woman receiver strategy amuse duckling lying evidence network walnut tactics forget hairy rebound impulse brother survive clothes stadium mailman rival ocean reward venture always armed unwrap",
            "humidity disease academic agency actress jacket gross physics cylinder solution fake mortgage benefit public busy prepare sharp friar change work slow purchase ruler again tricycle involve viral wireless mixture anatomy desert cargo upgrade"
        };
        
        SharedSecret secret = new  SharedSecret();
        byte[] master_secret = secret.combine(mnemonics, "TREZOR");
        String master = Hex.toHexString(master_secret);
        assertEquals("c938b319067687e990e05e0da0ecce1278f75ff58d9853f19dcaeed5de104aae", master);
    }
    
     // 5. Basic sharing 2-of-3 with mismatching threshold(256 bits)
    @Test(expected = SharedSecretException.class)
    public void test5() throws SharedSecretException, NoSuchAlgorithmException, InvalidKeyException {
        String[] mnemonics = new String[]{
            "humidity disease academic always aluminum jewelry energy woman receiver strategy amuse duckling lying evidence network walnut tactics forget hairy rebound impulse brother survive clothes stadium mailman rival ocean reward venture always armed unwrap"
        };
        
        SharedSecret secret = new  SharedSecret();
        byte[] master_secret = secret.combine(mnemonics, "TREZOR");
        String master = Hex.toHexString(master_secret);
        assertEquals("", master);
    }
    
    // 6. Mnemonics with different identifiers (256 bits)
    @Test(expected = SharedSecretException.class)
    public void test6() throws SharedSecretException, NoSuchAlgorithmException, InvalidKeyException {
        String[] mnemonics = new String[]{
            "smear husband academic acid deadline scene venture distance dive overall parking bracelet elevator justice echo burning oven chest duke nylon",
            "smear isolate academic agency alpha mandate decorate burden recover guard exercise fatal force syndrome fumes thank guest drift dramatic mule"
        };
        
        SharedSecret secret = new  SharedSecret();
        byte[] master_secret = secret.combine(mnemonics, "TREZOR");
        String master = Hex.toHexString(master_secret);
        assertEquals("", master);
    }
    
    // 7. Mnemonics with different iteration exponents (256 bits)
    @Test(expected = SharedSecretException.class)
    public void test7() throws SharedSecretException, NoSuchAlgorithmException, InvalidKeyException {
        String[] mnemonics = new String[]{
            "finger trash academic acid average priority dish revenue academic hospital spirit western ocean fact calcium syndrome greatest plan losing dictate",
            "finger traffic academic agency building lilac deny paces subject threaten diploma eclipse window unknown health slim piece dragon focus smirk"
        };
        
        SharedSecret secret = new  SharedSecret();
        byte[] master_secret = secret.combine(mnemonics, "TREZOR");
        String master = Hex.toHexString(master_secret);
        assertEquals("", master);
    }
    
    // 8. Mnemonics with mismatching group thresholds (256 bits)
    @Test(expected = SharedSecretException.class)
    public void test8() throws SharedSecretException, NoSuchAlgorithmException, InvalidKeyException {
        String[] mnemonics = new String[]{
            "flavor pink beard echo depart forbid retreat become frost helpful juice unwrap reunion credit math burning spine black capital lair",
            "flavor pink beard email diet teaspoon freshman identify document rebound cricket prune headset loyalty smell emission skin often square rebound",
            "flavor pink academic easy credit cage raisin crazy closet lobe mobile become drink human tactics valuable hand capture sympathy finger"
        };
        
        SharedSecret secret = new  SharedSecret();
        byte[] master_secret = secret.combine(mnemonics, "TREZOR");
        String master = Hex.toHexString(master_secret);
        assertEquals("", master);
    }
    
    // 9. Mnemonics with mismatching group counts (256 bits)
    @Test(expected = SharedSecretException.class)
    public void test9() throws SharedSecretException, NoSuchAlgorithmException, InvalidKeyException {
        String[] mnemonics = new String[]{
            "column flea academic leaf debut extra surface slow timber husky lawsuit game behavior husky swimming already paper episode tricycle scroll",
            "column flea academic agency blessing garbage party software stadium verify silent umbrella therapy decorate chemical erode dramatic eclipse replace apart"
        };
        
        SharedSecret secret = new  SharedSecret();
        byte[] master_secret = secret.combine(mnemonics, "TREZOR");
        String master = Hex.toHexString(master_secret);
        assertEquals("", master);
    }
    
    // 10. Mnemonics with greater group threshold than group counts (256 bits)
    @Test(expected = SharedSecretException.class)
    public void test10() throws SharedSecretException, NoSuchAlgorithmException, InvalidKeyException {
        String[] mnemonics = new String[]{
            "smirk pink acrobat acid auction wireless impulse spine sprinkle fortune clogs elbow guest hush loyalty crush dictate tracks airport talent",
            "smirk pink acrobat agency dwarf emperor ajar organize legs slice harvest plastic dynamic style mobile float bulb health coding credit",
            "smirk pink beard academic alto strategy carve shame language rapids ruin smart location spray training acquire eraser endorse submit peaceful"
        };
        
        SharedSecret secret = new  SharedSecret();
        byte[] master_secret = secret.combine(mnemonics, "TREZOR");
        String master = Hex.toHexString(master_secret);
        assertEquals("", master);
    }
    
    // 11. Mnemonics with duplicate member indices (256 bits)
    @Test(expected = SharedSecretException.class)
    public void test11() throws SharedSecretException, NoSuchAlgorithmException, InvalidKeyException {
        String[] mnemonics = new String[]{
            "fishing recover academic always device craft trend snapshot gums skin downtown watch device sniff hour clock public maximum garlic born",
            "fishing recover academic always aircraft view software cradle fangs amazing package plastic evaluate intend penalty epidemic anatomy quarter cage apart"
        };
        
        SharedSecret secret = new  SharedSecret();
        byte[] master_secret = secret.combine(mnemonics, "TREZOR");
        String master = Hex.toHexString(master_secret);
        assertEquals("", master);
    }
    
    // 12. Mnemonics with mismatching member thresholds (256 bits)
    @Test(expected = SharedSecretException.class)
    public void test12() throws SharedSecretException, NoSuchAlgorithmException, InvalidKeyException {
        String[] mnemonics = new String[]{
            "evoke garden academic academic answer wolf scandal modern warmth station devote emerald market physics surface formal amazing aquatic gesture medical",
            "evoke garden academic agency deal revenue knit reunion decrease magazine flexible company goat repair alarm military facility clogs aide mandate"
        };
        
        SharedSecret secret = new  SharedSecret();
        byte[] master_secret = secret.combine(mnemonics, "TREZOR");
        String master = Hex.toHexString(master_secret);
        assertEquals("", master);
    }
    
    // 13. Mnemonics giving an invalid digest (256 bits)
    @Test(expected = SharedSecretException.class)
    public void test13() throws SharedSecretException, NoSuchAlgorithmException, InvalidKeyException {
        String[] mnemonics = new String[]{
            "river deal academic acid average forbid pistol peanut custody bike class aunt hairy merit valid flexible learn ajar very easel",
            "river deal academic agency camera amuse lungs numb isolate display smear piece traffic worthy year patrol crush fact fancy emission"
        };
        
        SharedSecret secret = new  SharedSecret();
        byte[] master_secret = secret.combine(mnemonics, "TREZOR");
        String master = Hex.toHexString(master_secret);
        assertEquals("", master);
    }
    
    // 14. Insufficient number of groups (256 bits, case 1)
    @Test(expected = SharedSecretException.class)
    public void test14() throws SharedSecretException, NoSuchAlgorithmException, InvalidKeyException {
        String[] mnemonics = new String[]{
            "wildlife deal beard romp alcohol space mild usual clothes union nuclear testify course research heat listen task location thank hospital slice smell failure fawn helpful priest ambition average recover lecture process dough stadium"
        };
        
        SharedSecret secret = new  SharedSecret();
        byte[] master_secret = secret.combine(mnemonics, "TREZOR");
        String master = Hex.toHexString(master_secret);
        assertEquals("", master);
    }
    
    // 15. Insufficient number of groups (256 bits, case 2)
    @Test(expected = SharedSecretException.class)
    public void test15() throws SharedSecretException, NoSuchAlgorithmException, InvalidKeyException {
        String[] mnemonics = new String[]{
            "wildlife deal decision scared acne fatal snake paces obtain election dryer dominant romp tactics railroad marvel trust helpful flip peanut theory theater photo luck install entrance taxi step oven network dictate intimate listen",
            "wildlife deal decision smug ancestor genuine move huge cubic strategy smell game costume extend swimming false desire fake traffic vegan senior twice timber submit leader payroll fraction apart exact forward pulse tidy install"
        };
        
        SharedSecret secret = new  SharedSecret();
        byte[] master_secret = secret.combine(mnemonics, "TREZOR");
        String master = Hex.toHexString(master_secret);
        assertEquals("", master);
    }
    
    // 16. Threshold number of groups, but insufficient number of members in one group (256 bits)
    @Test(expected = SharedSecretException.class)
    public void test16() throws SharedSecretException, NoSuchAlgorithmException, InvalidKeyException {
        String[] mnemonics = new String[]{
            "wildlife deal decision shadow analysis adjust bulb skunk muscle mandate obesity total guitar coal gravity carve slim jacket ruin rebuild ancestor numerous hour mortgage require herd maiden public ceiling pecan pickup shadow club",
            "wildlife deal beard romp alcohol space mild usual clothes union nuclear testify course research heat listen task location thank hospital slice smell failure fawn helpful priest ambition average recover lecture process dough stadium"
        };
        
        SharedSecret secret = new  SharedSecret();
        byte[] master_secret = secret.combine(mnemonics, "TREZOR");
        String master = Hex.toHexString(master_secret);
        assertEquals("", master);
    }
    
    // 17. Threshold number of groups and members in each group (256 bits, case 1)
    @Test
    public void test17() throws SharedSecretException, NoSuchAlgorithmException, InvalidKeyException {
        String[] mnemonics = new String[]{
            "wildlife deal ceramic round aluminum pitch goat racism employer miracle percent math decision episode dramatic editor lily prospect program scene rebuild display sympathy have single mustang junction relate often chemical society wits estate",
            "wildlife deal decision scared acne fatal snake paces obtain election dryer dominant romp tactics railroad marvel trust helpful flip peanut theory theater photo luck install entrance taxi step oven network dictate intimate listen",
            "wildlife deal ceramic scatter argue equip vampire together ruin reject literary rival distance aquatic agency teammate rebound false argue miracle stay again blessing peaceful unknown cover beard acid island language debris industry idle",
            "wildlife deal ceramic snake agree voter main lecture axis kitchen physics arcade velvet spine idea scroll promise platform firm sharp patrol divorce ancestor fantasy forbid goat ajar believe swimming cowboy symbolic plastic spelling",
            "wildlife deal decision shadow analysis adjust bulb skunk muscle mandate obesity total guitar coal gravity carve slim jacket ruin rebuild ancestor numerous hour mortgage require herd maiden public ceiling pecan pickup shadow club"
        };
        
        SharedSecret secret = new  SharedSecret();
        byte[] master_secret = secret.combine(mnemonics, "TREZOR");
        String master = Hex.toHexString(master_secret);
        assertEquals("5385577c8cfc6c1a8aa0f7f10ecde0a3318493262591e78b8c14c6686167123b", master);
    }
    
    // 18. Threshold number of groups and members in each group (256 bits, case 2)
    @Test
    public void test18() throws SharedSecretException, NoSuchAlgorithmException, InvalidKeyException {
        
        String[] mnemonics = new String[]{
            "wildlife deal decision scared acne fatal snake paces obtain election dryer dominant romp tactics railroad marvel trust helpful flip peanut theory theater photo luck install entrance taxi step oven network dictate intimate listen",
            "wildlife deal beard romp alcohol space mild usual clothes union nuclear testify course research heat listen task location thank hospital slice smell failure fawn helpful priest ambition average recover lecture process dough stadium",
            "wildlife deal decision smug ancestor genuine move huge cubic strategy smell game costume extend swimming false desire fake traffic vegan senior twice timber submit leader payroll fraction apart exact forward pulse tidy install"
        };
        
        SharedSecret secret = new  SharedSecret();
        byte[] master_secret = secret.combine(mnemonics, "TREZOR");
        String master = Hex.toHexString(master_secret);
        assertEquals("5385577c8cfc6c1a8aa0f7f10ecde0a3318493262591e78b8c14c6686167123b", master);
    }
    
    // 19. Threshold number of groups and members in each group (256 bits, case 3)
    @Test
    public void test19() throws SharedSecretException, NoSuchAlgorithmException, InvalidKeyException {
        String[] mnemonics = new String[]{
            "wildlife deal beard romp alcohol space mild usual clothes union nuclear testify course research heat listen task location thank hospital slice smell failure fawn helpful priest ambition average recover lecture process dough stadium",
            "wildlife deal acrobat romp anxiety axis starting require metric flexible geology game drove editor edge screw helpful have huge holy making pitch unknown carve holiday numb glasses survive already tenant adapt goat fangs"
        };
        
        SharedSecret secret = new  SharedSecret();
        byte[] master_secret = secret.combine(mnemonics, "TREZOR");
        String master = Hex.toHexString(master_secret);
        assertEquals("5385577c8cfc6c1a8aa0f7f10ecde0a3318493262591e78b8c14c6686167123b", master);
    }
 }
