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
package iton.slip.secret.words;

import iton.slip.secret.Share;
import iton.slip.secret.SharedSecretException;
import java.util.HashMap;
import java.util.Map;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 *
 * @author Andrei
 */
public class MnemonicTest {
    
    private static final Map<String, Integer> MAP = new HashMap<>();
    
    public MnemonicTest() {
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
     * Test of indicesFromMnemonic method, of class Mnemonic.
     */
    @Test
    public void testMnemonicFromToIndices() {
        String mnemonic = "humidity disease academic always aluminum jewelry energy woman receiver strategy amuse duckling lying evidence network walnut tactics forget hairy rebound impulse brother survive clothes stadium mailman rival ocean reward venture always armed unwrap";
        short[] indices = Mnemonic.INSTANCE.indicesFromMnemonic(mnemonic);
        String result = Mnemonic.INSTANCE.indicesToMnemonic(indices);
        assertEquals(mnemonic, result);
    }
    
    @Test
    public void testEncodeDecodeMnemonic() throws SharedSecretException {
        String[] mnemonics = new String[]{
            "humidity disease academic always aluminum jewelry energy woman receiver strategy amuse duckling lying evidence network walnut tactics forget hairy rebound impulse brother survive clothes stadium mailman rival ocean reward venture always armed unwrap",
            "eraser senior decision smug corner ruin rescue cubic angel tackle skin skunk program roster trash rumor slush angel flea amazing"};
        
        for (String mnemonic : mnemonics) {
            Share share = Mnemonic.INSTANCE.decode(mnemonic);
            String result = Mnemonic.INSTANCE.encode(share);
            assertEquals(mnemonic, result);
        }
    }
}
