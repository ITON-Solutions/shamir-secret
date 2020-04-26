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

import iton.bip.mnemonic.words.IWordList;
import java.security.NoSuchAlgorithmException;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author ITON Solutions
 */
public class WordsListContentTests {
    
    int WORD_COUNT = 1024;
    
    public WordsListContentTests() {
    }
    
    private final IWordList wordList = Words.INSTANCE;

    
    
    @Test
    public void listCheck() throws NoSuchAlgorithmException {
        
        for(int i = 0; i < WORD_COUNT; i++){
            int length = wordList.getWord(i).getBytes().length;
            if(length < 4 || length > 8){
                assertFalse("Incorrect word list", true);
            }
        }
        assertTrue(true);
    }
    
}
