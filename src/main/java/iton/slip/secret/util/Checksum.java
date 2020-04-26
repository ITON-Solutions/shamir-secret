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

package iton.slip.secret.util;

import static iton.slip.secret.Common.CHECKSUM_LENGTH_WORDS;

/**
 *
 * @author ITON Solutions
 */
public class Checksum {
    
    private static final byte[] CUSTOMIZATION_STRING = "shamir".getBytes(); // The customization string used in the RS1024 checksum and in the PBKDF2 salt.
    
    private static int checksum(short[] data) {
        
        int[] GEN = new int[]{
            0xE0E040, 0x1C1C080, 0x3838100, 0x7070200, 0xE0E0009, 
            0x1C0C2412, 0x38086C24, 0x3090FC48, 0x21B1F890, 0x3F3F120
        };

        int chk = 1;
        for (short v : data){
            int b = chk >> 20;
            chk = ((chk & 0xFFFFF) << 10) ^ v;
            for(int i = 0; i < 10; i++){
                chk = ((b >> i) & 1) != 0 ? chk ^ GEN[i] : chk ^ 0;
            }
        }
        return chk;
    }
    
    public static boolean verify(short[] words){
        short[] values = new short[CUSTOMIZATION_STRING.length + words.length];
        for(int i = 0; i < CUSTOMIZATION_STRING.length; i++){
            values[i] = (short) CUSTOMIZATION_STRING[i];
        }
        
        System.arraycopy(words, 0, values, CUSTOMIZATION_STRING.length, words.length);
        return checksum(values) == 1;
    }
    
    public static short[] create(short[] data){
        short[] result = new short[CHECKSUM_LENGTH_WORDS];
        short[] values = new short[CUSTOMIZATION_STRING.length + data.length + CHECKSUM_LENGTH_WORDS];
        for(int i = 0; i < CUSTOMIZATION_STRING.length; i++){
            values[i] = (short) CUSTOMIZATION_STRING[i];
        }
        
        System.arraycopy(data, 0, values, CUSTOMIZATION_STRING.length, data.length);
        int checksum = checksum(values) ^ 1;
        for (byte i = CHECKSUM_LENGTH_WORDS; i > 0; i--) {
            result[CHECKSUM_LENGTH_WORDS - i] = (short) ((checksum >> 10 * (i - 1)) & 0x3FF);
        }
        return result;
    }
}
