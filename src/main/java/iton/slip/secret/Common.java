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

/**
 *
 * @author ITON Solutions
 */
public class Common {

    public static final int RADIX_BITS = 10;         // The length of the radix in bits.
    public static final int RADIX = 1 << RADIX_BITS; // The number of words in the word list.
    public static final int ID_LENGTH_BITS = 15;     // The length of the random identifier in bits.
    public static final int ITERATION_EXP_LENGTH_BITS = 5; // The length of the iteration exponent in bits.
    public static final int ID_EXP_LENGTH_WORDS = Utils.bitsToWords(ID_LENGTH_BITS + ITERATION_EXP_LENGTH_BITS); // The length of the random identifier and iteration exponent in words.
    public static final int MAX_SHARE_COUNT = 16;     // The maximum number of shares that can be created.
    public static final int CHECKSUM_LENGTH_WORDS = 3; // The length of the RS1024 checksum in words.
    public static final int DIGEST_LENGTH_BYTES = 4;   // The length of the digest of the shared secret in bytes.
    public static final byte[] CUSTOMIZATION_STRING = "shamir".getBytes(); // The customization string used in the RS1024 checksum and in the PBKDF2 salt.
    public static final int METADATA_LENGTH_WORDS = ID_EXP_LENGTH_WORDS + 2 + CHECKSUM_LENGTH_WORDS; // The length of the mnemonic in words without the share value.
    public static final int MIN_STRENGTH_BITS = 128; // The minimum allowed entropy of the master secret.
    public static final int MAX_STRENGTH_BITS = 256; // The maximum allowed entropy of the master secret.
    public static final int MIN_MNEMONIC_LENGTH_WORDS = METADATA_LENGTH_WORDS + Utils.bitsToWords(MIN_STRENGTH_BITS); // The minimum allowed length of the mnemonic in words.
    public static final int BASE_ITERATION_COUNT = 10000; // The minimum number of iterations to use in PBKDF2.
    public static final int ROUND_COUNT = 4;    // The number of rounds to use in the Feistel cipher.
    public static final int SECRET_INDEX = 255; // The index of the share containing the shared secret.
    public static final int DIGEST_INDEX = 254; // The index of the share containing the digest of the shared secret.
    
    public static final byte MNEMONIC_MAX_LEN = 8;
    public static final byte MNEMONIC_MIN_LEN = 4;
    public static final byte MNEMONIC_WORDS_MAX = 33;
    public static final byte MNEMONIC_WORDS_MIN = 20;
}
