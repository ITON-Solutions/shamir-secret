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

import static iton.slip.secret.Common.CHECKSUM_LENGTH_WORDS;
import static iton.slip.secret.Common.ID_EXP_LENGTH_WORDS;
import static iton.slip.secret.Common.METADATA_LENGTH_WORDS;
import static iton.slip.secret.Common.RADIX_BITS;
import iton.slip.secret.SharedSecretException;
import iton.slip.secret.util.Utils;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 *
 * @author Andrei
 */
public class BigEncoderTest {

    private static final Map<String, Integer> MAP = new HashMap<>();

    public BigEncoderTest() {
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
    public void testBigIntegerToFromIndices() throws SharedSecretException {
        String mnemonic = "humidity disease academic always aluminum jewelry energy woman receiver strategy amuse duckling lying evidence network walnut tactics forget hairy rebound impulse brother survive clothes stadium mailman rival ocean reward venture always armed unwrap";
        short[] indices = Mnemonic.INSTANCE.indicesFromMnemonic(mnemonic);
        BigInteger from = bigFromIndices(indices);
        short[] result =  bigToIndices(from, indices.length, RADIX_BITS);
        assertArrayEquals(indices, result);
    }
    
    @Test
    public void testEncodeDecodeWord() throws SharedSecretException {
        String[] mnemonics = new String[]{
            "humidity disease academic always aluminum jewelry energy woman receiver strategy amuse duckling lying evidence network walnut tactics forget hairy rebound impulse brother survive clothes stadium mailman rival ocean reward venture always armed unwrap",
            "eraser senior decision smug corner ruin rescue cubic angel tackle skin skunk program roster trash rumor slush angel flea amazing"};

        for (String mnemonic : mnemonics) {
            short[] indices = Mnemonic.INSTANCE.indicesFromMnemonic(mnemonic);
            int padding = RADIX_BITS * (indices.length - METADATA_LENGTH_WORDS) % Short.SIZE;
            short[] words = Arrays.copyOfRange(indices, ID_EXP_LENGTH_WORDS + 2, indices.length - CHECKSUM_LENGTH_WORDS);

            BigInteger value = bigFromIndices(words);
            int count = Utils.bitsToBytes(RADIX_BITS * words.length - padding);
            byte[] encoded = decodeFromBig(value, count);
            short[] decoded = bigToIndices(decodeToBig(encoded), words.length, RADIX_BITS);
            assertArrayEquals(words, decoded);
        }
    }

    @Test
    public void testEncodeDecodeBigInteger() throws SharedSecretException {
        String master_secret = "bb54aac4b89dc868ba37d9cc21b2cece";

        byte[] master = master_secret.getBytes();
        BigInteger encoded = decodeToBig(master);
        byte[] result = decodeFromBig(encoded, 32);
        assertArrayEquals(master, result);
        
       
    }
    
    private BigInteger bigFromIndices(short[] indices) {
        BigInteger value = BigInteger.ZERO;
        BigInteger radix = BigInteger.valueOf(1 << RADIX_BITS);
        for (short index : indices) {
            value = value.multiply(radix).add(BigInteger.valueOf(index));
        }
        return value;
    }

    private short[] bigToIndices(BigInteger value, int length, int bits) {

        short[] result = new short[length];
        BigInteger mask = BigInteger.valueOf((1 << bits) - 1);
        for (int i = 0; i < length; i++) {
            int indice = value.shiftRight(i * bits).and(mask).intValue();
            result[i] = (short) indice;
        }

        short[] reverse = new short[result.length];
        for (int i = 0; i < reverse.length; i++) {
            reverse[i] = result[reverse.length - i - 1];
        }

        return reverse;
    }

    private BigInteger decodeToBig(byte[] bytes) {
        BigInteger result = BigInteger.ZERO;
        for (int i = 0; i < bytes.length; i++) {
            BigInteger b = BigInteger.valueOf(bytes[bytes.length - i - 1] & 0xFF);
            b = b.shiftLeft(Byte.SIZE * i);
            result = result.add(b);
        }
        return result;
    }

    private byte[] decodeFromBig(BigInteger number, int length) throws SharedSecretException {

        BigInteger mask = BigInteger.valueOf(0xFF);
        ByteBuffer result = ByteBuffer.allocate(length);

        while (number.compareTo(BigInteger.ZERO) > 0) {
            byte b = number.and(mask).byteValue();
            result.put(b);
            number = number.shiftRight(Byte.SIZE);
        }
        // Zero padding to the length
        for (int i = result.position(); i < length; i++) {
            result.put((byte) 0);
        }

        if (length != 0 && result.position() > length) {
            throw new SharedSecretException(String.format("Error in encoding BigInteger value, expected greater than %d length value, got %d", length, result.limit()));
        }

        byte[] bytes = result.array();

        byte[] reverse = new byte[bytes.length];
        for (int i = 0; i < reverse.length; i++) {
            reverse[i] = (byte) (bytes[reverse.length - i - 1]);
        }

        return reverse;
    }

}
