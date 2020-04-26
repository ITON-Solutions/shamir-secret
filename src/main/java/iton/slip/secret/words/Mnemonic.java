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
import static iton.slip.secret.Common.ITERATION_EXP_LENGTH_BITS;
import static iton.slip.secret.Common.METADATA_LENGTH_WORDS;
import static iton.slip.secret.Common.RADIX_BITS;
import iton.slip.secret.Share;
import iton.slip.secret.SharedSecretException;
import iton.slip.secret.util.Checksum;
import iton.slip.secret.util.Utils;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author ITON Solutions
 */
public class Mnemonic {

    private static final Logger LOG = LoggerFactory.getLogger(Mnemonic.class);

    public static final Mnemonic INSTANCE = new Mnemonic();
    public static final int WORD_COUNT = 1024;
    private final Map<String, Short> MAP = new HashMap<>();

    private Mnemonic() {
        for (short i = 0; i < WORD_COUNT; i++) {
            MAP.put(Words.INSTANCE.getWord(i), (short) i);
        }
    }

    private short getIndex(String word) {
        return MAP.get(word);
    }

    public String indicesToMnemonic(short[] indices) {

        Words words = Words.INSTANCE;
        StringBuilder builder = new StringBuilder();
        int index = 0;

        for (int indice : indices) {
            if (++index < indices.length) {
                builder.append(words.getWord(indice)).append(" ");
            } else {
                builder.append(words.getWord(indice));
            }
        }
        return builder.toString();
    }

    public short[] indicesFromMnemonic(String mnemonic) {

        String[] words = mnemonic.toLowerCase().split(" ");
        short[] indices = new short[words.length];
        int index = 0;

        for (String word : words) {
            indices[index++] = getIndex(word);
        }

        return indices;
    }

    public Share decode(String mnemonic) throws SharedSecretException {
        short[] indices = indicesFromMnemonic(mnemonic);

        int padding = (RADIX_BITS * (indices.length - METADATA_LENGTH_WORDS)) % 0x10;
        if (padding > Byte.SIZE) {
            throw new SharedSecretException("Incorrect mnmemonic length");
        }

        if (!Checksum.verify(indices)) {
            throw new SharedSecretException("Invalid checksum");
        }

        Share share = new Share();

        short[] words = Arrays.copyOfRange(indices, 0, ID_EXP_LENGTH_WORDS);
        int id_exp = bigFromIndices(words).intValue();

        words = Arrays.copyOfRange(indices, ID_EXP_LENGTH_WORDS, ID_EXP_LENGTH_WORDS + 2);

        BigInteger big = bigFromIndices(words);
        words = bigToIndices(big, 5, 4);

        share.id = id_exp >> ITERATION_EXP_LENGTH_BITS;
        share.iteration_exponent = id_exp & 0x1F;
        share.group_index = words[0];
        share.group_threshold = words[1] + 1;
        share.group_count = words[2] + 1;
        share.member_index = words[3];
        share.member_threshold = words[4] + 1;

        LOG.debug(String.format("Id=%d Iteration exponent=%d Group index=%d Group threshold=%d Group count=%d Member index=%d Member threshold=%d",
                share.id,
                share.iteration_exponent,
                share.group_index,
                share.group_threshold,
                share.group_count,
                share.member_index,
                share.member_threshold));

        if (share.group_index > share.group_count - 1) {
            throw new SharedSecretException(String.format("Invalid group index (%d), group count is %d",
                    share.group_index,
                    share.group_count));
        }

        if (share.group_count < share.group_threshold) {
            throw new SharedSecretException(String.format("Invalid group threshold %d, cannot be greater than group count %d",
                    share.group_threshold,
                    share.group_count));
        }

        words = Arrays.copyOfRange(indices, ID_EXP_LENGTH_WORDS + 2, indices.length - CHECKSUM_LENGTH_WORDS);
        BigInteger value = bigFromIndices(words);
        int count = Utils.bitsToBytes(RADIX_BITS * words.length - padding);
        share.value = decodeFromBig(value, count);
        return share;
    }

    public String encode(Share share) {
        return encode(share.id,
                share.iteration_exponent,
                share.group_index,
                share.group_threshold,
                share.group_count,
                share.member_index,
                share.member_threshold,
                share.value);
    }

    public String encode(int id,
            int iteration_exponent,
            int group_index,
            int group_threshold,
            int group_count,
            int member_index,
            int member_threshold,
            byte[] value) {

        // Convert the share value from bytes to wordlist indices.
        int value_words = Utils.bitsToWords(value.length * Byte.SIZE);
        short[] prefix = encodePrefix(id, 
                iteration_exponent, 
                group_index, 
                group_threshold, 
                group_count);
  
        int member = ((group_count - 1 & 3) << 8) + (member_index << 4) + (member_threshold - 1);
        // push short value into array
        short[] result = new short[prefix.length + 1];
        System.arraycopy(prefix, 0, result, 0, prefix.length);
        result[prefix.length] = (short) member;
        
        short[] value_indices = bigToIndices(decodeToBig(value), value_words, RADIX_BITS);
        short[] data = Utils.concatenate(result, value_indices);
        short[] checksum = Checksum.create(data);
        return indicesToMnemonic(Utils.concatenate(data, checksum));
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
            BigInteger big = BigInteger.valueOf(bytes[bytes.length - i - 1] & 0xFF);
            big = big.shiftLeft(Byte.SIZE * i);
            result = result.add(big);
        }
        return result;
    }

    private byte[] decodeFromBig(BigInteger number, int length) throws SharedSecretException {

        BigInteger mask = BigInteger.valueOf(0xff);
        ByteBuffer result = ByteBuffer.allocate(length);

        while (number.compareTo(BigInteger.ZERO) > 0) {
            byte b = number.and(mask).byteValue();
            if (result.position() < result.limit()) {
                result.put(b);
                number = number.shiftRight(Byte.SIZE);
            } else {
                throw new SharedSecretException(String.format("Possibly invalid padding. Max byte legth %d", result.limit()));
            }
        }
        // Zero padding to the length
        for (int i = result.position(); i < length; i++) {
            result.put((byte) 0);
        }

        if (length != 0 && result.position() > length) {
            throw new SharedSecretException(String.format("Error in encoding BigInteger value, expected greater than %d length value, got %d", length, result.limit()));
        }
        result.flip();
        byte[] bytes = result.array();
        
        byte[] reverse = new byte[bytes.length];
        for(int i = 0; i < reverse.length; i ++){
            reverse[i] = bytes[reverse.length - i - 1];
        }
        return reverse;
    }
    
    private short[] encodePrefix(int id, 
            int iteration_exponent, 
            int group_index, 
            int group_threshold, 
            int group_count){
        
        BigInteger id_exp = BigInteger.valueOf((id << ITERATION_EXP_LENGTH_BITS) + iteration_exponent);
        short[] indice = bigToIndices(id_exp, ID_EXP_LENGTH_WORDS, RADIX_BITS);
        int group = (group_index << 6) + ((group_threshold - 1) << 2) + ((group_count - 1) >> 2);
         // push short value into array
        short[] result = new short[indice.length + 1];
        System.arraycopy(indice, 0, result, 0, indice.length);
        result[indice.length] = (short) group;
        return result;
    }
}
