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

import static iton.slip.secret.Common.ID_LENGTH_BITS;
import static iton.slip.secret.Common.RADIX_BITS;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author ITON Solutions
 * 
 * Represents a single mnemonic share and its metadata
 */
public class Share {

    private static final Logger LOG = LoggerFactory.getLogger(Share.class);

    public int id;
    public int iteration_exponent;
    public int group_index;
    public int group_threshold;
    public int group_count;
    public int member_index;
    public int member_threshold;
    public byte[] value;

    public Share() {
    }

    public Share(short id,
            byte iteration_exponent,
            byte group_index,
            byte group_threshold,
            byte group_count,
            byte member_index,
            byte member_threshold,
            byte[] value) {

        this.id = id;
        this.iteration_exponent = iteration_exponent;
        this.group_index = group_index;
        this.group_threshold = group_threshold;
        this.group_count = group_count;
        this.member_index = member_index;
        this.member_threshold = member_threshold;
        this.value = value;
    }

    public String toMnemonics(short id,
            byte iteration_exponent,
            byte group_index,
            byte group_threshold,
            byte group_count,
            byte member_index,
            byte member_threshold,
            byte[] value)
    {
        short[] words = new short[20];
        words[0] = (short) (id >> (ID_LENGTH_BITS - RADIX_BITS));
        words[1] = (short) (((id & 0x001F) << 5) + iteration_exponent);
        words[2] = group_index;
        words[2] <<= 6;
        words[2] = (short) (((group_threshold - 1) << 2) + (group_count - 1) >> 2);
        words[3] = (short) (((group_count - 1) & 0x03));
        words[3] <<= 8;
        words[3] = (short) ((member_index << 4) + (member_threshold - 1));
        return null;
    }
}
