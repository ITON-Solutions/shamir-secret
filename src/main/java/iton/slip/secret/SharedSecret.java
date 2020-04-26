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

import com.google.common.base.CharMatcher;
import static iton.slip.secret.Common.DIGEST_INDEX;
import static iton.slip.secret.Common.DIGEST_LENGTH_BYTES;
import static iton.slip.secret.Common.MAX_SHARE_COUNT;
import static iton.slip.secret.Common.MIN_STRENGTH_BITS;
import static iton.slip.secret.Common.MNEMONIC_WORDS_MAX;
import static iton.slip.secret.Common.MNEMONIC_WORDS_MIN;
import static iton.slip.secret.Common.SECRET_INDEX;
import iton.slip.secret.util.Utils;
import java.util.List;
import iton.slip.secret.util.Crypto;
import iton.slip.secret.words.Mnemonic;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author ITON Solutions
 */
public class SharedSecret {

    private static final Logger LOG = LoggerFactory.getLogger(SharedSecret.class);

    public SharedSecret() {
    }

    /**
     * Split an Encrypted Master Secret into mnemonic shares. This function is a
     * counterpart to `recover`, and it is used as a subroutine in `generate`.
     * The input is an *already encrypted* Master Secret (EMS), so it is
     * possible to encrypt the Master Secret in advance and perform the
     * splitting later. Decryption of the MS depends on the identifier and
     * iteration exponent, so the same values used for `Crypto.encrypt` must
     * also be used here. Otherwise it will be impossible to recover the
     * original MS from the generated shares.
     *
     * @param threshold The number of groups required to reconstruct the master
     * secret.
     * @param shared_secret The encrypted master secret to split.
     * @param share_count
     * @return List of shares
     * @throws SharedSecretException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    private Map<Integer, byte[]> split(
            int threshold,
            byte[] shared_secret,
            int share_count) throws SharedSecretException, NoSuchAlgorithmException, InvalidKeyException {

        if (threshold < 1) {
            throw new SharedSecretException("Sharing threshold must be >= 1");
        }

        if (share_count > Common.MAX_SHARE_COUNT) {
            throw new SharedSecretException(String.format("Too many shares (%d)", share_count));
        }

        if (threshold > share_count) {
            throw new SharedSecretException("Number of shares should be at least equal threshold");
        }

        Map<Integer, byte[]> shares = new HashMap<>();
        // If the group_threshold is 1, then the digest of the shared secret is not used
        if (threshold == 1) {
            for (int i = 0; i < share_count; i++) {
                shares.put(i, shared_secret);
            }
            return shares;
        }

        if (share_count == 1) {
            shares.put(0, shared_secret);
            return shares;
        }

        for (int i = 0; i < threshold - 2; i++) {
            byte[] share = new byte[shared_secret.length];
            Utils.randomBytes(share);
            shares.put(i, share);
        }
        
        byte[] random_part = new byte[shared_secret.length - DIGEST_LENGTH_BYTES];
        Utils.randomBytes(random_part);
        byte[] mac = Crypto.digest(random_part, shared_secret);
        byte[] digest = Arrays.copyOfRange(mac, 0, DIGEST_LENGTH_BYTES);

        Map<Integer, byte[]> base = new HashMap<>();
        base.putAll(shares);
        base.put(DIGEST_INDEX, Utils.concatenate(digest, random_part));
        base.put(SECRET_INDEX, shared_secret);

        for (int i = threshold - 2; i < share_count; i++) {
            shares.put(i, interpolate(base, i));
        }
        return shares;
    }

    /**
     * Returns f(x) given the Shamir shares (x_1, f(x_1)), ... , (x_k, f(x_k)).
     *
     * @param shares: The Shamir shares. type Map<Integer, byte[]>: A map of pairs (x_i,
     * y_i), where x_i is an integer and y_i is an array of bytes representing
     * the evaluations of the polynomials in x_i.
     * @param x: The x coordinate of the result.
     * @return Evaluations of the polynomials in x. type: bytes[].
     */
    private byte[] interpolate(Map<Integer, byte[]> shares, int x) throws SharedSecretException {

        Set<Integer> x_coord = shares.keySet();
        
        if(x_coord.contains(x)){
            return shares.get(x);
        }
        
        Set<Integer> lengths = new HashSet<>();
        shares.values().forEach((item) -> {
            lengths.add(item.length);
        });
        if(lengths.isEmpty() || lengths.size()> 1){
            throw new SharedSecretException("Invalid set of shares. All share values must have the same length and not de void");
        }
        int length = lengths.iterator().next();

        // Logarithm of the product of (x_i - x) for i = 1, ... , k.
        int log_prod = 0;
        log_prod = shares.keySet().stream().map((i) -> Utils.LOG[i ^ x]).reduce(log_prod, Integer::sum);
        
        byte[] share = new byte[length];
        
         for (int i : shares.keySet()) {
            int sum = 0;
            sum = shares.keySet().stream().map((k) -> Utils.LOG[i ^ k]).reduce(sum, Integer::sum);
            // The logarithm of the Lagrange basis polynomial evaluated at x
            int log_basis_eval = (log_prod - Utils.LOG[i ^ x] - sum) % 255;
            if (log_basis_eval < 0) {
                log_basis_eval += 255;
            }

            int[] intermediate_sum = new int[share.length];
            for (int k = 0; k < share.length; k++) {
                int share_val = shares.get(i)[k] & 0xFF;
                intermediate_sum[k] = share[k] & 0xFF;
                if (share_val != 0) {
                    intermediate_sum[k] ^= Utils.EXP[(Utils.LOG[share_val] + log_basis_eval) % 255];
                } else {
                    intermediate_sum[k] ^= 0;
                }
                share[k] = (byte) intermediate_sum[k];
            }
        }
        return share;
    }

    /**
     * Split a master secret into mnemonic shares using Shamir's secret sharing
     * scheme. The supplied Master Secret is encrypted by the passphrase (empty
     * passphrase is used if none is provided) and split into a set of mnemonic
     * shares. This is the user-friendly method to back up a pre-existing secret
     * with the Shamir scheme, optionally protected by a passphrase.
     *
     * @param groups_threshold: The number of groups required to reconstruct the
     * master secret.
     * @param groups: A list of (group group_threshold, group group_count) pairs for each
     * group, where member_count is the number of shares to generate for the
     * group and member_threshold is the number of members required to
     * reconstruct the group secret.
     * @param master_secret: The master secret to split.
     * @param passphrase: The passphrase used to encrypt the master secret.
     * @param iteration_exponent: The encryption iteration exponent.
     * @return List of groups mnemonics.
     * @throws iton.slip.secret.SharedSecretException
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.security.InvalidKeyException
     */
    public List<String> generate(
            byte[] master_secret,
            String passphrase,
            byte groups_threshold,
            List<Group> groups,
            byte iteration_exponent) throws SharedSecretException, NoSuchAlgorithmException, InvalidKeyException {

        if (master_secret.length * Byte.SIZE < MIN_STRENGTH_BITS || master_secret.length % 2 != 0) {
            throw new SharedSecretException("Master key entropy must be at least 128 bits and multiple of 16 bits");
        }
        if (!CharMatcher.ascii().matchesAllOf(passphrase)) {
            throw new SharedSecretException("Incorrect passphrase chars. The passphrase must contain only printable ASCII characters (code points 32-126).");
        }
        if (groups_threshold > MAX_SHARE_COUNT) {
            throw new SharedSecretException("More than 16 groups are not supported");
        }
        if (groups_threshold > groups.size()) {
            throw new SharedSecretException(String.format("Incorrect group threshold (%d), group count (%d)", groups_threshold, groups.size()));
        }
        for (Group group : groups) {
            if (group.member_threshold == 1 && group.member_count > 1) {
                throw new SharedSecretException("Can only generate one share for member_threshold = 1");
            }
        }
        for (Group group : groups) {
            if (group.member_threshold > group.member_count) {
                throw new SharedSecretException("Number of shares must not be less than member_threshold");
            }
        }

        List<String> mnemonics = new ArrayList<>();
        
        short id = Utils.randomBytes();
        byte[] encrypted_master = Crypto.encrypt(id, iteration_exponent, master_secret, passphrase);
        // Get group shares
        Map<Integer, byte[]> group_shares = split(groups_threshold, encrypted_master, groups.size());
        // Get all mnemonics
        for (int group_index : group_shares.keySet()) {
            Group group = groups.get(group_index);
            Map<Integer, byte[]> member_shares = split(group.member_threshold, group_shares.get(group_index), group.member_count);
            member_shares.keySet().stream().map((member_index) -> Mnemonic.INSTANCE.encode(id,
                    iteration_exponent,
                    group_index,
                    groups_threshold,
                    groups.size(),
                    member_index,
                    group.member_threshold,
                    member_shares.get(member_index)
            )).forEach((mnemonic) -> {
                mnemonics.add(mnemonic);
            });

        }
        return mnemonics;
    }

    public List<String> generate(
            byte[] master_secret,
            byte groups_threshold,
            List<Group> groups) throws SharedSecretException, NoSuchAlgorithmException, InvalidKeyException {

        return generate(master_secret, "", groups_threshold, groups, (byte) 1);
    }

    private Groups decode(String[] mnemonics) throws SharedSecretException {

        Groups root = new Groups();
        for (byte i = 0; i < mnemonics.length; i++) {

            Share share = Mnemonic.INSTANCE.decode(mnemonics[i]);

            if (root.groups.isEmpty()) {
                root.id = share.id;
                root.iteration_exponent = share.iteration_exponent;
                root.group_threshold = share.group_threshold;
                root.group_count = share.group_count;
            } else {
                if (share.iteration_exponent != root.iteration_exponent) {
                    throw new SharedSecretException(String.format("Iteration numbers of shares are inconsistent... %d/%d",
                            share.iteration_exponent, root.iteration_exponent));
                }
                
                if (share.id != root.id) {
                    throw new SharedSecretException(String.format("Invalid id... %d/%d",
                            share.id, root.id));
                }

                if (share.group_count != root.group_count) {
                    throw new SharedSecretException(String.format("Group count of shares are inconsistent... %d/%d",
                            share.group_count, root.group_count));
                }

                if (share.group_threshold != root.group_threshold) {
                    throw new SharedSecretException(String.format("Group threshold of shares are inconsistent... %d/%d",
                            share.group_threshold, root.group_threshold));
                }
            }

            Group group;
            if (root.groups.containsKey(share.group_index)) {
                group = root.groups.get(share.group_index);
            } else {
                group = new Group();
                group.member_threshold = share.member_threshold;
                root.groups.put(share.group_index, group);
            }
            
            if(group.member_threshold != share.member_threshold){
                throw new SharedSecretException(String.format("Mismatching member thresholds... %d/%d", group.member_threshold, share.member_threshold));
            }
            
            if(group.shares.containsKey(share.member_index)){
                throw new SharedSecretException(String.format("Duplicate member index %d", share.member_index));
            }
            group.shares.put(share.member_index, share.value);
        }
        
        if(root.groups.size() < root.group_threshold){
            throw new SharedSecretException(String.format("Insufficient number of mnemonic groups, %d. %d is required", root.groups.size(), root.group_threshold));
        }
        if (root.groups.size() != root.group_threshold) {
            throw new SharedSecretException(String.format("Wrong number of mnemonic groups (%d). Threshold: %d", root.groups.size(), root.group_threshold));
        }
        return root;
    }

    /**
     * Combine mnemonic shares to obtain the master secret which was previously
     * split using Shamir's secret sharing scheme. This is the user-friendly
     * method to recover a backed-up secret optionally protected by a
     * passphrase.
     *
     * @param mnemonics: List of mnemonics.
     * @param passphrase The passphrase used to encrypt the master secret.
     * @return The master secret.
     * @throws SharedSecretException
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.security.InvalidKeyException
     */
    public byte[] combine(String[] mnemonics, String passphrase) throws SharedSecretException, NoSuchAlgorithmException, InvalidKeyException {

        if (mnemonics == null || mnemonics.length == 0) {
            throw new SharedSecretException("The list of mnemonic is empty...");
        }

        for (String mnemonic : mnemonics) {
            int length = mnemonic.split(" ").length;
            if (length < MNEMONIC_WORDS_MIN || length > MNEMONIC_WORDS_MAX) {
                throw new SharedSecretException(String.format("Mnemonic length is not legal. (length:%d)", mnemonics.length));
            }
        }

        Groups root = decode(mnemonics);
        Map<Integer, byte[]> group_shares = new HashMap<>();
        
        for (Integer index : root.groups.keySet()) {
            Group group = root.groups.get(index);
            if (group.shares.size() < group.member_threshold) {
                throw new SharedSecretException(String.format("Member number is less than threshold... %d/%d",
                        group.shares.size(),
                        group.member_threshold));
            }
            
            byte[] group_share = recover(group.shares);
            group_shares.put(index, group_share);
        }
        byte[] encrypted_master = recover(group_shares);
        return Crypto.decrypt((short)root.id, (byte)root.iteration_exponent, encrypted_master, passphrase);
    }
    
    private byte[] recover(Map<Integer, byte[]> shares) throws SharedSecretException, NoSuchAlgorithmException, InvalidKeyException{
        
        if(shares.values().size() == 1){
            return shares.values().iterator().next();
        }
        
        byte[] shared_secret = interpolate(shares, SECRET_INDEX);
        byte[] digest_share = interpolate(shares, DIGEST_INDEX);
        
        byte[] random_part = Arrays.copyOfRange(digest_share, DIGEST_LENGTH_BYTES, digest_share.length);
        byte[] mac = Crypto.digest(random_part, shared_secret);
        byte[] digest = Arrays.copyOfRange(mac, 0, DIGEST_LENGTH_BYTES);
        
        if(!Arrays.equals(digest_share, Utils.concatenate(digest, random_part))){
            throw new SharedSecretException("Invalid digest");
        }
        return shared_secret;
    }
}
