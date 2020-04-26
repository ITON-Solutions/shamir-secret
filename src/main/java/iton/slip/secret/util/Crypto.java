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

import com.google.common.primitives.Shorts;
import static iton.slip.secret.Common.BASE_ITERATION_COUNT;
import static iton.slip.secret.Common.CUSTOMIZATION_STRING;
import static iton.slip.secret.Common.ROUND_COUNT;
import iton.slip.secret.SharedSecretException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.spongycastle.crypto.digests.SHA256Digest;
import org.spongycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.spongycastle.crypto.params.KeyParameter;

/**
 *
 * @author ITON Solutions
 */
public class Crypto {

    // encrypt master with a passphrase
    public static byte[] encrypt(short id,
            byte iteration_exponent,
            byte[] master, String passphrase) throws SharedSecretException {
        // get salt
        byte[] salt = new byte[CUSTOMIZATION_STRING.length + Short.BYTES];
        System.arraycopy(CUSTOMIZATION_STRING, 0, salt, 0, CUSTOMIZATION_STRING.length);
        System.arraycopy(Shorts.toByteArray(id), 0, salt, CUSTOMIZATION_STRING.length, Short.BYTES);

        byte[] IL = Arrays.copyOfRange(master, 0, master.length / 2);
        byte[] IR = Arrays.copyOfRange(master, master.length / 2, master.length);

        for (byte i = 0; i < ROUND_COUNT; i++) {
            byte[] round = round(i, passphrase, iteration_exponent, salt, IR);
            byte[] xor = Utils.xor(IL, round);
            IL = IR;
            IR = xor;
        }
        return Utils.concatenate(IR, IL);
    }

    // decrypt encrypted master with a passphrase
    public static byte[] decrypt(short id,
            byte iteration_exponent,
            byte[] encrypted_master, String passphrase) throws SharedSecretException {
        // get salt
        byte[] salt = new byte[CUSTOMIZATION_STRING.length + Short.BYTES];
        System.arraycopy(CUSTOMIZATION_STRING, 0, salt, 0, CUSTOMIZATION_STRING.length);
        System.arraycopy(Shorts.toByteArray(id), 0, salt, CUSTOMIZATION_STRING.length, Short.BYTES);

        byte[] IL = Arrays.copyOfRange(encrypted_master, 0, encrypted_master.length / 2);
        byte[] IR = Arrays.copyOfRange(encrypted_master, encrypted_master.length / 2, encrypted_master.length);

        for (byte i = ROUND_COUNT - 1; i >= 0; i--) {
            byte[] round = round(i, passphrase, iteration_exponent, salt, IR);
            byte[] xor = Utils.xor(IL, round);
            IL = IR;
            IR = xor;
        }
        return Utils.concatenate(IR, IL);
    }

    private static byte[] round(byte round, String passprase, int iteration_exponent, byte[] salt, byte[] IR) {

        int iteration_count = (BASE_ITERATION_COUNT << iteration_exponent) / ROUND_COUNT;
        byte[] password = new byte[passprase.getBytes().length + 1];
        password[0] = round;
        System.arraycopy(passprase.getBytes(), 0, password, 1, passprase.getBytes().length);
        byte[] secret = Utils.concatenate(salt, IR);

        PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator(new SHA256Digest());
        generator.init(password, secret, iteration_count);
        KeyParameter key = (KeyParameter) generator.generateDerivedMacParameters(IR.length * Byte.SIZE);
        return key.getKey();
    }
    
    public static byte[] digest(byte[] random_data, byte[] shared_secret) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(random_data, "HmacSHA256"));
        return mac.doFinal(shared_secret);
    }
}
