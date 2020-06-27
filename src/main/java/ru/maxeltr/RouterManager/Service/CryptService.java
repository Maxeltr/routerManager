/*
 * The MIT License
 *
 * Copyright 2019 Maxim Eltratov <Maxim.Eltratov@yandex.ru>.
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
package ru.maxeltr.RouterManager.Service;

import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import ru.maxeltr.RouterManager.Config.Config;


/**
 *
 * @author Maxim Eltratov <Maxim.Eltratov@yandex.ru>
 */
public class CryptService {

    private char[] pin;
    private final Cipher pbeCipher;

    private static final Logger logger = Logger.getLogger(CryptService.class.getName());

    public CryptService() throws NoSuchAlgorithmException, NoSuchPaddingException {
        this.pbeCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    }

    public SecretKeySpec createSecretKey(char[] password, byte[] salt, int iterationCount, int keyLength) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
        PBEKeySpec keySpec = new PBEKeySpec(password, salt, iterationCount, keyLength);
        SecretKey keyTmp = keyFactory.generateSecret(keySpec);
        return new SecretKeySpec(keyTmp.getEncoded(), "AES");
    }

    public String encrypt(byte[] value) {
        return this.encipher(value, this.getPin());
    }

    public String encrypt(byte[] value, char[] secretKey) {
        return this.encipher(value, secretKey);
    }

    private String encipher(byte[] value, char[] secretKey) {
        if (value.length == 0 || secretKey.length == 0) {
            return "";
        }

        String encryptedValue;
        byte[] cryptoText, iv;
        try {
            SecretKeySpec key = createSecretKey(secretKey, Config.SALT, Config.ITERATION_COUNT, Config.KEY_LENGTH);
            this.pbeCipher.init(Cipher.ENCRYPT_MODE, key);
            AlgorithmParameters parameters = this.pbeCipher.getParameters();
            IvParameterSpec ivParameterSpec = parameters.getParameterSpec(IvParameterSpec.class);
            cryptoText = this.pbeCipher.doFinal(value);
            iv = ivParameterSpec.getIV();
            encryptedValue = base64Encode(iv) + ":" + base64Encode(cryptoText);
        } catch (Exception ex) {
            logger.log(Level.SEVERE, String.format("Cannot encipher data.%n"), ex);

            return "";
        }

        return encryptedValue;
    }

    public byte[] decrypt(String value) {
        return this.decipher(value, this.getPin());
    }

    public byte[] decrypt(String value, char[] secretKey) {
        return this.decipher(value, secretKey);
    }

    private byte[] decipher(String value, char[] secretKey) {
        byte[] decryptedValue = new byte[0];

        if (value.isEmpty() || secretKey.length == 0) {
            return decryptedValue;
        }

        String iv, cryptoText;
        try {
            SecretKeySpec key = createSecretKey(secretKey, Config.SALT, Config.ITERATION_COUNT, Config.KEY_LENGTH);
            iv = value.split(":")[0];
            cryptoText = value.split(":")[1];
            this.pbeCipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(base64Decode(iv)));
            decryptedValue = this.pbeCipher.doFinal(base64Decode(cryptoText));
        } catch (Exception ex) {
            logger.log(Level.SEVERE, String.format("Cannot decipher data.%n"), ex);
        }

        return decryptedValue;
    }

    public void setPin(char[] pin) {
        this.pin = pin;
    }

    public char[] getPin() {
        return this.pin;
    }

    private String base64Encode(byte[] value) {
        return Base64.getEncoder().encodeToString(value);
    }

    private byte[] base64Decode(String value) {
        return Base64.getDecoder().decode(value);
    }

}
