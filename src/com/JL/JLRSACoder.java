package com.JL;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.signers.DSADigestSigner;
import org.bouncycastle.crypto.signers.RSADigestSigner;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;


public class JLRSACoder {
    public static final String KEY_ALGORITHM = "RSA";

    //系统加密
    public static final String KEY_PROVIDER = "BC";

    public static final String SIGNATURE_ALGORITHM = "SHA1WithRSA";

    public static final String   charset = "utf-8";
    static{
        try{
            Security.addProvider(new BouncyCastleProvider());
        }catch(Exception e){
            e.printStackTrace();
        }
    }





    public static String sign(byte[] encoderData, byte[] privateInfoByte) throws Exception {
        PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(privateInfoByte));
        Signature sig = Signature.getInstance(SIGNATURE_ALGORITHM, KEY_PROVIDER);
        sig.initSign(privateKey);
        sig.update(encoderData);
        return new String(Base64.getEncoder().encode(sig.sign()));
    }

    /**
     * 校验数字签名
     */
    public static boolean verify(byte[] encoderData, String sign, byte[] publicInfoByte) throws Exception {
        PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicInfoByte));
        Signature sig = Signature.getInstance(SIGNATURE_ALGORITHM, KEY_PROVIDER);
        sig.initVerify(publicKey);
        sig.update(encoderData);
        return sig.verify(Base64.getDecoder().decode(sign.getBytes()));
    }



    // 使用N、e值还原公钥
    public static PublicKey getPublicKey(byte[] publicInfoByte) throws NoSuchAlgorithmException, InvalidKeySpecException {
        PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicInfoByte));
        return publicKey;
    }

    // 使用N、d值还原私钥
    public static PrivateKey getPrivateKey(byte[] publicInfoByte) throws NoSuchAlgorithmException, InvalidKeySpecException {
        PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(publicInfoByte));
        return privateKey;
    }




    /**
     * 私钥加密
     * @param data
     * @param privateInfoByte
     * @return
     * @throws IOException
     * @throws InvalidCipherTextException
     */
    public static String encryptData(String data,  byte[] privateInfoByte) throws IOException, InvalidCipherTextException {

        AsymmetricBlockCipher cipher = new RSAEngine();
        //这里也可以从流中读取，从本地导入
        AsymmetricKeyParameter priKey = PrivateKeyFactory.createKey(privateInfoByte);
        //true表示加密
        cipher.init(true, priKey);
        byte[] encryptDataBytes = cipher.processBlock(data.getBytes(charset)
                , 0, data.getBytes(charset).length);
        return  Base64.getEncoder().encodeToString(encryptDataBytes);
    }

    /**
     * 公钥解密
     * @param data
     * @param publicInfoBytes
     * @return
     * @throws IOException
     * @throws InvalidCipherTextException
     */
    public static String decryptData(String data,  byte[] publicInfoBytes) throws IOException, InvalidCipherTextException {
        AsymmetricBlockCipher cipher = new RSAEngine();
        byte[] encryptDataBytes=Base64.getDecoder().decode(data);
        //解密
        ASN1Object pubKeyObj = ASN1Primitive.fromByteArray(publicInfoBytes);
        AsymmetricKeyParameter pubKey = PublicKeyFactory.createKey(SubjectPublicKeyInfo.getInstance(pubKeyObj));
        //false表示解密
        cipher.init(false, pubKey);
        byte[] decryptDataBytes=cipher.processBlock(encryptDataBytes, 0, encryptDataBytes.length);
        return new String(decryptDataBytes, charset);
    }

    public static String byteArrayToHexStr(byte[] src){
        StringBuilder stringBuilder = new StringBuilder("");
        if (src == null || src.length <= 0) {
            return null;
        }
        for (int i = 0; i < src.length; i++) {
            int v = src[i] & 0xFF;
            String hv = Integer.toHexString(v);
            if (hv.length() < 2) {
                stringBuilder.append(0);
            }
            stringBuilder.append(hv);
        }
        return stringBuilder.toString();
    }


}
