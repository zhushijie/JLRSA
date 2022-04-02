package com.JL;

import com.alibaba.fastjson.JSONObject;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;

import javax.crypto.SecretKey;
import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

public class JLRSACoderEEA {



    /*生成licence文件
    * */
    public static void main(String[] args) throws Exception {


        Scanner input = new Scanner(System.in);
        String hardwarekey = null;       // 记录输入度的字符串
        System.out.println("请输入机器码：");
        hardwarekey = input.next();       // 等待输入值
        System.out.println("您输入机器码是："+hardwarekey);
        // Map<String, Object> keyMap = JLRSACoder.initKeys("julingkeji");
        Map<String,Object> datamap=new HashMap<>();
        if(null==hardwarekey||hardwarekey.equals("")){
            System.out.println("机器码有误");
            return;
        }
        //用户使用信息

        datamap.put("Product.name", "承德市招生办中考系统");
        datamap.put("Product.version", "2.0");
        datamap.put("Product.type", "年度用户");
        datamap.put("Product.hardwarekey",hardwarekey);
        datamap.put("License.expiry","2022-10-20");

        String pubKeyBase64str="";
        String priKeyBase64str="";

        RSAKeyPairGenerator rsaKeyPairGenerator = new RSAKeyPairGenerator();
        RSAKeyGenerationParameters rsaKeyGenerationParameters = new RSAKeyGenerationParameters(BigInteger.valueOf(3), new SecureRandom(), 2048, 25);
        //初始化参数
        rsaKeyPairGenerator.init(rsaKeyGenerationParameters);
        AsymmetricCipherKeyPair keyPair = rsaKeyPairGenerator.generateKeyPair();
        //公钥
        AsymmetricKeyParameter publicKeyParameter = keyPair.getPublic();
        //私钥
        AsymmetricKeyParameter privateKeyParameter = keyPair.getPrivate();

        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicKeyParameter);
        ASN1Object asn1ObjectPublic = subjectPublicKeyInfo.toASN1Primitive();
        byte[] publicInfoByte = asn1ObjectPublic.getEncoded();

        PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(privateKeyParameter);
        ASN1Object asn1ObjectPrivate = privateKeyInfo.toASN1Primitive();
        byte[] privateInfoByte = asn1ObjectPrivate.getEncoded();


        //需加密的原始数据
        JSONObject json = new JSONObject(datamap);
        String str=json.toJSONString();
        //数据进行base64编码
        str= Base64.getEncoder().encodeToString(str.getBytes());
        //对data base64进行私钥加密
        String encoderData=JLRSACoder.encryptData(str,privateInfoByte);
        //对数据b获得签名
        String sign = JLRSACoder.sign(encoderData.getBytes(), privateInfoByte);

        //System.out.println("数据原文Base64：" + str);
        pubKeyBase64str= Base64.getEncoder().encodeToString(publicInfoByte);
        System.out.println("公钥：" + pubKeyBase64str);
        System.out.println("data私钥密文：" +str);
        System.out.println("data私钥加密密文：" +encoderData);
        String decoderData=JLRSACoder.decryptData(encoderData,publicInfoByte);
        System.out.println("data私钥解密文：" +decoderData);
        System.out.println("sign：" +sign);
        System.out.println("verify：" +JLRSACoder.verify(encoderData.getBytes(),sign,publicInfoByte));



        Properties prop = new Properties();
        FileOutputStream oFile = new FileOutputStream("eeaLisence.properties", false);//true表示追加打开
        prop.setProperty("Product.name", "承德市招生办中考系统");
        prop.setProperty("Product.version", "2.0");
        prop.setProperty("Product.type", "年度用户");
        prop.setProperty("License.hardwarekey", hardwarekey);

        prop.setProperty("License.expiry", datamap.get("License.expiry").toString());
        prop.setProperty("License.publicKey", pubKeyBase64str);
        prop.setProperty("License.data",encoderData );
        prop.setProperty("License.signature", sign);

        BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(oFile, "utf-8"));
        bw.newLine();
        for(Enumeration<?> e = prop.keys(); e.hasMoreElements();) {
            String key = (String)e.nextElement();
            String val = prop.getProperty(key);
            bw.write(key + "=" + val);
            bw.newLine();
        }
        bw.flush();
        oFile.close();
    }
}
