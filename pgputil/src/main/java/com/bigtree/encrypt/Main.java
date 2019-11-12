package com.bigtree.encrypt;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

/**
 * @author xianqiangliu
 */
public class Main {
    public static void main(String[] s) throws Exception{
        Security.addProvider(new BouncyCastleProvider());
        KeyBasedFileProcessor kbfp = new KeyBasedFileProcessor();

        //boolean encryp = false ;  //加密：true   解密：false
        /*if (encryp) {
            String outPath = "E:/pgp/outFilePath/adi.txt.asc";//加密后输出的文件
            String inputPath = "E:/pgp/adi.txt";//加密前的文件
            String publicKeys = "E:/pgp/publicKeyPath/publickey_for_test4096pgp.key";  //公钥地址
            kbfp.encryptFile(outPath, inputPath, publicKeys, true, true);
        }else{
            String password = "11111111";  //私钥的Key
            String inputPath = "E:/pgp/outFilePath/adi.txt.asc";  //加密后的文件
            String privateKeys = "E:/pgp/privateKeyPath/secretkey_for_test4096pgp.key";//私钥地址
            String outPath = "E:/pgp/outFilePath/adi.ok.txt";//解密后的文件
            kbfp.decryptFile(inputPath, privateKeys, password.toCharArray(), outPath);
        }*/
        boolean encryp = false ;  //加密：true   解密：false
        if (encryp) {
            String outPath = "pgputil/src/main/resources/adi.txt.asc";//加密后输出的文件
            String inputPath = "pgputil/src/main/resources/adi.txt";//加密前的文件
            String publicKeys = "pgputil/src/main/resources/publickey_for_test4096pgp.key";  //公钥地址
            kbfp.encryptFile(outPath, inputPath, publicKeys, true, true);
        }else{
            String password = "11111111";  //私钥的Key
            String inputPath = "pgputil/src/main/resources/adi.txt.asc";  //加密后的文件
            String privateKeys = "pgputil/src/main/resources/secretkey_for_test4096pgp.key";//私钥地址
            String outPath = "pgputil/src/main/resources/adi.ok.txt";//解密后的文件
            kbfp.decryptFile(inputPath, privateKeys, password.toCharArray(), outPath);
        }

    }
}
