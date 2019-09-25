package cn.gudqs.crypto;

import cn.gudqs.crypto.util.Base64Util;
import cn.gudqs.crypto.util.RSAHelper;
import cn.gudqs.crypto.util.RSAUtil;

import java.nio.charset.StandardCharsets;
import java.util.Map;

public class Main {

//    private static String privateKey = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAJEq5BlUar57utzY+9Tha8GLK/ufni6qdhKZYmCdA6ES8tRvE2sBu4+9nKyK/lgv5QqWh19ygoWhDPmnZvoPGcbeGcHbMZ4YlXGyEgOjmIR33NqG9BrqixOcNPWEfme7Jn5f35iL2pkmMeGZd8aeGYdxDUjpIUgLkctrdyvt3NVhAgMBAAECgYBUaKcnH1HOHq3B2p1b5BM+/8h8UAyvP8jV+cAdQ08n6pet9ERLNT+1TeB653sLFhZM+MgQNMo2HzYnODKFdiBa/bBCjiDFft0xUXlbtXUSBsTFQEiepGii5ILRnSDqEvcpcQ/3sbhZ5q8RKXXcZBignzGN3rcizFJRxodMiFTQAQJBAPiiDY3g4XsAr4KiuLwzjeWKMUnFcabZLQdZ2z0ky82zk7Qr6KnaSMP0tJDqmqtZuset4iNq+2lYE3XMFQd25OECQQCVeAZuyeI33fgh6enl9U7YoJoye0JtHaQKF6MVOVrfN/9rvpeE3RS95E/t8sSStan8IS36JvZVB2u7e95l44CBAkEA1Tyu4ULAP20MGb8TLx4MEZRex0VWPuG987MGC7+WJzpfcEPETIBQrfceMbdzpYfUYFLqQrQLIYMPVZUNaBR5IQJBAIT2F2rYhjdCaufoSFx7Ip+MBn9frJCabIFZ04Ye1lp5WurCydC0Ri5B+mRmsDz+A2+5KEg9/qVXC5vlLcqfXYECQH77xj2FjxWJJR3j2Dwxdq9XTFzVwVjFxqoH25K9YvpFj1cfJc3SdSKxUs8++i2KMIuWugSSA0VCGSQG4GwNWKs=";

    public static void main(String[] args) throws Exception {
        String source = "这是一行测试RSA数字签名的无意义文字";
        System.out.println("原文字：\r\n" + source);

        Map<String, Object> keyPairMap = RSAUtil.genKeyPair();
        String publicKey = RSAUtil.getPublicKey(keyPairMap);
        String privateKey = RSAUtil.getPrivateKey(keyPairMap);

        //私钥加密
        byte[] data = source.getBytes();
        byte[] encodedData = RSAUtil.encryptByPrivateKey(data, privateKey);
        String base64EncodedData = Base64Util.encodeByte(encodedData);
        System.out.println("加密后BASE64：\r\n" + base64EncodedData);

        //公钥解密
//        String res = decryptByPublic(base64EncodedData, publicKey);
//        System.out.println("解密后: " + res);

        // chat
        String pbK = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkoyNFn/9EZWzO9s23v90\n" +
                "OB3JxzHo9LVJYZm7KnPAz3P2/MqUS4gNvBqzxqMBUSapUKB46QvL6f9c2SUrgeD2\n" +
                "Ke5tR0n6PWVk0EkFkIMb65XPcq6/Id9ozdYVNAukex8C+Qus9A+nk+w+RyuphZHa\n" +
                "l6rgagxLuURX8L6uOW5sBefnkK43O/N9wExPeGrwIFEBWSJsj0tZl4D/UZtBnDbZ\n" +
                "IBTeFXNFdnDcVSwnwVPXLLzSM+3PfAZJZOyUF1NW8E9BML/HBtnSEAmku6sdZR2/\n" +
                "yNcREkLQ+m6ZPghHjtBibMGCu4A1etDOpzlclmH5DDF9l0l/BuDOg6VR2Ggt5GIT\n" +
                "rwIDAQAB";
        String base64Source = "jn8+AhSS7mJct6DaHSkdo4NVv5zAkIisxdxXUsEWX9qXTJ7VGBZLXSfYah/xmQkm1gWZsdvf9CtP9Z7tD/ldM9G9gpjuABCTo1eSGYTDe0m+nY/6W5hXEMBF1/kj0hr+LESZjSLzuwgDFHcec8PFyvNXE2y+skqK1LStMaAB+KTLBrHt4uHpG3gnWPcOiBQ/Nte/Fw5G4xyBi5KVrrRnI8lYvSwMsA6u1dYQGjT0rBMzEaDVnvLr8Zqe+sy9xrLJUl8nAI/Fqnj3dLd7PDwLlYqL09j/aFtXWrgx/0wWlUzqQA5Q37auW2udzKvM3Ovq59UZWXKPUYLUSs6+yiV0lQ==";
        String result = decryptByPublic(base64Source, pbK);
        System.out.println("chat: ");
        System.out.println(result);
    }

    public static String decryptByPublic(String base64Source, String publicKey) throws Exception {
        byte[] encodedData = Base64Util.base64Decode(base64Source);
        RSAHelper rsaHelper = RSAHelper.getInstance();
        rsaHelper.loadPublicKeyPEM(publicKey);
        byte[] res = rsaHelper.decryptByPublicKey(encodedData);
        String res0 = Base64Util.encodeByte(res);
        return res0;
    }
    /**
     * 得到 base64 的 一串字符, 然后根据 js中代码, 将base64转二进制后转成16进制, 然后在getSharedKey方法中与某数字modPow运算,得到 aes 的密钥
     * fFf5Ko5P1aH7WRTn95FvbRhps5wDrIeEqGjM/dCgMb7XZzlT/ZaLDTQsUztWKVv/5L6B5qjcCIgbDoZxvkOidwriD35SRWLOKQ/GXlrOvLTFkMllQm8bXxOUHob/OmTEUkRYE3LcuSTFf7TCiqAc1v2QeysDzp+yPqRBhAdYv9U=
     * fFf5Ko5P1aH7WRTn95FvbRhps5wDrIeEqGjM/dCgMb7XZzlT/ZaLDTQsUztWKVv/5L6B5qjcCIgbDoZxvkOidwriD35SRWLOKQ/GXlrOvLTFkMllQm8bXxOUHob/OmTEUkRYE3LcuSTFf7TCiqAc1v2QeysDzp+yPqRBhAdYv9U=
     */
}
