package cn.gudqs.crypto.util;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import java.io.IOException;

/**
 * @author wq
 * @date 2019/9/25
 * @description crypto
 */
public class Base64Util {

    public static String encodeByte(byte[] encodedData) {
        return base64Encode(encodedData);
    }

    public static byte[] decodeString(String publicKey) throws IOException {
        return base64Decode(publicKey);
    }

    public static String base64Encode(byte[] data) {
        return new BASE64Encoder().encode(data);
    }

    public static byte[] base64Decode(String data) throws IOException {
        return new BASE64Decoder().decodeBuffer(data);
    }

}
