package com.kingbom.digital.signature.service;

import com.google.common.io.ByteStreams;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

@Slf4j
@Component
public class SignatureService {

    public String privateKeyName = "src/main/resources/config/private_key.der";

    public String publicKeyName = "src/main/resources/config/public_key.der";

    private PrivateKey privateKey;

    private PublicKey publicKey;

    private KeyFactory keyFactory;

    private Signature sign;

    public SignatureService() throws Exception {
        keyFactory = KeyFactory.getInstance("RSA");
        sign = Signature.getInstance("SHA256withRSA");
    }

    public byte[] signSignature(String message) throws Exception {
        byte[] priKeyBytes = getKeyBytes(privateKeyName);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(priKeyBytes);
        privateKey = keyFactory.generatePrivate(spec);
        sign.initSign(privateKey);
        sign.update(message.getBytes());
        return sign.sign();
    }

    public boolean verify(String message, byte[] signature) throws Exception {
        byte[] pubKeyBytes = getKeyBytes(publicKeyName);
        X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(pubKeyBytes);
        publicKey = keyFactory.generatePublic(pubSpec);
        sign.initVerify(publicKey);
        sign.update(message.getBytes());
        return sign.verify(signature);
    }

    public byte[] getKeyBytes(String path){
        try(InputStream inputStream = Files.newInputStream(Paths.get(path))){
            return ByteStreams.toByteArray(inputStream);
        } catch (Exception e) {
            log.error("getKeyBytes Exception : ", e);
            throw new RuntimeException(e);
        }
    }
}
