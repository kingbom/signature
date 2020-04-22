package com.kingbom.digital.signature.security;

import com.kingbom.digital.signature.service.SignatureService;
import org.junit.Assert;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class SignatureTest {

    private SignatureService signature;

    @BeforeEach
    void setUp() throws Exception {
        signature = new SignatureService();
    }

    @Test
    void givenMessageDog_whenSignaturesVerifyWithMessageDeg_thenVerifyPass() throws Exception {
        byte[] messageSignature =  signature.signSignature("dog");
        Assert.assertTrue(signature.verify("dog", messageSignature));
    }

    @Test
    void givenMessageDog_whenSignaturesAndVerifyWithMessageCat_thenVerifyNotPass() throws Exception {
        byte[] messageSignature = signature.signSignature("dog");
        Assert.assertFalse(signature.verify("cat", messageSignature));
    }
}
