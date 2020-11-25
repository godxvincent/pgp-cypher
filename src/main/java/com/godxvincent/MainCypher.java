// Links de información
// https://www.codesandnotes.be/2018/09/04/openpgp-integration-java-and-javascript-java-pgp-encryption/
// https://github.com/codesandnotes/openpgp-integration
// Como instalar librerias con gradle
// https://neuhalje.github.io/bouncy-gpg/

package com.godxvincent;

import org.bouncycastle.openpgp.PGPException;

import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.SignatureException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;

public class MainCypher {

    private static final Logger LOGGER = LoggerFactory.getLogger(MainCypher.class);

    // https://www.codesandnotes.be/2018/09/04/openpgp-integration-java-and-javascript-java-pgp-encryption/
    public static void main(String[] args) {

        MainCypher clasePrincipalCifrado = new MainCypher();
        // Lee llave publica y la deja en string
        String llavePublicaSender = clasePrincipalCifrado.readFileInput("ricardo andres vargas martinez_0xA5E84250_public.asc");
        String llavePrivadaSender = clasePrincipalCifrado.readFileInput("ricardo andres vargas martinez_0xA5E84250_SECRET.asc");
        String llavePublicaReceiver = clasePrincipalCifrado.readFileInput("ricardo andres vargas_0x4ABE8134_public.asc");
        String llavePrivadaReceiver = clasePrincipalCifrado.readFileInput("ricardo andres vargas_0x4ABE8134_SECRET.asc");
        // La llave privada del receptor no la tenemos nosotros solo el cliente.
        String contenidoCifrar = clasePrincipalCifrado.readFileInput("textoTest.txt");
        String userSenderIdEmail = "godxvincent@gmail.com";
        String userSenderPassphrase = "gm0$MhRbNsR4oRo6L5hVk9Andh&i9iJZ";
        String userReceiverIdEmail = "godxvincent@hotmail.com";
        boolean archivoCifrado = clasePrincipalCifrado.cifrarArchivo(userSenderIdEmail,
                userSenderPassphrase,
                userReceiverIdEmail,
                llavePublicaSender,
                llavePrivadaSender,
                llavePublicaReceiver,
                contenidoCifrar,
                "textoTest.pgp");
        if (archivoCifrado) {
            System.out.println("El archivo de entrada fue cifrado correctamente");
        }
    }

    /*
    Lee los archivos de input de la carpeta resources.
    **/
    public String readFileInput(String fileName) {
        InputStream fileInput = null;
        String contents = null;
        try {
            ClassLoader classLoader = getClass().getClassLoader();
            fileInput = classLoader.getResourceAsStream(fileName);
            ByteArrayOutputStream bais = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            int length;
            while ((length = fileInput.read(buffer)) != -1) {
                bais.write(buffer, 0, length);
            }

            contents = bais.toString(StandardCharsets.UTF_8.name());
            fileInput.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return contents;
    }

    public boolean cifrarArchivo(String userSenderIdEmail,
                                 String userSenderPassphrase,
                                 String userReceiverIdEmail,
                                 String senderPublicKey,
                                 String senderPrivateKey,
                                 String receiverPublicKey,
                                 String unencryptedMessage,
                                 String fileNameOutput) {

        SecureRandom secureRandom;
        OpenPGP openPgp;
        boolean cifroArchivo = false;

        try {
            secureRandom = SecureRandom.getInstanceStrong();
            openPgp = new OpenPGP(secureRandom);

            FileOutputStream archivoCifrado = new FileOutputStream(fileNameOutput);

            ByteArrayOutputStream arregloBytesCifrado = openPgp.encryptAndSignToFile(
                    unencryptedMessage,
                    userSenderIdEmail,
                    userSenderPassphrase,
                    OpenPGP.ArmoredKeyPair.of(senderPrivateKey, senderPublicKey),
                    userReceiverIdEmail,
                    receiverPublicKey);
            arregloBytesCifrado.writeTo(archivoCifrado);
            cifroArchivo = true;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Could not initialize a strong secure random instance", e);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (PGPException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
        return cifroArchivo;
    }

}
