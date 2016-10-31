//package atnf.atoms.mon.util;

package sec;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;

public class RSA {
    private BigInteger n, d, e;
    private int bitlen = 1024;
    
    /** Create an instance that can encrypt using someone elses public key. */
    public RSA(BigInteger newn, BigInteger newe) {
        n = newn;
        e = newe;
    }
    
    /** Create an instance that can both encrypt and decrypt. */
    public RSA(int bits) {
        bitlen = bits;
        SecureRandom r = new SecureRandom();
        BigInteger p = new BigInteger(bitlen / 2, 100, r);
        BigInteger q = new BigInteger(bitlen / 2, 100, r);
        n = p.multiply(q);
        BigInteger m = (p.subtract(BigInteger.ONE)).multiply(q
                .subtract(BigInteger.ONE));
        e = new BigInteger("3");
        while (m.gcd(e).intValue() > 1) {
            e = e.add(new BigInteger("2"));
        }
        d = e.modInverse(m);
    }
    
    /** Encrypt the given plaintext message. */
    public synchronized String encrypt(String message) {
        return (new BigInteger(message.getBytes())).modPow(e, n).toString(16);
    }
    
    /** Encrypt the given plaintext message. */
    public synchronized BigInteger encrypt(BigInteger message) {
        return message.modPow(e, n);
    }
    
    /** Decrypt the given ciphertext message. */
    public synchronized String decrypt(String message) {
        return new String((new BigInteger(message)).modPow(d, n).toByteArray());
    }
    
    /** Decrypt the given ciphertext message. */
    public synchronized BigInteger decrypt(BigInteger message) {
        return message.modPow(d, n);
    }
    
    /** Generate a new public and private key set. */
    public synchronized void generateKeys() {
        SecureRandom r = new SecureRandom();
        BigInteger p = new BigInteger(bitlen / 2, 100, r);
        BigInteger q = new BigInteger(bitlen / 2, 100, r);
        n = p.multiply(q);
        BigInteger m = (p.subtract(BigInteger.ONE)).multiply(q
                .subtract(BigInteger.ONE));
        e = new BigInteger("3");
        while (m.gcd(e).intValue() > 1) {
            e = e.add(new BigInteger("2"));
        }
        d = e.modInverse(m);
    }
    
    /** Return the modulus. */
    public synchronized BigInteger getN() {
        return n;
    }
    
    /** Return the public key. */
    public synchronized BigInteger getE() {
        return e;
    }
    
    /** Trivial test program. */
    public static void main(String[] args) {
        RSA rsa = new RSA(1024);
        
        String text1 = "Yellow and Black Border Collies";
        System.out.println("Plaintext: " + text1);
        BigInteger plaintext = new BigInteger(text1.getBytes());
        
        BigInteger ciphertext = rsa.encrypt(plaintext);
        System.out.println("Ciphertext: " + ciphertext.toString(16));
        plaintext = rsa.decrypt(ciphertext);
        
        String text2 = new String(plaintext.toByteArray());
        System.out.println("Plaintext: " + text2);
        System.out.println("");
        System.out.println("");
        //encrypts a message with the public key of the receiver
        System.out.println("---------------------------------------------");
        String encrypted = rsa.sendMessage("My name is Murilo", rsa.getN(), rsa.getE());
        System.out.println("encrypted: "+encrypted);
        System.out.println("---------------------------------------------");
        String decrypted = rsa.receiveMessage(new BigInteger(encrypted,16), rsa.getN(), rsa.getE());
        System.out.println("decrypted: "+decrypted);
    }
    
    public synchronized String sendMessage(String plainTextMessage, BigInteger n, BigInteger e){
        try {
            MessageDigest digestor = MessageDigest.getInstance("SHA-256");
            //CREATES THE SIGNATURE HEADER
            String hashedSignature = "";
            byte[] hash = digestor.digest(plainTextMessage.getBytes(StandardCharsets.UTF_8));
            for(int i=0;i<hash.length;i++){
                hashedSignature += String.format("%02X", hash[i] & 0xFF);
            }
            BigInteger encryptedSignature = new BigInteger(hashedSignature.getBytes());
            encryptedSignature = encrypt(encryptedSignature);
            
            //ENCRYPTS THE WHOLE MESSAGE
            RSA encryptor = new RSA(n, e);
            BigInteger encryptedMessage = new BigInteger(("[SIGNATURE]"+hashedSignature.toString()+"[SIGNATURE][MESSAGE]"+plainTextMessage+"[MESSAGE]").getBytes());
            encryptedMessage = encrypt(encryptedMessage);
            return ""+encryptedMessage.toString(16);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(RSA.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
    
    public synchronized String receiveMessage(BigInteger message, BigInteger n, BigInteger e){
        try {
            MessageDigest digestor = MessageDigest.getInstance("SHA-256");
            String[] msgPieces = new String(decrypt(message).toByteArray()).split("(\\x{5B}SIGNATURE\\x{5D})|(\\x{5B}MESSAGE\\x{5D})");
            String signature = msgPieces[1];
            String mainMessage = msgPieces[3];
            byte[] msgHash = digestor.digest(mainMessage.getBytes());
            String hashedMessage = "";
            for(int i=0;i<msgHash.length;i++){
                hashedMessage += String.format("%02X", msgHash[i] & 0xFF);
            }
            if(signature.equals(hashedMessage)){
                System.out.println("Assinatura Confirmada!!! Mensagem Íntegra");
                return mainMessage;
            } else {
                System.out.println("Mensagem não passou pelo teste de integridade e autenticidade.\nRejeite esta mensagem");
                return null;
            }
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(RSA.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
}
