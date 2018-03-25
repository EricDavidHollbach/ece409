package ca.uwaterloo.ece;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.jcajce.provider.digest.SHA3.Digest224;
import org.bouncycastle.util.encoders.Hex;

public class App 
{
    public static void main(String[] args) {
        BigInteger p = new BigInteger("168199388701209853920129085113302407023173962717160229197318545484823101018386724351964316301278642143567435810448472465887143222934545154943005714265124445244247988777471773193847131514083030740407543233616696550197643519458134465700691569680905568000063025830089599260400096259430726498683087138415465107499");
        BigInteger q = new BigInteger("959452661475451209325433595634941112150003865821");
        BigInteger g = new BigInteger("94389192776327398589845326980349814526433869093412782345430946059206568804005181600855825906142967271872548375877738949875812540433223444968461350789461385043775029963900638123183435133537262152973355498432995364505138912569755859623649866375135353179362670798771770711847430626954864269888988371113567502852");

        if (p.isProbablePrime(Integer.MAX_VALUE)) {
            System.out.println("p is prime");
        }

        if (q.isProbablePrime(Integer.MAX_VALUE) && p.subtract(BigInteger.ONE).mod(q).equals(BigInteger.ZERO)) {
            System.out.println("q is a prime factor of p - 1");
        }

        if (g.modPow(q, p).equals(BigInteger.ONE)) {
            System.out.println("g has order q");
        }

        BigInteger sk1 = new BigInteger("432398415306986194693973996870836079581453988813");
        BigInteger pk1 = new BigInteger("49336018324808093534733548840411752485726058527829630668967480568854756416567496216294919051910148686186622706869702321664465094703247368646506821015290302480990450130280616929226917246255147063292301724297680683401258636182185599124131170077548450754294083728885075516985144944984920010138492897272069257160");

        if (pk1.equals(g.modPow(sk1, p))) {
            System.out.println("(sk1, pk1) is valid");
        }

        BigInteger sk2 = BigInteger.ZERO.setBit(159).subtract(BigInteger.ONE);
        BigInteger pk2 = g.modPow(sk2, p);

        BigInteger sk3 = BigInteger.ZERO.setBit(159).subtract(BigInteger.TEN);
        BigInteger pk3 = g.modPow(sk3, p);

        BigInteger m = pk1.xor(pk2).xor(BigInteger.ONE);

        // DSS user1 = new DSS(pk1, pk2);
        // user1.sign(message);
        SecureRandom rnd = new SecureRandom();
        BigInteger k = new BigInteger(q.bitLength(), rnd);

        while (k.compareTo(q) >= 0) {
            k = new BigInteger(q.bitLength(), rnd);
        }

        BigInteger r = g.modPow(k, p).mod(q);

        Digest224 digest224 = new Digest224();
        byte[] digest = digest224.digest(m.toByteArray());

        BigInteger h_m = (new BigInteger(digest)).mod(q);
        BigInteger s = h_m.subtract(sk1.multiply(r)).multiply(k.modInverse(q)).mod(q);

        if (h_m.mod(q).equals(sk1.multiply(r).add(k.multiply(s)).mod(q))) {
            System.out.println("successfully signed m");
        }

        // System.out.println("SHA3-224 = " + Hex.toHexString(digest));

        // DSS user2 = new DSS(pk1, pk2);

        return;
    }
}
