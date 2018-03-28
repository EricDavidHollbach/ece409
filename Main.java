import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.IOException;

import java.lang.Process;
import java.lang.ProcessBuilder;

import java.math.BigInteger;

import java.security.SecureRandom;

public class Main
{
    private static final BigInteger p = new BigInteger("168199388701209853920129085113302407023173962717160229197318545484823101018386724351964316301278642143567435810448472465887143222934545154943005714265124445244247988777471773193847131514083030740407543233616696550197643519458134465700691569680905568000063025830089599260400096259430726498683087138415465107499"); 
    private static final BigInteger q = new BigInteger("959452661475451209325433595634941112150003865821");
    private static final BigInteger g = new BigInteger("94389192776327398589845326980349814526433869093412782345430946059206568804005181600855825906142967271872548375877738949875812540433223444968461350789461385043775029963900638123183435133537262152973355498432995364505138912569755859623649866375135353179362670798771770711847430626954864269888988371113567502852");

    public static void main(String[] args) {
        System.out.println("--------------------part (a)--------------------");

        if (p.isProbablePrime(Integer.MAX_VALUE)) {
            System.out.println("p is prime");
        }

        if (q.isProbablePrime(Integer.MAX_VALUE) && p.subtract(BigInteger.ONE).mod(q).equals(BigInteger.ZERO)) {
            System.out.println("q is a prime factor of p - 1");
        }
        
        verifyMultiplicativeOrder(args);

        BigInteger sk1 = new BigInteger("432398415306986194693973996870836079581453988813");
        BigInteger pk1 = new BigInteger("49336018324808093534733548840411752485726058527829630668967480568854756416567496216294919051910148686186622706869702321664465094703247368646506821015290302480990450130280616929226917246255147063292301724297680683401258636182185599124131170077548450754294083728885075516985144944984920010138492897272069257160");

        if (pk1.equals(g.modPow(sk1, p))) {
            System.out.println("(sk1, pk1) is valid");
        }

        BigInteger sk2 = BigInteger.ZERO.setBit(q.bitLength() - 1).subtract(BigInteger.ONE);
        BigInteger pk2 = g.modPow(sk2, p);

        if (pk2.equals(g.modPow(sk2, p))) {
            System.out.println("(sk2, pk2) is valid");
        }

        BigInteger sk3 = BigInteger.ZERO.setBit(q.bitLength() - 1).subtract(BigInteger.TEN);
        BigInteger pk3 = g.modPow(sk3, p);

        if (pk3.equals(g.modPow(sk3, p))) {
            System.out.println("(sk3, pk3) is valid");
        }

        System.out.println("--------------------part (b)--------------------");
        System.out.println("User 1 generate Sig1:");

        BigInteger m1 = new BigInteger(pk1.toString(16) + pk2.toString(16) + "01", 16);
        System.out.println("m = 0x" + m1.toString(16));

        System.out.println("x = 0x" + sk1.toString(16));
        System.out.println("y = 0x" + pk1.toString(16));

        DSS user1 = new DSS(sk1, pk1);
        BigInteger[] sig1 = user1.sign(m1);

        System.out.println("User 2 verify Sig1:");

        DSS user2_verify = new DSS(null, pk1);
        user2_verify.verify(m1, sig1);

        System.out.println("User 2 generate Sig2:");

        BigInteger m2 = new BigInteger(pk2.toString(16) + pk3.toString(16) + "01", 16);
        System.out.println("m = 0x" + m2.toString(16));

        System.out.println("x = 0x" + sk2.toString(16));
        System.out.println("y = 0x" + pk2.toString(16));

        DSS user2_sign = new DSS(sk2, pk2);
        BigInteger[] sig2 = user2_sign.sign(m2);

        System.out.println("--------------------part (c)--------------------");
        SecureRandom rnd = new SecureRandom();
        BigInteger nonce1, nonce2, t1, t2;

        BigInteger mask = BigInteger.ZERO.setBit(216).subtract(BigInteger.ONE);

        while (true) {
            nonce1 = new BigInteger(128, rnd);

            String preImage = sha3_224("01") + m1.toString(16) + nonce1.toString(16);
            t1 = new BigInteger(sha3_224(preImage), 16);

            if (t1.and(mask).bitLength() == 192) {
                break;
            }
        }

        System.out.println("nonce1 = 0x" + nonce1.toString(16));

        while (true) {
            nonce2 = new BigInteger(128, rnd);

            String preImage = sha3_224("01") + m1.toString(16) + nonce1.toString(16);
            t2 = new BigInteger(sha3_224(preImage), 16);

            if (t2.and(mask).bitLength() == 192) {
                break;
            }
        }

        System.out.println("nonce2 = 0x" + nonce2.toString(16));

        return;
    }
    
    private static void verifyMultiplicativeOrder(String args[]) {
    	if (args == null || args.length == 0) {
        	System.out.println("NONE");

    		// Skip verification to save time
    		return;
    	}
    	
    	// Factor p - 1 and find LCM of multiplicative inverse of the factors
        if (args[0].equals("bonus")) {
        	System.out.println("BONUS");
        	if (MultiplicativeOrder.findMultiplicativeInverse(g, p).compareTo(q) == 0) {
        		System.out.println("q is the multiplicative order of g under GF(p)");
        		return;
        	}
        	
        // Brute force
        } else if (args[0].equals("normal")) {
        	System.out.println("NORMAL");

        	BigInteger qIndex = q;
        	while (q.compareTo(BigInteger.ZERO) > 0) {
        		qIndex = qIndex.subtract(BigInteger.ONE);
        		if (g.modPow(qIndex, p).compareTo(BigInteger.ONE) == 0) {
        			System.out.println("q is the multiplicative order of g under GF(p)");
        			return;
        		}
        	}
        }
    	System.out.println("q is not the multiplicative order of g under GF(p)");
    }

    private static class DSS {
        private BigInteger x;
        private BigInteger y;

        protected DSS(BigInteger sk, BigInteger pk) {
            x = sk;
            y = pk; // equals g.modPow(sk, q)
        }

        protected BigInteger[] sign(BigInteger m) {
            System.out.println("Sig");

            BigInteger h_m = new BigInteger(sha3_224(m.toString(16)), 16);

            System.out.println("1. h_m = 0x" + h_m.mod(q).toString(16));

            SecureRandom rnd = new SecureRandom();
            BigInteger k = new BigInteger(q.bitLength(), rnd);

            while (k.compareTo(q) >= 0 || k.compareTo(BigInteger.ZERO) <= 0) {
                k = new BigInteger(q.bitLength(), rnd);
            }

            System.out.println("2. k = 0x" + k.toString(16));

            BigInteger r = g.modPow(k, p).mod(q);
            System.out.println("3. r = 0x" + r.toString(16));

            BigInteger s = h_m.subtract(x.multiply(r)).multiply(k.modInverse(q)).mod(q);
            System.out.println("4. s = 0x" + s.toString(16));

            if (h_m.mod(q).equals(x.multiply(r).add(k.multiply(s)).mod(q))) {
                System.out.println("5. signature is (" + r.toString() + ", " + s.toString() + ")");
                return new BigInteger[] {r, s};
            }

            System.out.println("Error generating a valid signature.");
            return null;
        }

        protected boolean verify(BigInteger m, BigInteger[] sig) {
            System.out.println("Ver");
            if (sig.length != 2) {
                System.err.println("Wrong number of arguments! Must provide (r, s) to be verified..");
            }

            for (BigInteger rs : sig) {
                if (rs.compareTo(q) > 0 || rs.compareTo(BigInteger.ZERO) <= 0) {
                    System.out.println("Reject the signature since 0 < r,s < q is not satisfied.");
                    return false;
                }
            }

            BigInteger h_m = new BigInteger(sha3_224(m.toString(16)), 16);
            System.out.println("1. h_m = 0x" + h_m.mod(q).toString());

            BigInteger r = sig[0];
            BigInteger s = sig[1];

            BigInteger s_inv = s.modInverse(q);
            System.out.println("2. s^(-1) = 0x" + s_inv.toString());

            BigInteger u = h_m.multiply(s_inv).mod(q);
            System.out.println("3. u = 0x" + u.toString());

            BigInteger v = r.negate().multiply(s_inv).mod(q);
            System.out.println("4. v = 0x" + v.toString());

            BigInteger w = g.modPow(u, p).multiply(y.modPow(v, p)).mod(p).mod(q);
            System.out.println("5. w = 0x" + w.toString());

            if (w.equals(r)) {
                System.out.println("Verification success.");
                return true;
            }

            return false;
        }
    }

    private static String sha3_224(String message) {
        String digest = "";

        try {
        	// Absolute path file. JRE on one machine cannot find python.exe added to PATH.
        	// Process p = new ProcessBuilder("C:\\Users\\Raymond Zhuang\\AppData\\Local\\Programs\\Python\\Python36-32\\python.exe", "sha3-224.py", message).start();
            Process p = new ProcessBuilder("python", "sha3-224.py", message).start();

            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));

            int i = 0;
            String line;
            while ((line = br.readLine()) != null) {
                int value = Integer.valueOf(line);
                digest += Integer.toHexString(value);
            }
        } catch (IOException ex) {
            System.out.println(ex);
        }

        return digest;
    }
}
