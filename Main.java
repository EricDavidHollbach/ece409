import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.IOException;
import java.lang.Process;
import java.lang.ProcessBuilder;
import java.math.BigInteger;
import java.security.SecureRandom;

public class Main
{
    private static final BigInteger p = new BigInteger("23");//new BigInteger("168199388701209853920129085113302407023173962717160229197318545484823101018386724351964316301278642143567435810448472465887143222934545154943005714265124445244247988777471773193847131514083030740407543233616696550197643519458134465700691569680905568000063025830089599260400096259430726498683087138415465107499"); 
    private static final BigInteger q = new BigInteger("11");//new BigInteger("959452661475451209325433595634941112150003865821");
    private static final BigInteger g = new BigInteger("2");//new BigInteger("94389192776327398589845326980349814526433869093412782345430946059206568804005181600855825906142967271872548375877738949875812540433223444968461350789461385043775029963900638123183435133537262152973355498432995364505138912569755859623649866375135353179362670798771770711847430626954864269888988371113567502852");

    public static void main(String[] args) {
        if (p.isProbablePrime(Integer.MAX_VALUE)) {
            System.out.println("p is prime");
        }

        if (q.isProbablePrime(Integer.MAX_VALUE) && p.subtract(BigInteger.ONE).mod(q).equals(BigInteger.ZERO)) {
            System.out.println("q is a prime factor of p - 1");
        }

        // TODO use a simple for loop here
        if (g.modPow(q, p).equals(BigInteger.ONE)) {
            System.out.println("g has order q");
        }

        BigInteger sk1 = new BigInteger("5");//BigInteger.ZERO.setBit(q.bitLength() - 2).subtract(BigInteger.ZERO);
        BigInteger pk1 = new BigInteger("9");//g.modPow(sk1, p);

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

        // BigInteger m = new BigInteger(pk1.toString(16) + pk2.toString(16) + "00000001", 16);

        // DSS user1 = new DSS(sk1, pk1);
        // BigInteger[] sig1 = user1.sign(m);
        // System.out.println(user1.verify(m, sig1));

        // DSS user2 = new DSS(null, pk1);
        // System.out.println(user2.verify(m, sig1));

        BigInteger m = new BigInteger(pk1.toString(16) + pk2.toString(16) + "00000001", 16);

        DSS test = new DSS(sk1, pk1);
        BigInteger[] sig = test.sign(m);
        System.out.println(test.verify(m, sig));

        return;
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

            BigInteger h_m = m.mod(p);//new BigInteger(sha3_224(m.toString(16)), 16);
            System.out.println("1. h_m = " + h_m.toString());

            SecureRandom rnd = new SecureRandom();
            BigInteger k = new BigInteger(q.bitLength(), rnd);

            while (k.compareTo(q) >= 0 || k.compareTo(BigInteger.ZERO) <= 0) {
                k = new BigInteger(q.bitLength(), rnd);
            }

            System.out.println("2. k = " + k.toString());

            BigInteger r = g.modPow(k, p).mod(q);
            System.out.println("3. r = " + r.toString());

            BigInteger s = h_m.subtract(x.multiply(r)).multiply(k.modInverse(q)).mod(q);
            System.out.println("4. s = " + s.toString());

            if (h_m.mod(q).equals(x.multiply(r).add(k.multiply(s)).mod(q))) {
                System.out.println("5. signature is (" + r.toString() + ", " + s.toString() + ")");
                return new BigInteger[] {r, s};
            }

            System.out.println("Error generating a valid signature");
            return null;
        }

        protected boolean verify(BigInteger m, BigInteger[] sig) {
            System.out.println("Ver");
            if (sig.length != 2) {
                System.err.println("Wrong number of arguments! Must provide (r, s) to be verified..");
            }

            for (BigInteger rs : sig) {
                if (rs.compareTo(q) > 0 || rs.compareTo(BigInteger.ZERO) <= 0) {
                    System.out.println("Invalid signature -- r or s is not nonnegative or too large");
                    return false;
                }
            }

            BigInteger h_m = m.mod(p);//new BigInteger(sha3_224(m.toString(16)), 16);
            System.out.println("1. h_m = " + h_m.toString());

            BigInteger r = sig[0];
            BigInteger s = sig[1];

            BigInteger s_inv = s.modInverse(q);
            System.out.println("2. s^-1 = " + s_inv.toString());

            BigInteger u = h_m.multiply(s_inv).mod(q);
            System.out.println("3. u = " + u.toString());

            BigInteger v = r.negate().multiply(s_inv).mod(q);
            System.out.println("4. v = " + v.toString());

            BigInteger w = g.modPow(u, p).multiply(y.modPow(v, p)).mod(q);
            System.out.println("5. w = " + w.toString());

            if (w.equals(r)) {
                System.out.println("6. w = r = " + r.toString() + ". Verification success.");
                return true;
            }

            return false;
        }
    }

    private static String sha3_224(String message) {
        String digest = "";

        try {
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
