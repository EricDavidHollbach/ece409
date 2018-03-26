package ca.uwaterloo.ece;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.IOException;
import java.lang.Process;
import java.lang.ProcessBuilder;
import java.math.BigInteger;
import java.security.SecureRandom;

import org.python.core.PyObject;
import org.python.util.PythonInterpreter;

public class App 
{
    private static final BigInteger p = new BigInteger("168199388701209853920129085113302407023173962717160229197318545484823101018386724351964316301278642143567435810448472465887143222934545154943005714265124445244247988777471773193847131514083030740407543233616696550197643519458134465700691569680905568000063025830089599260400096259430726498683087138415465107499"); 
    private static final BigInteger q = new BigInteger("959452661475451209325433595634941112150003865821");
    private static final BigInteger g = new BigInteger("94389192776327398589845326980349814526433869093412782345430946059206568804005181600855825906142967271872548375877738949875812540433223444968461350789461385043775029963900638123183435133537262152973355498432995364505138912569755859623649866375135353179362670798771770711847430626954864269888988371113567502852");

    public static void main(String[] args) {
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

        // Attempt 1.
        // BigInteger m = pk1.xor(pk2).xor(BigInteger.ONE);

        // byte[] message = new byte[1152];

        // message[0] = 0x60;

        // for (int i = 1; i < message.length - 1; i++) {
        //     message[i] = 0x00;
        // }

        // message[message.length - 1] = 0x01;

        // Digest224 digest224 = new Digest224();
        // byte[] digest = digest224.digest(message);

        // System.out.println(Hex.toHexString(digest));

        // Attempt 2.
        // StringWriter writer = new StringWriter(); //ouput will be stored here

        // ScriptEngineManager manager = new ScriptEngineManager();
        // ScriptContext context = new SimpleScriptContext();

        // context.setWriter(writer); //configures output redirection
        // ScriptEngine engine = manager.getEngineByName("python");
        // engine.eval(new FileReader("hello.py"), context);
        // System.out.println(writer.toString()); 

        // Attempt 3.
        // PythonInterpreter interpreter = new PythonInterpreter();
        // interpreter.exec("import sys\nsys.path.append('/Users/edhollba/Desktop/ece409-project1')\nimport sha3-224");
        // // execute a function that takes a string and returns a string
        // PyObject someFunc = interpreter.get("main");
        // PyObject result = someFunc.__call__();
        // String realResult = (String) result.__tojava__(String.class);
        // System.out.println(realResult);
        BigInteger m = null;

        DSS user1 = new DSS(sk1, pk1);
        BigInteger[] sig1 = user1.sign(m);
        System.out.println(user1.verify(m, sig1));

        DSS user2 = new DSS(null, pk1);
        System.out.println(user2.verify(m, sig1));

        return;
    }

    private static BigInteger sha3_224(BigInteger message) {
        String digest = "";

        try {
            Process p = new ProcessBuilder("python", "sha3-224.py", message.toHexString()).start();

            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));

            int i = 0;
            String line;
            while ((line = br.readLine()) != null) {
                int value = Integer.valueOf(line);
                message += Integer.toHexString(value);
            }
        } catch (IOException ex) {
            System.out.println(ex);
        }

        return new BigInteger(digest, 16);
    }

    private static class DSS {
        private BigInteger x;
        private BigInteger y;

        protected DSS(BigInteger sk, BigInteger pk) {
            x = sk;
            y = pk; // equals g.modPow(sk, q)
        }

        protected BigInteger[] sign(BigInteger m) {        
            SecureRandom rnd = new SecureRandom();
            BigInteger k = new BigInteger(q.bitLength(), rnd);

            while (k.compareTo(q) >= 0) {
                k = new BigInteger(q.bitLength(), rnd);
            }

            BigInteger r = g.modPow(k, p).mod(q);
            BigInteger s = ssh3_224(m).subtract(x.multiply(r)).multiply(k.modInverse(q)).mod(q);

            if (ssh3_224(m).mod(q).equals(x.multiply(r).add(k.multiply(s)).mod(q))) {
                return new BigInteger[] {r, s};
            }

            return null;
        }

        protected boolean verify(BigInteger m, BigInteger[] sig) {
            if (sig.length != 2) {
                System.err.println("Wrong number of arguments!! Must provide (r, s) to be verified..");
            }

            for (BigInteger rs : sig) {
                if (rs.compareTo(q) > 0 || rs.compareTo(BigInteger.ZERO) < 0) {
                    System.out.println("Invalid signature -- r or s is not nonnegative or too large");
                    return false;
                }
            }

            BigInteger r = sig[0];
            BigInteger s = sig[1];

            BigInteger u = ssh3_224(m).multiply(s.modInverse(q)).mod(q);
            BigInteger v = r.negate().multiply(s.modInverse(q)).mod(q);

            if (g.modPow(u, q).multiply(y.modPow(v, q)).mod(q).equals(r)) {
                return true;
            }

            return false;
        }
    }
}
