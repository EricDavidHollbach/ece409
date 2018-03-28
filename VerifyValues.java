import java.math.BigInteger;

public class VerifyValues {
	
	public static void verifyP(BigInteger p) {
		System.out.println("VERIFY p -");
        if (p.isProbablePrime(Integer.MAX_VALUE)) {
            System.out.println("p is prime");
        }
        if (p.bitLength() % 64 == 0) {
        	System.out.println("p has bit length of multiple of 64 bits");
        }
        if (p.bitLength() >= 512 && p.bitLength() <= 1024) {
        	System.out.println("p has bit length between 512 and 1024 bits");
        }
	}
	
	public static void verifyQ(BigInteger q, BigInteger p) {
		System.out.println("VERIFY q -");
		if (q.bitLength() == 160) {
			System.out.println("q has bit length of 160");
		}
		if (q.isProbablePrime(Integer.MAX_VALUE) && p.subtract(BigInteger.ONE).mod(q).equals(BigInteger.ZERO)) {
            System.out.println("q is a prime factor of p - 1");
        }
	}
	
	public static void verifyG(BigInteger g, BigInteger q, BigInteger p, String[] args) {
		System.out.println("VERIFY g -");
		// Skip verification to save time
    	if (args == null || args.length == 0) {
        	System.out.println("No multiplicative order verification");
    		return;
    	}
    	
    	// Factor p - 1 and find LCM of multiplicative inverse of the factors
        if (args[0].equals("bonus")) {
        	System.out.println("Bonus multiplicative order verification");
        	if (MultiplicativeOrder.findMultiplicativeInverse(g, p).compareTo(q) == 0) {
        		System.out.println("q is the multiplicative order of g under GF(p)");
        		return;
        	}
        	
        // Brute force
        } else if (args[0].equals("normal")) {
        	System.out.println("Normal multiplicative order verification");
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
}
