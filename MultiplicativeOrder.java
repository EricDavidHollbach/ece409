import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

public class MultiplicativeOrder {
	
	private static final BigInteger ONE = BigInteger.ONE;
	private static final BigInteger TWO = BigInteger.valueOf(2);
    private static final BigInteger THREE = BigInteger.valueOf(3);
	
	// Represents a number's unique prime factors and their exponents
	public static class PrimeExp {
		BigInteger prime;
		long exponent;

		PrimeExp(BigInteger prime, long exponent) {
			this.prime = prime;
			this.exponent = exponent;
		}
	}

	public static BigInteger findMultiplicativeInverse(BigInteger base, BigInteger modulo) {
		// Factor  modulo - 1
		BigInteger modulo1 = modulo.subtract(ONE);
		List<PrimeExp> primeExpList = primeFactor(modulo1);
		BigInteger multiOrder = ONE;

		// Fine the multiplicative inverse for each factor
		for (PrimeExp primeExp : primeExpList) {
			BigInteger counter = BigInteger.ZERO;

			// Divide modulo1 by one factor
			BigInteger Mi = modulo1.divide(primeExp.prime.pow((int) primeExp.exponent));
			BigInteger multiInv = base.modPow(Mi,modulo);

			// If it does not equate to 1, continue modPow with the factor until it's 1
			while (multiInv.compareTo(ONE) > 0) {
				multiInv = multiInv.modPow(primeExp.prime, modulo);
				counter = counter.add(ONE);
			}
			System.out.println(counter);

			// No BigInteger Least Common Multiple. Use reduction by GCD
			counter = primeExp.prime.pow(counter.intValue());
			counter = counter.divide(multiOrder.gcd(counter));
			multiOrder = multiOrder.multiply(counter);
		}
		return multiOrder;
	}

	private static List<PrimeExp> primeFactor(BigInteger num) {
		List<PrimeExp> primeExpList = new ArrayList<>();
		BigInteger current = num; // Keep track as we factor
		Long exp = 0L; // Exponent for factors

		// Check how many factors or 2 there are
		while(!current.testBit(exp.intValue())) exp++;
		current = current.shiftRight(exp.intValue());

		primeExpList.add(new PrimeExp(TWO, exp));

		// Factor for numbers larger than 2
		BigInteger root = sqrt(current);
		BigInteger factor = THREE;

		// Stop when current number reaches 1
		while (current.compareTo(ONE) > 0) {

			// If the current factor is greater than the root, the root is the final factor
			if (factor.compareTo(root) > 0) factor = current;

			// Keep dividing by factor until a remainder appears
			exp = -1L;
			BigInteger[] qr;
			do {
				qr = current.divideAndRemainder(factor);
				exp ++;
			} while (qr[1].bitLength() <= 0);

			current = qr[0];

			// Add the prime factor and exponents to list
			if (exp > 0L) {
				primeExpList.add(new PrimeExp(factor, exp));
				root = sqrt(current);
			}

			// Increment factor by 2
			factor = factor.add(TWO);
		}

		return primeExpList;
	}

	// Returns ceiling of square root
	private static BigInteger sqrt(BigInteger num) {
		BigInteger current = num;
		BigInteger testSqrt;
		do {
			testSqrt = current;
			current = num.divide(testSqrt).add(testSqrt).shiftRight(1);
		} while(current.compareTo(testSqrt) >= 0);
		return testSqrt;
	}
}
