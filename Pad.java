public class Pad {

	public static void test(){
		// empty message
        System.out.println("MD: " + sha3_224(pad(BigInteger.ZERO, 0)));

        // non multiples of 8
        System.out.println("MD: " + sha3_224(pad(new BigInteger("00"), 1)));
        System.out.println("MD: " + sha3_224(pad(new BigInteger("03"), 2)));
        System.out.println("MD: " + sha3_224(pad(new BigInteger("06"), 3)));
        System.out.println("MD: " + sha3_224(pad(new BigInteger("08"), 4)));
        System.out.println("MD: " + sha3_224(pad(new BigInteger("09"), 5)));

        // multiples of 8
        System.out.println("MD: " + sha3_224(pad(new BigInteger("CC", 16), 8)));
        System.out.println("MD: " + sha3_224(pad(new BigInteger("41FB", 16), 16)));
        System.out.println("MD: " + sha3_224(pad(new BigInteger("1F877C", 16), 24)));

        System.exit(0);
	}

    private static String pad(BigInteger m, int bitLength) {
        // if (bitLength % 8 == 0) {
        //     return m.toString(16);
        // }

        // e.g. 01 || 10000 ... 00000001 => 0x06 0x00 ... 0x80
        int leadingZeros = 5;//bitLength - m.bitLength();

        m = BigInteger.valueOf(6);

        String result = "";

        for (int i = 0; i < leadingZeros / 4; i++) {
            result += "0";
        }

        result += m.shiftLeft(1152 - (leadingZeros + m.bitLength()) % 1152).setBit(7).toString(16);
        System.out.println(result.length() == 144*2);
        System.out.println(result);

        return result;
    }
}
