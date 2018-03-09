import java.math.BigInteger;

public class Main {
    public static void main(String[] args) {
        BigInteger p = new BigInteger("168199388701209853920129085113302407023173962717160229197318545484823101018386724351964316301278642143567435810448472465887143222934545154943005714265124445244247988777471773193847131514083030740407543233616696550197643519458134465700691569680905568000063025830089599260400096259430726498683087138415465107499");

        BigInteger q = new BigInteger("959452661475451209325433595634941112150003865821");

        if (p.isProbablePrime(Integer.MAX_VALUE)) {
            System.out.println("p is prime");
        }

        if (q.isProbablePrime(Integer.MAX_VALUE) && p.subtract(BigInteger.ONE).mod(q) == BigInteger.ZERO) {
            System.out.println("q is a prime factor of p - 1");
        }
        return;
    }
}

