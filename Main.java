import java.math.BigInteger;

public class Main {
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

        // TODO check if g is order q

        return;
    }
}

