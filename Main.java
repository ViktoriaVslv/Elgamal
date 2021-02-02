package Elgamal;

import java.io.IOException;
import java.math.BigInteger;

public class Main {
    public static void  main (String [] args) throws IOException {


        Key k = new Key(500);

        Elgamal elgamal = new Elgamal(k);
//        elgamal.encryption("text.txt","text1.txt");
//        elgamal.decryption("text1.txt","text2.txt");
      // elgamal.signature("text.txt","text1.txt");
       boolean t = elgamal.check("text1.txt");
       System.out.println(t);
    }
}
