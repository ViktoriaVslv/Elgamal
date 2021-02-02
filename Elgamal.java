package Elgamal;

import org.bouncycastle.crypto.digests.MD4Digest;
import org.bouncycastle.util.encoders.Hex;
import java.io.IOException;
import java.io.FileWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

import java.util.List;

public class Elgamal {
    private BigInteger p;
    private BigInteger g;
    private BigInteger x;
    private BigInteger y;
    private Key key;


    public Elgamal (Key k){
        p = k.getP();
        g = k.getG();
        x = k.getX();
        y = k.getY();
        key = k;
    }
    public void signature(String in, String out) throws IOException{
        List<String> lines = Files.readAllLines(Paths.get(in), StandardCharsets.UTF_8);
        FileWriter fileOut = new FileWriter(out);
        int len = lines.size();
        String str = lines.get(0);
        fileOut.write( lines.get(0)+"\n");
        for (int i=1; i<len;i++) {
            str += lines.get(i);
            fileOut.write( lines.get(i)+"\n");
        }
        byte[] mes =str.getBytes();

        MD4Digest md4 = new MD4Digest();
        md4.update (mes, 0, mes.length);
        byte[] hash = new byte[md4.getDigestSize()];
        md4.doFinal (hash, 0);

        BigInteger m = new BigInteger(1,hash);
        BigInteger k = key.generationNum(new BigInteger("0"),p.subtract(BigInteger.valueOf(1)));
        while (!NOD(k,p.subtract(BigInteger.valueOf(1))).equals(new BigInteger("1"))){
            k =  key.generationNum(new BigInteger("0"),p.subtract(BigInteger.valueOf(1)));
        }
        BigInteger r = key.fastPowMod(g,k,p);
        BigInteger k1 = multiInverse(k,p.subtract(BigInteger.valueOf(1)));
        BigInteger s = (m.subtract(x.multiply(r)).multiply(k1)).mod(p.subtract(BigInteger.valueOf(1)));
        fileOut.write(r.toString()+"\n");
        fileOut.write(s.toString()+"\n");
        fileOut.close();

    }

    private BigInteger multiInverse(BigInteger num, BigInteger mod1){
        BigInteger mod = mod1;
        BigInteger x2 = new BigInteger("1");
        BigInteger x1 = new BigInteger("0");
        BigInteger y2 = new BigInteger("0");
        BigInteger y1 = new BigInteger("1");
        BigInteger x;
        BigInteger y, q, r;
        while (!mod1.equals(BigInteger.valueOf(0))){
            q = num.divide(mod1);
            r = num.subtract(q.multiply(mod1));
            x = x2.subtract(q.multiply(x1));
            y = y2.subtract(q.multiply(y1));
            num = mod1;
            mod1 = r;
            x2 = x1;
            x1 = x;
            y2 = y1;
            y1 = y;
        }
        return x2.mod(mod);
    }
    public boolean check(String in) throws IOException{
        List<String> lines = Files.readAllLines(Paths.get(in), StandardCharsets.UTF_8);
        int len = lines.size();
        String str = lines.get(0);
        for (int i=1; i<len-2;i++)
            str+=lines.get(i);
        byte[] mes =str.getBytes();
        MD4Digest md4 = new MD4Digest();
        md4.update (mes, 0, mes.length);
        byte[] hash = new byte[md4.getDigestSize()];
        md4.doFinal (hash, 0);
        BigInteger m = new BigInteger(hash);
        BigInteger r = new BigInteger(lines.get(len-2));
        BigInteger s = new BigInteger(lines.get(len-1));
        BigInteger res1 = key.fastPowMod(y,r,p).multiply(key.fastPowMod(r,s,p)).mod(p);
        BigInteger res2 = key.fastPowMod(g,m,p);
        boolean equals = res1.equals(res2);
        return equals;
    }

    private BigInteger NOD (BigInteger a, BigInteger b){
        while ((!a.equals(new BigInteger("0")))&&(!b.equals(new BigInteger("0")))){
            if(a.max(b).equals(a))
                a = a.mod(b);
            else
                b = b.mod(a);
        }
        return a.add(b);
    }

    public void encryption(String in, String out) throws IOException{
        List<String> lines = Files.readAllLines(Paths.get(in), StandardCharsets.UTF_8);
        int len = lines.size();
        String str = lines.get(0);
        for (int i=1; i<len-2;i++)
            str+=lines.get(i);
        byte[] mes =str.getBytes();
        FileWriter fileOut = new FileWriter(out);
        BigInteger M = new BigInteger(mes);
        if(M.max(p).equals(M)){
            throw new SizeException("Message longer than key!");
        }
        BigInteger k = key.generationNum(BigInteger.ONE,p.subtract(BigInteger.ONE));
        BigInteger a = key.fastPowMod(g,k,p);
        BigInteger b = key.fastPowMod(y,k,p);
        b = b.multiply(M).mod(p);

        fileOut.write(a.toString()+"\n");
        fileOut.write(b.toString()+"\n");

        fileOut.close();
    }

    public void decryption(String in, String out) throws IOException{

        FileWriter fileOut = new FileWriter(out);
        List<String> lines = Files.readAllLines(Paths.get(in), StandardCharsets.UTF_8);
        BigInteger A = new BigInteger(lines.get(0));
        BigInteger B = new BigInteger(lines.get(1));
        BigInteger a = key.fastPowMod(A,x,p);
        a = multiInverse(a,p);
        BigInteger M = B.multiply(a).mod(p);
        fileOut.write(new String(M.toByteArray()));
        fileOut.close();
    }
}
