package Elgamal;
import org.bouncycastle.crypto.digests.MD4Digest;
import java.math.BigInteger;
import java.util.Random;


public class Key {
    private BigInteger p;
    private BigInteger g;
    private BigInteger x;
    private BigInteger y;
    private  int len;

    public Key (String password){

        byte[] mes =password.getBytes();
        MD4Digest md4 = new MD4Digest();
        md4.update (mes, 0, mes.length);
        byte[] hash = new byte[md4.getDigestSize()];
        md4.doFinal (hash, 0);
//        Hex.encode (hash, System.out);
//        for(int i=0; i<hash.length;i++) {
//            System.out.println(hash[i]);
//        }
        this.len = hash.length*8;
        System.out.println(len);
        p = new BigInteger(1,hash);
        while (!simplicityTest(p)) {
            p = p.add(BigInteger.valueOf(1));
        }
        g = generationNum(new BigInteger("0"),p);
        x = generationNum(new BigInteger("1"),p.subtract(BigInteger.valueOf(1)));
        y = fastPowMod(g,x,p);
    }
    public Key (int len){
        if (len<128) {
            throw new SizeException("Size of key is small!");
        }
        this.len =len;
        p = new BigInteger(len, 90,new Random());
        while (!simplicityTest(p)){
            p = p.add(BigInteger.valueOf(1));
        }
        g = generationNum(new BigInteger("0"),p);
        x = generationNum(new BigInteger("1"),p.subtract(BigInteger.valueOf(1)));
        y = fastPowMod(g,x,p);
    }

    public BigInteger getP(){return p;}
    public BigInteger getG(){return g;}
    public BigInteger getX(){return x;}
    public BigInteger getY(){return y;}

    private boolean simplicityTest(BigInteger num){ // тест простоты
        int [] simpleNum =new int []{2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,
                67,71,73,79,83,89,97,101,103,107,109,113,127,131, 137,139, 149,151,157,
                163,167,173,179,181,191,193,197,199,211,223,227,229,233,239,241,251,257};
        for (int value : simpleNum) {
            BigInteger res = num.mod(BigInteger.valueOf(value));
            if (res.equals(BigInteger.valueOf(0)))
                return false;
        }
        //тест Миллера-Рабина
        BigInteger res = num.subtract(BigInteger.valueOf(1));
        BigInteger t;
        BigInteger s = new BigInteger("0");
        while ((res.mod(BigInteger.valueOf(2))).equals(BigInteger.valueOf(0))) {
            res = res.divide(BigInteger.valueOf(2));
            s = s.add(BigInteger.valueOf(1));
        }
        t = res;
        int flag = 0;
        for (int i = 0; i < len + 1; i++) {
            BigInteger a = generationNum(new BigInteger("1"),num.subtract(BigInteger.valueOf(1)));
            BigInteger x = fastPowMod(a,t,num);
            if(x.equals(new BigInteger("1"))||x.equals(num.subtract(new BigInteger("1")))){
                continue;
            }
            else {
                for (int j = 1; j <s.intValue(); j++) {

                    x = fastPowMod(x,new BigInteger("2"),num);
                    if(x.equals(new BigInteger("1")))
                        return false;
                    if (x.equals(num.subtract(new BigInteger("1")))){
                        flag =1;
                       break;}
                }
                if(flag==1){
                    flag =0;
                    continue;
                }
                return false;
            }
        }
        return true;
    }

    public BigInteger generationNum(BigInteger min, BigInteger max){
        BigInteger res = new BigInteger(len, new Random());
        while ((res.max(min)).equals(min) || (res.min(max)).equals(max)){
            res = new BigInteger(len, new Random());
        }
        return res;
    }
    public BigInteger fastPowMod(BigInteger osn, BigInteger st, BigInteger mod){
        BigInteger res = new BigInteger("1");
        byte [] num = st.toByteArray();
        int size = 8*num.length;
        int [] num_bit= new int[size];
        for(int i=0; i<num.length; i++) {
            int by = num[i];
            if(by<0)
                by= by*(-1)-1;
            int[] tmp = new int[8];
            for (int j = 0; j < 8; j++) {
                tmp[j] = by % 2;
                by = (by - by % 2) / 2;
            }
            if(num[i]<0){
                for (int j = 0; j < 8; j++) {
                    tmp[j]= (tmp[j]+1)%2;
                }
            }
            for (int j = 0; j < 8; j++) {
                num_bit[i * 8 + j] = tmp[7 - j];
            }
        }
        for (int value : num_bit) {
            res = res.multiply(res).mod(mod);
            res = osn.pow(value).multiply(res).mod(mod);
        }
        return res;
    }
}
