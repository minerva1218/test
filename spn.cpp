#include<stdlib.h>
#include<stdio.h>

#define ROUND 4

int spn();
void subsitution();
void permutation();
void keyMixing(int);
void int_to_4byte_array(int);

int rspn();
void rsubsitution();

int c_byte[4];
int k[ROUND+1]; //ROUND為4 
int plaintext,ciphertext;
 
int main(void)
{
    /*-------------------------
    此程式是實作SPN演算法
    輸入為 16-bit 明文 與 5把 16-bit 金鑰
    實作方式可看下面註解與PPT  lec08-attacks to block cipher
    https://www.dropbox.com/s/fonuefta7wmivvz/lec08-attacks%20to%20block%20cipher.pdf?dl=0
    --------------------------*/

    
    printf("Please input 5 keys:");
    for(int i=0; i<=ROUND; i++)scanf("%d",k+i); //輸入五把鑰匙 也是16位元 k+1和&k[1]一樣意思
    while(1){
    printf("\nPlease input plaintext:");
    scanf("%d",&plaintext);//輸入想加密的明文 只取16位元
    ciphertext=plaintext;
    ciphertext=spn();//開始加密 輸出存回密文
    printf("\nplaintext ciphertext\n%10d%10d",plaintext,ciphertext);
    ciphertext=rspn();
    printf("\nplaintext reciphertext\n%10d%10d",plaintext,ciphertext);
}

    return 0;
}

int spn()
{
    /*-------------------------
    此SPN演算法做 4 round (ROUND為4)
    keyMixing 會把key與原文XOR
    subsitution會做取代( 如 0換成14 1換成4)
    permutation會做原文重新排列(比方把第二個bit換成第五個)
    最後一round做完後會再keyMixing一次
    注意PPT中位元順序是由左到右為低到高
    因而1是 1000 0000 0000 0000
    而非    0000 0000 0000 0001
    --------------------------*/

    int_to_4byte_array(ciphertext);

    for(int round = 1; round <= ROUND-1; round++) {//spn演算法可看講義P9
        keyMixing(k[round-1]); //因為KEY從0開始算比round少一號 
        subsitution();
        permutation();
    }
    keyMixing(k[ROUND-1]);
    subsitution();//最後 1 round 沒有permutation 詳情請看講義第九頁 
    keyMixing(k[ROUND]);
    return (c_byte[0] +(c_byte[1]<<4)+ (c_byte[2]<<8) + (c_byte[3]<<12) );//把4段byte存回一個int
}

void subsitution()
{
    /*-------------------------
    subsitution會做取代( 如 0換成14 1換成4)
    可以看PPT的第 7 頁
    SBOX就是取代表
    --------------------------*/
    int sbox[16] = {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7};
    for(int i = 0; i <4; i++)c_byte[i]=sbox[ c_byte[i] ];
    return;
}


void permutation()
{
    /*-------------------------
    permutation會做原文重新排列(比方把第二個bit換成第五個)
    可以看PPT的第 8 頁
    table是交換的表
    代表bit要怎麼交換
    比方 table[1]=4代表第0位元和第4位元交換
    因為是交換所以 table[1]=4 和 table[4]=1 有對稱性質
    --------------------------*/
    int table[16] = {0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15};
    //Table和講義少一是因為從零開始
    int c[16];
    int cp[16];
    for(int i = 0; i < 4; i++) { //把c_byte取成bit存入c
        c[4*i]=(c_byte[i])&0x1;
        c[4*i+1]=(c_byte[i]>>1)&0x1;
        c[4*i+2]=(c_byte[i]>>2)&0x1;
        c[4*i+3]=(c_byte[i]>>3)&0x1;
    }

    for(int i=0; i<16; i++)cp[table[i]]=c[ i ]; //cp 第 i 位元 對表存取 C 的位元 例如 CP的第一位元(cp[1])是存c[4]
    for(int i=0; i<4; i++)c_byte[i]=cp[i*4] + (cp[i*4+1]<<1) + (cp[i*4+2]<<2) + (cp[i*4+3]<<3); //把C從二進位的位元存回Byte

    return;
}

void keyMixing(int key)
{
    for(int i=0; i<4; i++) {
        int mask=i*4;
        int k_byte=(key& (0xf<<mask) ) >>mask; //把key分成四段byte 先用and mask出要的位元再移到最右邊
        c_byte[i] = k_byte ^ c_byte[i];
    }

    return;
}

void print_c_byte_by01(){
    printf("\n");
    for(int i=0; i<4; i++) { 
        printf(" ");
        for(int j=1; j<=8; j<<=1)printf(j&(c_byte[i])?"1":"0");
    }
}

int rspn()
{
    /*-------------------------
    此SPN演算法做 4 round (ROUND為4)
    keyMixing 會把key與原文XOR
    subsitution會做取代( 如 0換成14 1換成4)
    permutation會做原文重新排列(比方把第二個bit換成第五個)
    最後一round做完後會再keyMixing一次
    因而1是 1000 0000 0000 0000
    而非    0000 0000 0000 0001
    
    Rspn則是解碼
    由圖片可知作法 其中sbox需反向  
    --------------------------*/
    int_to_4byte_array(ciphertext);
    keyMixing(k[ROUND]);
    rsubsitution();
    for(int round = ROUND; round >= 2; round--) {//spn演算法可看講義P9
        keyMixing(k[round-1]);
        permutation();
        rsubsitution();
    }
    keyMixing(k[0]);
    return (c_byte[0] +(c_byte[1]<<4)+ (c_byte[2]<<8) + (c_byte[3]<<12) );//把4段byte存回一個int
}

void rsubsitution()
{
    /*-------------------------
    subsitution會做取代( 如 0換成14 1換成4)
    可以看PPT的第 7 頁
    SBOX就是取代表
    --------------------------*/
    int sbox[16] = {14,3,4,8,1,12,10,15,7,13,9,6,11,2,0,5};
    for(int i = 0; i <4; i++)c_byte[i]=sbox[ c_byte[i] ];
    return;
}

void int_to_4byte_array(int ciphertext){
    int mask=0x0f;
    int next_byte=4;
    for(int i = 0; i < 4; i++) { //把密文用byte存 也就是 4 bits 
        c_byte[i]=ciphertext&mask;//只取最低 4 bits 
        ciphertext=ciphertext>>next_byte;//右移 4 bits到下個byte 
    }
}
