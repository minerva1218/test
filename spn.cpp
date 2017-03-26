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
int k[ROUND+1]; //ROUND��4 
int plaintext,ciphertext;
 
int main(void)
{
    /*-------------------------
    ���{���O��@SPN�t��k
    ��J�� 16-bit ���� �P 5�� 16-bit ���_
    ��@�覡�i�ݤU�����ѻPPPT  lec08-attacks to block cipher
    https://www.dropbox.com/s/fonuefta7wmivvz/lec08-attacks%20to%20block%20cipher.pdf?dl=0
    --------------------------*/

    
    printf("Please input 5 keys:");
    for(int i=0; i<=ROUND; i++)scanf("%d",k+i); //��J�����_�� �]�O16�줸 k+1�M&k[1]�@�˷N��
    while(1){
    printf("\nPlease input plaintext:");
    scanf("%d",&plaintext);//��J�Q�[�K������ �u��16�줸
    ciphertext=plaintext;
    ciphertext=spn();//�}�l�[�K ��X�s�^�K��
    printf("\nplaintext ciphertext\n%10d%10d",plaintext,ciphertext);
    ciphertext=rspn();
    printf("\nplaintext reciphertext\n%10d%10d",plaintext,ciphertext);
}

    return 0;
}

int spn()
{
    /*-------------------------
    ��SPN�t��k�� 4 round (ROUND��4)
    keyMixing �|��key�P���XOR
    subsitution�|�����N( �p 0����14 1����4)
    permutation�|����孫�s�ƦC(����ĤG��bit�����Ĥ���)
    �̫�@round������|�AkeyMixing�@��
    �`�NPPT���줸���ǬO�ѥ���k���C�찪
    �]��1�O 1000 0000 0000 0000
    �ӫD    0000 0000 0000 0001
    --------------------------*/

    int_to_4byte_array(ciphertext);

    for(int round = 1; round <= ROUND-1; round++) {//spn�t��k�i�����qP9
        keyMixing(k[round-1]); //�]��KEY�q0�}�l���round�֤@�� 
        subsitution();
        permutation();
    }
    keyMixing(k[ROUND-1]);
    subsitution();//�̫� 1 round �S��permutation �Ա��Ь����q�ĤE�� 
    keyMixing(k[ROUND]);
    return (c_byte[0] +(c_byte[1]<<4)+ (c_byte[2]<<8) + (c_byte[3]<<12) );//��4�qbyte�s�^�@��int
}

void subsitution()
{
    /*-------------------------
    subsitution�|�����N( �p 0����14 1����4)
    �i�H��PPT���� 7 ��
    SBOX�N�O���N��
    --------------------------*/
    int sbox[16] = {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7};
    for(int i = 0; i <4; i++)c_byte[i]=sbox[ c_byte[i] ];
    return;
}


void permutation()
{
    /*-------------------------
    permutation�|����孫�s�ƦC(����ĤG��bit�����Ĥ���)
    �i�H��PPT���� 8 ��
    table�O�洫����
    �N��bit�n���洫
    ��� table[1]=4�N���0�줸�M��4�줸�洫
    �]���O�洫�ҥH table[1]=4 �M table[4]=1 ����٩ʽ�
    --------------------------*/
    int table[16] = {0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15};
    //Table�M���q�֤@�O�]���q�s�}�l
    int c[16];
    int cp[16];
    for(int i = 0; i < 4; i++) { //��c_byte����bit�s�Jc
        c[4*i]=(c_byte[i])&0x1;
        c[4*i+1]=(c_byte[i]>>1)&0x1;
        c[4*i+2]=(c_byte[i]>>2)&0x1;
        c[4*i+3]=(c_byte[i]>>3)&0x1;
    }

    for(int i=0; i<16; i++)cp[table[i]]=c[ i ]; //cp �� i �줸 ���s�� C ���줸 �Ҧp CP���Ĥ@�줸(cp[1])�O�sc[4]
    for(int i=0; i<4; i++)c_byte[i]=cp[i*4] + (cp[i*4+1]<<1) + (cp[i*4+2]<<2) + (cp[i*4+3]<<3); //��C�q�G�i�쪺�줸�s�^Byte

    return;
}

void keyMixing(int key)
{
    for(int i=0; i<4; i++) {
        int mask=i*4;
        int k_byte=(key& (0xf<<mask) ) >>mask; //��key�����|�qbyte ����and mask�X�n���줸�A����̥k��
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
    ��SPN�t��k�� 4 round (ROUND��4)
    keyMixing �|��key�P���XOR
    subsitution�|�����N( �p 0����14 1����4)
    permutation�|����孫�s�ƦC(����ĤG��bit�����Ĥ���)
    �̫�@round������|�AkeyMixing�@��
    �]��1�O 1000 0000 0000 0000
    �ӫD    0000 0000 0000 0001
    
    Rspn�h�O�ѽX
    �ѹϤ��i���@�k �䤤sbox�ݤϦV  
    --------------------------*/
    int_to_4byte_array(ciphertext);
    keyMixing(k[ROUND]);
    rsubsitution();
    for(int round = ROUND; round >= 2; round--) {//spn�t��k�i�����qP9
        keyMixing(k[round-1]);
        permutation();
        rsubsitution();
    }
    keyMixing(k[0]);
    return (c_byte[0] +(c_byte[1]<<4)+ (c_byte[2]<<8) + (c_byte[3]<<12) );//��4�qbyte�s�^�@��int
}

void rsubsitution()
{
    /*-------------------------
    subsitution�|�����N( �p 0����14 1����4)
    �i�H��PPT���� 7 ��
    SBOX�N�O���N��
    --------------------------*/
    int sbox[16] = {14,3,4,8,1,12,10,15,7,13,9,6,11,2,0,5};
    for(int i = 0; i <4; i++)c_byte[i]=sbox[ c_byte[i] ];
    return;
}

void int_to_4byte_array(int ciphertext){
    int mask=0x0f;
    int next_byte=4;
    for(int i = 0; i < 4; i++) { //��K���byte�s �]�N�O 4 bits 
        c_byte[i]=ciphertext&mask;//�u���̧C 4 bits 
        ciphertext=ciphertext>>next_byte;//�k�� 4 bits��U��byte 
    }
}
