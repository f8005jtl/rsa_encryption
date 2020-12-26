/*
===============================================
テキスト暗号化プログラムVer2.0 todonyan 2019/12/17
===============================================
[履歴]
  -2019/12/17 Ver1.0:共通鍵暗号方式 追加
  -2020/01/26 Ver2.0:公開鍵暗号方式 追加
[参考]
  -公開鍵暗号方式
  https://qiita.com/tcb78/items/3eaa4a222bd544012db5
===============================================
●使い方
0.コンパイル
  ・コンパイル：gcc -o encryption.exe encryption.c
1.共通鍵暗号方式モード(シーザー暗号)
  ・暗号化：./encryption.exe -enc -i input.txt -o output.enc
  ・復号化：./encryption.exe -dec -i output.enc -o decrypted.txt 
2.公開鍵暗号方式モード(RSA)
  ・鍵生成(初期化)：./encryption.exe -iniRSA
  ・暗号化：./encryption.exe -encRSA -i input.txt -o output.enc
  ・復号化：./encryption.exe -decRSA -i output.enc -o decrypted.txt 
===============================================
*/
/*[ヘッダ]========================================================*/
/*****************************/
/* 暗号・復号プログラム基本ヘッダ */
/*****************************/
#include <stdio.h>
#include <string.h>// for strcmp()
#pragma warning(disable:4996)// VC++ Error対策
/*****************************/
/* 公開鍵暗号方式モード用ヘッダ   */
/*****************************/
#include <stdlib.h>// for srand()
#include <time.h>// for srand()
#include <math.h>// for sqrt()
/******************************/

/*[設定]========================================================*/
/*******************************/
/* 暗号・復号プログラム基本設定     */
/*******************************/
#define READ_TEXT_MAX 2048 // 1行の最大文字数(バイト数)
#define CONV_KEY 20191217// 暗号キー(共通鍵暗号方式のみ)

/*[関数]========================================================*/
/*******************************/
/* 暗号・復号プログラム基本関数     */
/******************************/
int getModeSelect(char **);// 選択モードを数値にして返す関数
char getFileData(char *,char *);// ファイルの中身を配列にして返す関数
char writeFileData(char *,char *);// ファイルの書出関数
void strToEnc(char *,int);// 文字配列を暗号する関数
void strToDec(char *,int);// 文字配列を復号する関数
int textEncDecProgram(char **);// 暗号・復号化プログラム本体
/*******************************/
/* 公開鍵暗号方式モード用関数      */
/******************************/
int getDecKeyRSA();// 復号化処理(秘密鍵)
int getEncKeyRSA();// 暗号化処理(公開鍵)
void secretKeyWrite(int);// 暗号キー(暗号平文)の書出
void secretKeyRead(int *);// 暗号キー(暗号平文)の読込
void initPublicKeyRSA();// 公開鍵暗号方式の初期化(公開鍵,秘密鍵生成)
void encDecKeyWrite(int,int,int);// 暗号・復号キー読込
void encDecKeyRead(int *,int *,int *);// 暗号・復号キー書出
int getPrimeNums(int *,int *);// 素数p,qを生成する関数(乱数で)
int getPrime(int);// 素数を返す関数(乱数で)
int gcd(int,int);//最大公約数
int lcm(int,int);//最小公倍数
int extpower(int,int,int);// nのべき乗計算

/*[本プログラム]========================================================*/
// Entry Point
int main(int argc, char *argv[]){
  textEncDecProgram(argv);// 暗号・復号化プログラム本体
  return 0;
}
int textEncDecProgram(char **argv){
  char text_str[READ_TEXT_MAX]={0};// 文字配列初期化
  getFileData(argv[3],text_str);// ファイルの読込
  switch(getModeSelect(argv)){// モード選択
    case 1:strToEnc(text_str,CONV_KEY);break;// 暗号化処理(共通鍵)
    case 2:strToDec(text_str,CONV_KEY);break;// 復号化処理(共通鍵)
    case 3:// 公開鍵暗号方式の初期化
     initPublicKeyRSA();break;// 公開鍵暗号方式の初期化(公開鍵,秘密鍵生成)
    case 4:// 公開鍵暗号化
      strToEnc(text_str,getEncKeyRSA());break;// 暗号化処理(公開鍵)
    case 5:// 秘密鍵復号化
      strToDec(text_str,getDecKeyRSA());break;// 復号化処理(秘密鍵)
    default:printf("getModeSelectError");return -1;// 処理失敗
  }
  writeFileData(argv[5],text_str);// ファイルの書出
  return 0;
}
int getEncKeyRSA(){
  int e,n,d=0;// e,n:公開鍵 d:秘密鍵
  int encrypted_num=0;// 暗号化後の値
  int plain_num = rand() % 100+1;// 平文(1~100の乱数、自由変更OK)
  encDecKeyRead(&e,&n,&d);// 暗号・復号キー読込
  encrypted_num = extpower(plain_num, e, n);// 暗号化
  // 秘密鍵(暗号平文)の生成※今回、秘密鍵は2つ必要になる(厳重)
  secretKeyWrite(encrypted_num);
  return plain_num;// 元の平文を返却 ※間違えないように
}
int getDecKeyRSA(){
  int e,n,d=0;// e,n:公開鍵 d:秘密鍵
  int decrypted_num=0;// 復号化後の値
  // 秘密鍵(暗号平文)の読込※復号には秘密鍵2つ必要(厳重)
  secretKeyRead(&decrypted_num);
  encDecKeyRead(&e,&n,&d);// 暗号・復号キー読込
  decrypted_num = extpower(decrypted_num, d, n);// 復号化
  return decrypted_num;// 復号値を返却
}
void initPublicKeyRSA(){
  int p,q,n,l = 0;// p,q:素数 n:公開鍵 l:最小公倍数
  int e = 2,d = 2;// e:公開鍵 d:秘密鍵
  srand((unsigned int)time(NULL));// 乱数の初期化
  getPrimeNums(&p,&q);// 素数p,qを生成(乱数で)
  n = p * q;// 公開鍵nの算出
  l = lcm(p-1, q-1);// 最小公倍数lの算出
  while(gcd(l, e) != 1){e++;}// 公開鍵eの算出
  while(e * d % l != 1){d++;}// 秘密鍵dの算出
  encDecKeyWrite(e,n,d);// 暗号・復号キー書出
}
void secretKeyWrite(int num){
  FILE *fp;
  fp = fopen("SECRET_KEY.txt", "w");// 秘密鍵
  fprintf(fp,"%d",num);// 秘密鍵numを保存
  fclose(fp);
}
void secretKeyRead(int *num){
  FILE *fp;
  fp = fopen("SECRET_KEY.txt", "r");// 秘密鍵
  fscanf(fp,"%d",num);// 秘密鍵numを読込
  fclose(fp);
}
void encDecKeyWrite(int e,int n,int d){
  FILE *fp;
  fp = fopen("ENCKEY.txt", "w");// 公開鍵(暗号鍵)
  fprintf(fp, "%d,%d",e,n);// 公開鍵e,nを保存
  fclose(fp);
  fp = fopen("DECKEY.txt", "w");// 秘密鍵(復号鍵)
  fprintf(fp, "%d,%d",d,n);// 秘密鍵d,nを保存
  fclose(fp);
}
void encDecKeyRead(int *e,int *n,int *d){
  FILE *fp;
  fp = fopen("ENCKEY.txt", "r");// 公開鍵(暗号鍵)
  fscanf(fp, "%d,%d",e,n);// 公開鍵e,nを読込
  fclose(fp);
  fp = fopen("DECKEY.txt", "r");// 秘密鍵(復号鍵)
  fscanf(fp, "%d,%d",d,n);// 秘密鍵d,nを読込
  fclose(fp);
}
int getPrimeNums(int *p,int *q) {
  do{
    *p = getPrime(100);// pの素数を算出
    *q = getPrime(100);// qの素数を算出
  }while(p==q);// pとqが同じならループ
  // p<qなら交換
  if(p < q) {int tmp = *p;*p = *q;*q = tmp;}
  return 0;// 正常終了
}
int getPrime(int rangeMax){
  int num = rand() % rangeMax;// 0〜rangeMaxの乱数を格納
  for(int i = 2;i <= sqrt(num);i++){// 素数の計算
    if(num % i == 0){num = rand() % rangeMax;i=1;}// 素数以外の場合やり直す
  }
  return num;
}
int gcd(int a,int b) {
  if(b == 0){
      return a;
  } else {
      return gcd(b, a % b);
  }
}
int lcm(int a,int b) {
  return a * b / gcd(a, b);
}
int extpower(int a,int k,int n) {
  a %= n;
  if(a == 0 || n == 0){
    return 0;
  }
  if(k == 0){
    return 1 % n;
  }
  int value = 1;
  for(int i = 0; i < k; i++) {
    value *= a;
    if(value >= n) {
      value %= n;
    }
  }
  return value;
}
void strToDec(char *text_p,int caesar_num){
  char text_buf_str[READ_TEXT_MAX]={0};// テキスト格納用配列
  for(int i=0;text_p[i]!='\0';i++){// 復号アルゴリズム(シーザー暗号)
    text_buf_str[i]=text_p[i]-caesar_num;
  }
  strcpy(text_p,text_buf_str);// ポインタにコピー
}
void strToEnc(char *text_p,int caesar_num){
  char text_buf_str[READ_TEXT_MAX]={0};// テキスト格納用配列
  for(int i=0;text_p[i]!='\0';i++){// 暗号アルゴリズム(シーザー暗号)
    text_buf_str[i]=text_p[i]+caesar_num;
  }
  strcpy(text_p,text_buf_str);// ポインタにコピー
}
char writeFileData(char *fname,char *text_p){
  FILE *fp;// FILE型構造体
  fp = fopen(fname, "w");// ファイルを開く
  if(fp == NULL){printf("%s FileOpenError\n", fname);return -1;}// ファイルチェック
  fprintf(fp,"%s",text_p);// ファイルに書く
  fclose(fp);// ファイルを閉じる
  return *text_p;// 意味はないけど明示的になる
}
char getFileData(char *fname,char *text_p){
  FILE *fp;// FILE型構造体
  char text_buf_str[READ_TEXT_MAX]={0};// テキスト格納用配列
  fp = fopen(fname, "r");// ファイルを開く
  if(fp == NULL){printf("%s FileOpenError\n", fname);return -1;}// ファイルチェック
  for(int i=0; i<READ_TEXT_MAX ; i++){// 読取処理
    text_buf_str[i] = fgetc(fp);// 1文字単位で文字を読取
    if(text_buf_str[i] == EOF){text_buf_str[i]='\0';break;}// 終端表示子があったら処理終了
  }
  strcpy(text_p,text_buf_str);// 読取文字をポインタにコピー
  fclose(fp);// ファイルを閉じる
  return *text_p;// 意味はないけど明示的になる
}
int getModeSelect(char **mode_pp){
  if(!strcmp(mode_pp[1],"-enc")){
    printf("共通鍵暗号化モード\n");
    return 1;
  }else if(!strcmp(mode_pp[1],"-dec")){
    printf("共通鍵復号化モード\n");
    return 2;
  }else if(!strcmp(mode_pp[1],"-iniRSA")){
    printf("公開鍵暗号化方式初期化モード\n");
    return 3;
  }else if(!strcmp(mode_pp[1],"-encRSA")){
    printf("公開鍵暗号化モード\n");
    return 4;
  }else if(!strcmp(mode_pp[1],"-decRSA")){
    printf("秘密鍵復号化モード\n");
    return 5;
  }else{
    printf("選択失敗\n");
    return -1;
  }
  return 0;
}






























/*
  char *text_p = text_str;
  switch(getModeSelect(argv)==1)strToEnc(text_p);// 暗号化処理
  if(getModeSelect(argv)==2)strToDec(text_p);// 復号化処理

  if(getModeSelect(argv)==1){// 暗号化モード
    getFileData(argv[3],text_p);// ファイルの読込
    strToEnc(text_p);// 文字配列の暗号化
    writeFileData(argv[5],text_p);// ファイルの書出
  }
  else if(getModeSelect(argv)==2){// 復号化モード
    getFileData(argv[3],text_p);// ファイルの読込
    strToDec(text_p);// 文字配列の復号化
    writeFileData(argv[5],text_p);// ファイルの書出
  }
  else{
    printf("選択失敗\n");
  }
printf("%s",text_buf_str);
  for(int i=0;text_buf_str[i]!='\0';i++){
    text_buf_str[i]=text_buf_str[i]-CONV_KEY;
  }
  printf("%s",text_buf_str);



printf("%c",text_p[i]+CONV_KEY);
//for(int i=0;i<READ_TEXT_MAX && text_str[i]!=EOF;i++)putchar(text_str[i]);// テキストの表示


atoi()とシーザー暗号で解けるがあえてしない。
  //for(int i=0;i<READ_TEXT_MAX && txt_buf[i]!=EOF;i++)putchar(txt_buf[i]);// テキストの表示



strcpy(p, "DEF");

  // 読み込んだデータを配列へ格納
  for(i=1; i<READ_TEXT_MAX; i++){
    buf[i] = fgetc(fp);
    if(buf[i] == EOF)break;
  }
  printf("%c",buf[0]);
  printf("%s",buf);

  //char buf_text[READ_TEXT_MAX];// 読込用一時データ
  //char cp_text[READ_TEXT_MAX];// コピー用一時データ
  //char *buf_text_p;
  //int ch = 0;
  //char siny[2048];
  //int n,i,j;
  //char temp, data[1000][1000];
  
  //memset(data, 0, sizeof(data));

  while((temp = fgetc(fp)) != EOF){
    if (temp == ' ' || temp == '\n') {
      data[i][j] = '\n';
      i++;
      j = 0;
    } else {
      data[i][j] = temp;
    j++;
    }
  }
  for (i = 0; i < 10; i++) {
    printf("[%d] Output : %s \n", i, data[i]);
  }
  printf("%s\n",mode_pp[1]);
  while ((ch = fgetc(fp)) != EOF ) {
    putchar(ch);
  }

  //printf("%s",buf_text);
  // 引数表示テスト
  //printf("文字列の個数 %d\n",argc);
  //for(int i=0;i<argc;i++){printf("%d 番目の文字列 %s\n",i,argv[i]);printf("%d 番目の文字列 %s\n",1,argv[0]);}

この問題の解答方法はシーザー暗号方式だと思うが、
あえて、共通鍵暗号方式を使ってみる。
GCCコンパイルの仕方
http://www.ysr.net.it-chiba.ac.jp/data/cc.html

gcc -o encryption.exe encryption.c
./encryption.exe -enc -i input.txt -o output.enc


  // while((chr=fgetc(fp))!=EOF)putchar(chr);
 
//char rd_text[READ_TEXT_MAX];


  //cmd_line_arg(argc,argv);
  //read_text();
 while((chr=fgetc(fp))!=EOF){
    //printf("%d",chr);
    putchar(chr);
  }

int cmd_line_arg(int argc, char *argv[]){
  int i;
  printf("文字列の個数 %d\n",argc);
  for(i=0;i<argc;i++)
    printf("%d 番目の文字列 %s\n",i,argv[i]);
  return 0;
}

void read_text(){
  
}

for(int j = 0;j<sizeof(buf_text) / sizeof(buf_text[0]);j++) {
			cp_text[j] = buf_text[j];
      
		}
    i++;

  // ファイルの内容を配列にコピー
  while(fgets(buf_text,READ_TEXT_MAX,fp)!=NULL){
    
    printf("%d",i);
    i++;
  }


*/

