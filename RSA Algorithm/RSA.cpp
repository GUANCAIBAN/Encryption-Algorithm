#include<stdio.h>
#include<string.h>
int changdu;
int c[100];
//�ж��������ǲ��ǻ��ء� 
bool gcd(int p, int q) {
	int temp1, temp2;   //q=temp2*p+temp1 ;
	if (q < p) {
		temp1 = p;
		p = q;
		q = temp1;
	}
	temp1 = q % p, temp2 = q / p;
	while (temp1 != 0) {

		q = p; p = temp1;
		temp1 = q % p; temp2 = q / p;
	}
	if (temp1 == 0 && temp2 == q) {
		printf("����������\n");
		return true;
	}
	else {
		printf("���������������������룺\n");
		return false;
	}
}

//��e����ģ(p-1)(q-1)����Ԫd����˽Կ 
int extend(int e, int t) {
	int d;
	for (d = 0; d < t; d++) {
		if (e * d % t == 1)
			return d;
	}
}

//�ж������p��q�ǲ������� 
bool is_sushu(int s) {
	for (int i = 2; i < s; i++) {
		if (s % i == 0) return false;
	}
	return true;
}
//������ת������������ 
//void convert(){
//	char mingwen[100];    //�������� 
//	printf("���������ģ�\n");
//	gets(mingwen);
//	changdu=strlen();
//	int ming[changdu];   //����������� 
//	for(int i=0;i<changdu;i++){
//	ming[i]=mingwen[i];        //����ĸת���ɶ�Ӧ��ascii�롣 
//	printf("%d",mingwen[i]);
//	} 
//	 
//	
//}


//���ܺ��� 
void encrypt(int e, int n) {       //�Լ�ָ��ָ��e 

	//�Ƚ���������ת������ĸ����Ӧ��ascii�롣 
	char mingwen[100];    //�������� 
	printf("���������ģ�\n");
	scanf("%s", mingwen);
	//gets(mingwen);
	changdu = strlen(mingwen);
	int ming[strlen(mingwen)];   //����������� 
	for (int i = 0; i < strlen(mingwen); i++) {
		ming[i] = mingwen[i];        //����ĸת���ɶ�Ӧ��ascii�롣 
		printf("%d", mingwen[i]);  //����ĸת���ɶ�Ӧ��ascii�롣���Բ���ӡ 
	}
	printf("\n");
	//��ʼ���� 
	printf("���ܿ�ʼ��������������������\n");
	int zhuan = 1;    //cΪ���ܺ���������� 
	for (int i = 0; i < strlen(mingwen); i++) {

		for (int j = 0; j < e; j++) {
			zhuan = zhuan * ming[i] % n;
			//zhuan=zhuan%n; 
		}
		c[i] = zhuan;
		//printf("%d",mi[i]); 
		zhuan = 1;
	}
	printf("��������Ϊ��\n");
	for (int i = 0; i < strlen(mingwen); i++)
		printf("%d", c[i]);
	printf("\n���ܽ�����������������������\n");
	//����д���ᵼ�������
//	{
//		for(int i=0;i<strlen(mingwen);i++){
//		zhuan=pow()
//		mi[i]=int(pow(ming[i],e))%n;
//		printf("����Ϊ��%d",mi[0]);
//	}
//	} 


//	printf("����Ϊ��\n");
//	for(int i=0;i<strlen(mingwen);i++){
//		printf("%d",mi[i]);
//	}

}


//���ܺ��� 
void decrypto(int d, int n) {
	int de_mingwen[changdu], zhuan1 = 1;
	char de_ming[changdu];
	for (int i = 0; i < changdu; i++) {

		for (int j = 0; j < d; j++) {
			zhuan1 = zhuan1 * c[i] % n;
			//zhuan=zhuan%n; 
		}
		de_mingwen[i] = zhuan1;
		//printf("%d",mi[i]); 
		zhuan1 = 1;
	}
	printf("���ܿ�ʼ��������������������\n");
	printf("���ܺ����������Ϊ��\n");
	for (int i = 0; i < changdu; i++)
		printf("%d", de_mingwen[i]);
	printf("\n");
	printf("���ܺ�ķ�������Ϊ��\n");
	for (int i = 0; i < changdu; i++) {
		de_ming[i] = de_mingwen[i];
		printf("%c", de_ming[i]);
	}
	printf("\n���ܽ�����������������������\n");
}


int main() {
	int q, p, e, d, n, t, x, tep;
	while (1) {
		printf("������p:", p); scanf("%d", &p);
		tep = is_sushu(p);
		if (tep == 0) {
			printf("p��������������������p��\n");
			continue;
		}
		printf("������q:", q); scanf("%d", &q);
		tep = is_sushu(q);
		if (tep == 0) {
			printf("q��������������������q��\n");
			printf("������q:", q); scanf("%d", &q);
			tep = is_sushu(q);
		}
		n = q * p;
		t = (q - 1) * (p - 1);
		tep = gcd(p, q);
		if (tep == 0)  continue;
		printf("t=(q-1)*(p-1)=%d\n", t);
		printf("������һ��ָ��e��ʹ�ã�e,t��=1\n"); scanf("%d", &e);
		tep = gcd(e, t);
		while (tep == 0) {
			printf("����������һ��ָ��e��ʹ�ã�e,t��=1��"); scanf("%d", &e);
			tep = gcd(e, t);
		}
		d = extend(e, t);
		printf("��ԿΪ��%d,һ�����ܺã�", d);
		printf("\n\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
		encrypt(e, n);
		printf("\n��������ȷ����Կ����Կ��ȷ���������������:"); scanf("%d", &d);
		decrypto(d, n);
		printf("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
	}

	return 0;
}
