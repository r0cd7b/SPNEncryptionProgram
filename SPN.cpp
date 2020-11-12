#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <conio.h>
enum work {
	TEXT_SIZE = 1024,
	BLOCK_SIZE = 16,
	KEY_SIZE = 16,
	CYCLE = 10,
	ROUND_KEY_SIZE = CYCLE + 1,
	LOAD_KEY = 1,
	ENCRYPT,
	DECRYPT
};

void GenerateKey(unsigned char *key, FILE *key_file); // 무작위 키 생성 함수.
void LoadKey(unsigned char *key, FILE *key_file); // 키 파일 생성 및 불러오기 함수.
void GeneratePlaintext(unsigned char *text, unsigned int *text_length, FILE *plaintext_file); // 평문 파일 생성 함수.
int LoadPlaintext(unsigned char *text, unsigned int *text_length, FILE *plaintext_file); // 평문 파일 불러오기 함수.
int LoadCyphertext(unsigned char *text, unsigned int *text_length, FILE *ciphertext_file); // 암호문 파일 불러오기 함수.
void SaveCyphertext(unsigned char *ciphertext, unsigned int *padded_length, FILE *ciphertext_file); // 암호문 파일 저장 함수.
void SavePlaintext(unsigned char *plaintext, unsigned int *padded_length, FILE *plaintext_file); // 복호문 파일 저장 함수.

void KeyExpansions(unsigned char *key, unsigned char(*word)[4][4], unsigned char *s_box, unsigned char *round_constant);  // 키 확장(라운드 키 생성) 함수.
void AddRoundKey(unsigned char *text, unsigned char(*word)[4][4], int round); // 라운드 키 XOR(AddRoundKey) 함수.
void SubBytes(unsigned char *text, unsigned char *s_box); // S-Box를 이용한 바이트 대체 함수.
void ShiftRows(unsigned char *text, int inverse); // 4 * 4 평문 행렬의 행 이동 함수.
unsigned char mTwo(unsigned char column); // 오버플로우를 고려한 2 곱하기 연산.
unsigned char m(unsigned char column, int number); // 행렬 특수 곱하기 연산.
void MixColumns(unsigned char *text, int inverse); // 4 * 4 평문 행렬의 열 특수 연산 함수.

int main() {
	unsigned char text[TEXT_SIZE] = { 0 };
	unsigned char *plaintext = NULL; // 128비트 블록 단위의 패딩된 평문.
	unsigned char *ciphertext = NULL; // 128비트 블록 단위의 암호문.
	unsigned char key[KEY_SIZE] = { 0 }; // 128비트 키.
	unsigned char word[ROUND_KEY_SIZE][4][4] = { 0 }; // 확장된 키. word는 32비트(4바이트)이므로 1바이트를 4개씩 묶어 2차원 배열로 표현.
	unsigned char s_box[256] = { // S-Box 표.
		0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
		0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
		0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
		0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
		0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
		0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
		0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
		0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
		0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
		0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
		0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
		0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
		0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
		0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
		0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
		0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
	};
	unsigned char inverse_s_box[256] { // Inverse S-Box 표.
		0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
		0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
		0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
		0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
		0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
		0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
		0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
		0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
		0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
		0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
		0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
		0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
		0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
		0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
		0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
		0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };
	unsigned char round_constant[CYCLE] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 }; // Round Constant 표.
	unsigned int select = 0, key_loaded = 0, text_length = 0, block = 0, padded_length = 0, i = 0, j = 0;
	FILE *key_file = NULL, *plaintext_file = NULL, *ciphertext_file = NULL;

	while (1) {
		printf("┌────────────────────────────┐\n");
		printf("│                  SPN 구조 암호 프로그램                │\n");
		printf("│                                                        │\n");
		printf("│                                        20163248 이상균 │\n");
		printf("│                                                        │\n");
		printf("│ 1. 키 불러오기                                         │\n");
		printf("│ 2. 암호화(ECB 모드)                                    │\n");
		printf("│ 3. 복호화(ECB 모드)                                    │\n");
		printf("│                                                        │\n");
		printf("│ * 그 외 입력 시 종료                                   │\n");
		printf("└────────────────────────────┘\n");
		printf(">>");
		scanf_s("%d", &select);
		while (getchar() != '\n');
		switch (select) {
		// 키 
		case LOAD_KEY:
			LoadKey(key, key_file); // 키 불러오기.
			KeyExpansions(key, word, s_box, round_constant); // 입력으로 사용하는 키를 4묶음씩 4바이트 워드 배열을 11개로 확장(데이터는 1바이트 단위로 처리).
			key_loaded = 1; // key_loaded 플래그 1.
			break;

		// 암호화 작업.
		case ENCRYPT:
			// 키를 불러왔는지 확인.
			if (!key_loaded) {
				printf("키가 없습니다. 먼저 키를 불러오십시오.\n");
				break; // 실패 시 건너뛰기.
			}

			// 평문 파일 불러오기.
			if (LoadPlaintext(text, &text_length, plaintext_file)) // 불러오기를 실패할 경우.
				GeneratePlaintext(text, &text_length, plaintext_file); // 평문 파일 생성.

			// 문자열 길이에 맞춰 블록 수 계산 및 동적 할당.
			if (text_length % BLOCK_SIZE) // 블록 수 계산.
				block = text_length / BLOCK_SIZE + 1; // 나눈 나머지가 있을 경우 + 1 블록.
			else
				block = text_length / BLOCK_SIZE; // 나눈 나머지가 없을 경우 + 0 블록.
			padded_length = block * BLOCK_SIZE; // 총 길이 계산.
			plaintext = (unsigned char *)calloc(padded_length, 1); // 지정한 크기대로 동적 할당 및 0으로 초기화.
			ciphertext = (unsigned char *)calloc(padded_length, 1); // 지정한 크기대로 동적 할당 및 0으로 초기화.
			for (i = 0; i < text_length; i++)
				plaintext[i] = text[i]; // 불러들인 평문을 plaintext에 복사.

			// ECB 블록 암호 모드 수행. 블록 수만큼 반복.
			for (i = 0; i < block; i++) {
				unsigned char block_text[BLOCK_SIZE] = { 0 };
				for (j = 0; j < BLOCK_SIZE; j++)
					block_text[j] = plaintext[BLOCK_SIZE * i + j]; // 수행할 평문 블록을 block_text에 복사.

				// Initial Round. 라운드 반복 전 우선 작업.
				AddRoundKey(block_text, word, 0); // AddRoundKey 수행.
				// Rounds. 마지막 라운드 이전까지 수행.
				for (j = 1; j < CYCLE; j++) { // 1 ~ 9라운드.
					SubBytes(block_text, s_box); // Sub Bytes. S-Box를 이용하여 데이터 치환.
					ShiftRows(block_text, 1); // Shift Rows. 평문 행렬의 행을 바이트 단위로 왼쪽 회전.
					MixColumns(block_text, 1); // Mix Columns. 평문 행렬의 열을 바이트 단위로 특수 연산.
					AddRoundKey(block_text, word, j); // AddRoundKey. i 라운드에 해당하는 라운드 키 이용.
				}
				// Final Round. 마지막 라운드 수행. 단, Mix Columns은 수행 안 함.
				SubBytes(block_text, s_box);
				ShiftRows(block_text, 1);
				AddRoundKey(block_text, word, CYCLE);

				for (j = 0; j < BLOCK_SIZE; j++)
					ciphertext[BLOCK_SIZE * i + j] = block_text[j]; // 암호화된 블록을 ciphertext에 복사.
			}
			printf("암호화가 완료되었습니다.\n\n");
			printf("암호문: \n");
			for (i = 0; i < padded_length; i++)
				printf("%c", ciphertext[i]); // 암호문 출력.
			printf("\n\n");

			// 암호문을 파일로 저장하기.
			SaveCyphertext(ciphertext, &padded_length, ciphertext_file);

			free(plaintext); // 종료 시 동적 할당 해제.
			free(ciphertext);
			plaintext = NULL;
			ciphertext = NULL;
			break;

		// 복호화 작업.
		case DECRYPT:
			// 키를 불러왔는지 확인.
			if (!key_loaded) {
				printf("키가 없습니다. 먼저 키를 불러오십시오.\n");
				break; // 실패 시 건너뛰기.
			}

			// 암호문 파일 불러오기.
			if (LoadCyphertext(text, &text_length, ciphertext_file)) // 불러오기를 실패할 경우.
				break; // 이하 작업 건너뛰기.

			// 문자열 길이에 맞춰 블록 수 계산 및 동적 할당.
			if (text_length % BLOCK_SIZE) // 블록 수 계산.
				block = text_length / BLOCK_SIZE + 1; // 나눈 나머지가 있을 경우 + 1 블록.
			else
				block = text_length / BLOCK_SIZE; // 나눈 나머지가 없을 경우 + 0 블록.
			padded_length = block * BLOCK_SIZE; // 총 길이 계산.
			plaintext = (unsigned char *)calloc(padded_length, 1); // 지정한 크기대로 동적 할당 및 0으로 초기화.
			ciphertext = (unsigned char *)calloc(padded_length, 1); // 지정한 크기대로 동적 할당 및 0으로 초기화.
			for (i = 0; i < text_length; i++)
				ciphertext[i] = text[i]; // 불러들인 암호문을 ciphertext에 복사.

			// ECB 블록 암호 모드 수행. 블록 수만큼 반복.
			for (i = 0; i < block; i++) {
				unsigned char block_text[BLOCK_SIZE] = { 0 };
				for (j = 0; j < BLOCK_SIZE; j++)
					block_text[j] = ciphertext[BLOCK_SIZE * i + j]; // 수행할 암호문 블록을 block_text에 복사.

				// Initial Round. 라운드 반복 전 우선 작업.
				AddRoundKey(block_text, word, CYCLE); // AddRoundKey 수행.
				// Rounds. 마지막 라운드 이전까지 수행.
				for (j = CYCLE - 1; j > 0; j--) { // 1 ~ 9라운드.
					ShiftRows(block_text, -1); // Inverse Shift Rows. 암호문 행렬의 행을 바이트 단위로 왼쪽 회전.
					SubBytes(block_text, inverse_s_box); // Inverse Sub Bytes. S-Box를 이용하여 데이터 치환.
					AddRoundKey(block_text, word, j); // AddRoundKey. i 라운드에 해당하는 라운드 키 이용.
					MixColumns(block_text, -1); // Inverse Mix Columns. 암호문 행렬의 열을 바이트 단위로 특수 연산.
				}
				// Final Round. 마지막 라운드 수행. 단, Inverse Mix Columns은 수행 안 함.
				ShiftRows(block_text, -1);
				SubBytes(block_text, inverse_s_box);
				AddRoundKey(block_text, word, 0);

				for (j = 0; j < BLOCK_SIZE; j++)
					plaintext[BLOCK_SIZE * i + j] = block_text[j]; // 복호화된 블록을 plaintext에 복사.
			}
			printf("복호화가 완료되었습니다.\n\n");
			printf("복호문: \n");
			for (i = 0; i < padded_length; i++)
				printf("%c", plaintext[i]); // 복호문 출력.
			printf("\n\n");

			// 복호문을 파일로 저장하기.
			SavePlaintext(plaintext, &padded_length, plaintext_file);

			free(plaintext); // 종료 시 동적 할당 해제.
			free(ciphertext);
			plaintext = NULL;
			ciphertext = NULL;
			break;

		// 종료.
		default:
			return 0;
		}
		system("pause");
		system("cls");
	}
}

void GenerateKey(unsigned char *key, FILE *key_file) {
	int i = 0;
	srand((unsigned int)time(NULL));
	for (i = 0; i < KEY_SIZE; i++)
		key[i] = (unsigned char)((float)rand() / RAND_MAX * 256); // 1바이트 단위로 난수 생성.
	fopen_s(&key_file, "key.txt", "wb");
	for (i = 0; i < KEY_SIZE; i++)
		fprintf(key_file, "%c", key[i]); // 키 파일로 저장.
	fclose(key_file);
	printf("무작위 키를 \'key.bin\' 파일에 저장합니다.\n");
}
void LoadKey(unsigned char *key, FILE *key_file) {
	char c = 0;
	int i = 0;
	if (fopen_s(&key_file, "key.txt", "rb")) { // 키 파일이 없을 경우.
		printf("참고할 \'key.txt\' 파일이 없습니다.\n");
		GenerateKey(key, key_file);
	}
	else { // 키 파일이 있을 경우.
		for (i = 0; i < KEY_SIZE; i++)
			fscanf_s(key_file, "%c", &key[i], 1); // 키를 불러온 후 key 배열에 복사.
		fclose(key_file);
	}
	printf("저장된 \'key.txt\' 파일을 불러옵니다.\n\n");
	printf("키: ");
	for (i = 0; i < KEY_SIZE; i++)
		printf("%c", key[i]); // 키를 문자로 출력.
	printf("\n\n");
	printf("16진수 키: ");
	for (i = 0; i < KEY_SIZE; i++)
		printf("%02X ", key[i]); // 키를 16진수로 출력.
	printf("\n\n");
}
void GeneratePlaintext(unsigned char *text, unsigned int *text_length, FILE *plaintext_file) {
	unsigned int i = 0;
	printf("불러올 \'plaintext.txt\' 파일이 없습니다.\n");
	printf("파일을 새로 생성합니다.\n\n");
	printf("평문 입력\n>>");
	gets_s((char *)text, TEXT_SIZE - 1); // 평문 입력.
	*text_length = strlen((char *)text); // 평문 길이 저장.
	for (i = *text_length; i < TEXT_SIZE; i++)
		text[i] = 0; // 나머지 text 원소는 0으로 초기화.
	fopen_s(&plaintext_file, "plaintext.txt", "w");
	fputs((char *)text, plaintext_file); // 평문 파일로 저장.
	fclose(plaintext_file);
	printf("\n평문을 \'plaintext.txt\' 파일에 저장했습니다.\n");
}
int LoadPlaintext(unsigned char *text, unsigned int *text_length, FILE *plaintext_file) {
	unsigned int i = 0;
	printf("저장된 \'plaintext.txt\' 파일을 불러옵니다.\n");
	if (fopen_s(&plaintext_file, "plaintext.txt", "rb")) // 파일이 없을 경우.
		return 1;
	// 이하 파일이 있을 경우.
	for (i = 0; i < TEXT_SIZE; i++)
		if (fscanf_s(plaintext_file, "%c", &text[i], 1) == EOF) // 평문 불러오기.
			break;
	fclose(plaintext_file);
	*text_length = i; // 평문 길이 저장.
	for (i = *text_length; i < TEXT_SIZE; i++)
		text[i] = 0; // 나머지 text 원소는 0으로 초기화.
	printf("\n평문: \n");
	for (i = 0; i < *text_length; i++)
		printf("%c", text[i]); // 불러온 평문 출력.
	printf("\n\n");
	return 0;
}
int LoadCyphertext(unsigned char *text, unsigned int *text_length, FILE *ciphertext_file) {
	unsigned int i = 0;
	printf("저장된 \'ciphertext.txt\' 파일을 불러옵니다.\n");
	if (fopen_s(&ciphertext_file, "ciphertext.txt", "rb")) { // 파일이 없을 경우.
		printf("불러올 \'ciphertext.txt\' 파일이 없습니다.\n");
		printf("암호화 작업부터 수행해주세요.\n");
		return 1;
	}
	// 이하 파일이 있을 경우.
	for (i = 0; i < TEXT_SIZE; i++)
		if (fscanf_s(ciphertext_file, "%c", &text[i], 1) == EOF) // 암호문 불러오기.
			break;
	fclose(ciphertext_file);
	*text_length = i; // 암호문 길이 저장.
	for (i = *text_length; i < TEXT_SIZE; i++)
		text[i] = 0; // 나머지 text 원소는 0으로 초기화.
	printf("\n암호문: \n");
	for (i = 0; i < *text_length; i++)
		printf("%c", text[i]); // 불러온 암호문 출력.
	printf("\n\n");
	return 0;
}
void SaveCyphertext(unsigned char *ciphertext, unsigned int *padded_length, FILE *ciphertext_file) {
	unsigned int i = 0;
	fopen_s(&ciphertext_file, "ciphertext.txt", "wb");
	for (i = 0; i < *padded_length; i++)
		fprintf(ciphertext_file, "%c", ciphertext[i]); // 암호문을 파일로 저장.
	fclose(ciphertext_file);
	printf("암호문을 \'ciphertext.txt\' 파일에 저장합니다.\n");
}
void SavePlaintext(unsigned char *plaintext, unsigned int *padded_length, FILE *plaintext_file) {
	unsigned int i = 0;
	fopen_s(&plaintext_file, "plaintext.txt", "wb");
	for (i = 0; i < *padded_length; i++)
		fprintf(plaintext_file, "%c", plaintext[i]); // 복호문을 파일로 저장.
	fclose(plaintext_file);
	printf("복호문을 \'plaintext.txt\' 파일에 저장합니다.\n");
}
void KeyExpansions(unsigned char *key, unsigned char(*word)[4][4], unsigned char *s_box, unsigned char *round_constant) {
	unsigned char before_word[4] = { 0 }; // word[4n - 1]의 원본은 살려두기 위해 임시 배열(before_word)을 이용.
	int i = 0, j = 0, k = 0;

	// 처음 네개의 워드는 미리 만들어 둔 128비트(16바이트) 키로부터 만듦.
	for (i = 0; i < 4; i++)
		for (j = 0; j < 4; j++)
			word[0][i][j] = key[i * 4 + j]; // 1바이트씩 총 16바이트 대입.

	// word[1][4][4]부터는 아래 과정을 수행.
	for (i = 1; i < ROUND_KEY_SIZE; i++) {

		// 4n번째 word는 아래 과정을 거친다.
		// RotWord. (4n - 1)번째 word를 1 바이트 왼쪽 회전하여 before_word에 저장.
		for (j = 0; j < 4; j++)
			before_word[j] = word[i - 1][3][(j + 1) % 4];

		// SubWord. S-Box를 이용하여 1바이트 단위로 before_word 교환.
		for (j = 0; j < 4; j++)
			before_word[j] = s_box[(int)(before_word[j] >> 4) * BLOCK_SIZE + (before_word[j] & 0x0f)]; // S-Box는 16 * 16 행렬이므로 (왼쪽 4비트 * 16 + 오른쪽 4비트)를 계산하여 찾아갈 수 있음.

		// XOR with Rcon[]. Round constant를 이용해 before_word를 XOR.
		before_word[0] ^= round_constant[i - 1]; // 해당 라운스 수에 해당하는 round_constant의 원소와 XOR.
		before_word[1] ^= 0x00; // 나머지는 0과 XOR하여 1로 통일.
		before_word[2] ^= 0x00;
		before_word[3] ^= 0x00;

		// 변환된 before_word와 4n번째 word를 XOR.
		for (j = 0; j < 4; j++)
			word[i][0][j] = before_word[j] ^ word[i - 1][0][j];

		// 4n번째 word를 제외한 나머지 word는 (n - 1)번째 word와 XOR.
		for (j = 1; j < 4; j++)
			for (k = 0; k < 4; k++)
				word[i][j][k] = word[i - 1][j][k] ^ word[i][j - 1][k];
	}
}
void AddRoundKey(unsigned char *text, unsigned char(*word)[4][4], int round) {
	int i = 0, j = 0;
	for (i = 0; i < 4; i++)
		for (j = 0; j < 4; j++)
			text[i * 4 + j] ^= word[round][i][j]; // 1바이트 단위로 라운드 키와 평문 XOR.
}
void SubBytes(unsigned char *text, unsigned char *s_box) {
	int i = 0;
	for (i = 0; i < BLOCK_SIZE; i++)
		text[i] = s_box[(int)(text[i] >> 4) * BLOCK_SIZE + (text[i] & 0x0f)]; // S-Box는 16 * 16 행렬이므로 (왼쪽 4비트 * 16 + 오른쪽 4비트)를 계산하여 찾아갈 수 있음.
}
void ShiftRows(unsigned char *text, int inverse) {
	unsigned char temp = 0;
	if (inverse >= 0) {
		temp = text[4];
		text[4] = text[5];
		text[5] = text[6];
		text[6] = text[7];
		text[7] = temp;
		temp = text[8];
		text[8] = text[10];
		text[10] = temp;
		temp = text[9];
		text[9] = text[11];
		text[11] = temp;
		temp = text[12];
		text[12] = text[15];
		text[15] = text[14];
		text[14] = text[13];
		text[13] = temp;
		return;
	}
	temp = text[4];
	text[4] = text[7];
	text[7] = text[6];
	text[6] = text[5];
	text[5] = temp;
	temp = text[8];
	text[8] = text[10];
	text[10] = temp;
	temp = text[9];
	text[9] = text[11];
	text[11] = temp;
	temp = text[12];
	text[12] = text[13];
	text[13] = text[14];
	text[14] = text[15];
	text[15] = temp;
}
unsigned char mTwo(unsigned char column) {
	return column << 1 ^ (column >> 7) * 0x1B; // 2 곱하기 연산. 단, 오버플로우가 있을 시 0x1B를 추가로 XOR.
}
unsigned char m(unsigned char column, int number) {
	unsigned char temp = 0;
	if (number & 8)
		temp ^= mTwo(mTwo(mTwo(column)));
	if (number & 4)
		temp ^= mTwo(mTwo(column));
	if (number & 2)
		temp ^= mTwo(column);
	if (number & 1)
		temp ^= column;
	return temp;
}
void MixColumns(unsigned char *text, int inverse) {
	int i = 0;
	if (inverse >= 0) {
		for (i = 0; i < 4; i++) {
			unsigned char column[4] = { text[i], text[i + 4], text[i + 8], text[i + 12] };
			text[i] = m(column[0], 2) ^ m(column[1], 3) ^ m(column[2], 1) ^ m(column[3], 1);
			text[i + 4] = m(column[0], 1) ^ m(column[1], 2) ^ m(column[2], 3) ^ m(column[3], 1);
			text[i + 8] = m(column[0], 1) ^ m(column[1], 1) ^ m(column[2], 2) ^ m(column[3], 3);
			text[i + 12] = m(column[0], 3) ^ m(column[1], 1) ^ m(column[2], 1) ^ m(column[3], 2);
		}
		return;
	}
	for (i = 0; i < 4; i++) {
		unsigned char column[4] = { text[i], text[i + 4], text[i + 8], text[i + 12] };
		text[i] = m(column[0], 14) ^ m(column[1], 11) ^ m(column[2], 13) ^ m(column[3], 9);
		text[i + 4] = m(column[0], 9) ^ m(column[1], 14) ^ m(column[2], 11) ^ m(column[3], 13);
		text[i + 8] = m(column[0], 13) ^ m(column[1], 9) ^ m(column[2], 14) ^ m(column[3], 11);
		text[i + 12] = m(column[0], 11) ^ m(column[1], 13) ^ m(column[2], 9) ^ m(column[3], 14);
	}
}