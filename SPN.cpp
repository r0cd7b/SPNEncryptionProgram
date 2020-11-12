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

void GenerateKey(unsigned char *key, FILE *key_file); // ������ Ű ���� �Լ�.
void LoadKey(unsigned char *key, FILE *key_file); // Ű ���� ���� �� �ҷ����� �Լ�.
void GeneratePlaintext(unsigned char *text, unsigned int *text_length, FILE *plaintext_file); // �� ���� ���� �Լ�.
int LoadPlaintext(unsigned char *text, unsigned int *text_length, FILE *plaintext_file); // �� ���� �ҷ����� �Լ�.
int LoadCyphertext(unsigned char *text, unsigned int *text_length, FILE *ciphertext_file); // ��ȣ�� ���� �ҷ����� �Լ�.
void SaveCyphertext(unsigned char *ciphertext, unsigned int *padded_length, FILE *ciphertext_file); // ��ȣ�� ���� ���� �Լ�.
void SavePlaintext(unsigned char *plaintext, unsigned int *padded_length, FILE *plaintext_file); // ��ȣ�� ���� ���� �Լ�.

void KeyExpansions(unsigned char *key, unsigned char(*word)[4][4], unsigned char *s_box, unsigned char *round_constant);  // Ű Ȯ��(���� Ű ����) �Լ�.
void AddRoundKey(unsigned char *text, unsigned char(*word)[4][4], int round); // ���� Ű XOR(AddRoundKey) �Լ�.
void SubBytes(unsigned char *text, unsigned char *s_box); // S-Box�� �̿��� ����Ʈ ��ü �Լ�.
void ShiftRows(unsigned char *text, int inverse); // 4 * 4 �� ����� �� �̵� �Լ�.
unsigned char mTwo(unsigned char column); // �����÷ο츦 ����� 2 ���ϱ� ����.
unsigned char m(unsigned char column, int number); // ��� Ư�� ���ϱ� ����.
void MixColumns(unsigned char *text, int inverse); // 4 * 4 �� ����� �� Ư�� ���� �Լ�.

int main() {
	unsigned char text[TEXT_SIZE] = { 0 };
	unsigned char *plaintext = NULL; // 128��Ʈ ��� ������ �е��� ��.
	unsigned char *ciphertext = NULL; // 128��Ʈ ��� ������ ��ȣ��.
	unsigned char key[KEY_SIZE] = { 0 }; // 128��Ʈ Ű.
	unsigned char word[ROUND_KEY_SIZE][4][4] = { 0 }; // Ȯ��� Ű. word�� 32��Ʈ(4����Ʈ)�̹Ƿ� 1����Ʈ�� 4���� ���� 2���� �迭�� ǥ��.
	unsigned char s_box[256] = { // S-Box ǥ.
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
	unsigned char inverse_s_box[256] { // Inverse S-Box ǥ.
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
	unsigned char round_constant[CYCLE] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 }; // Round Constant ǥ.
	unsigned int select = 0, key_loaded = 0, text_length = 0, block = 0, padded_length = 0, i = 0, j = 0;
	FILE *key_file = NULL, *plaintext_file = NULL, *ciphertext_file = NULL;

	while (1) {
		printf("������������������������������������������������������������\n");
		printf("��                  SPN ���� ��ȣ ���α׷�                ��\n");
		printf("��                                                        ��\n");
		printf("��                                        20163248 �̻�� ��\n");
		printf("��                                                        ��\n");
		printf("�� 1. Ű �ҷ�����                                         ��\n");
		printf("�� 2. ��ȣȭ(ECB ���)                                    ��\n");
		printf("�� 3. ��ȣȭ(ECB ���)                                    ��\n");
		printf("��                                                        ��\n");
		printf("�� * �� �� �Է� �� ����                                   ��\n");
		printf("������������������������������������������������������������\n");
		printf(">>");
		scanf_s("%d", &select);
		while (getchar() != '\n');
		switch (select) {
		// Ű 
		case LOAD_KEY:
			LoadKey(key, key_file); // Ű �ҷ�����.
			KeyExpansions(key, word, s_box, round_constant); // �Է����� ����ϴ� Ű�� 4������ 4����Ʈ ���� �迭�� 11���� Ȯ��(�����ʹ� 1����Ʈ ������ ó��).
			key_loaded = 1; // key_loaded �÷��� 1.
			break;

		// ��ȣȭ �۾�.
		case ENCRYPT:
			// Ű�� �ҷ��Դ��� Ȯ��.
			if (!key_loaded) {
				printf("Ű�� �����ϴ�. ���� Ű�� �ҷ����ʽÿ�.\n");
				break; // ���� �� �ǳʶٱ�.
			}

			// �� ���� �ҷ�����.
			if (LoadPlaintext(text, &text_length, plaintext_file)) // �ҷ����⸦ ������ ���.
				GeneratePlaintext(text, &text_length, plaintext_file); // �� ���� ����.

			// ���ڿ� ���̿� ���� ��� �� ��� �� ���� �Ҵ�.
			if (text_length % BLOCK_SIZE) // ��� �� ���.
				block = text_length / BLOCK_SIZE + 1; // ���� �������� ���� ��� + 1 ���.
			else
				block = text_length / BLOCK_SIZE; // ���� �������� ���� ��� + 0 ���.
			padded_length = block * BLOCK_SIZE; // �� ���� ���.
			plaintext = (unsigned char *)calloc(padded_length, 1); // ������ ũ���� ���� �Ҵ� �� 0���� �ʱ�ȭ.
			ciphertext = (unsigned char *)calloc(padded_length, 1); // ������ ũ���� ���� �Ҵ� �� 0���� �ʱ�ȭ.
			for (i = 0; i < text_length; i++)
				plaintext[i] = text[i]; // �ҷ����� ���� plaintext�� ����.

			// ECB ��� ��ȣ ��� ����. ��� ����ŭ �ݺ�.
			for (i = 0; i < block; i++) {
				unsigned char block_text[BLOCK_SIZE] = { 0 };
				for (j = 0; j < BLOCK_SIZE; j++)
					block_text[j] = plaintext[BLOCK_SIZE * i + j]; // ������ �� ����� block_text�� ����.

				// Initial Round. ���� �ݺ� �� �켱 �۾�.
				AddRoundKey(block_text, word, 0); // AddRoundKey ����.
				// Rounds. ������ ���� �������� ����.
				for (j = 1; j < CYCLE; j++) { // 1 ~ 9����.
					SubBytes(block_text, s_box); // Sub Bytes. S-Box�� �̿��Ͽ� ������ ġȯ.
					ShiftRows(block_text, 1); // Shift Rows. �� ����� ���� ����Ʈ ������ ���� ȸ��.
					MixColumns(block_text, 1); // Mix Columns. �� ����� ���� ����Ʈ ������ Ư�� ����.
					AddRoundKey(block_text, word, j); // AddRoundKey. i ���忡 �ش��ϴ� ���� Ű �̿�.
				}
				// Final Round. ������ ���� ����. ��, Mix Columns�� ���� �� ��.
				SubBytes(block_text, s_box);
				ShiftRows(block_text, 1);
				AddRoundKey(block_text, word, CYCLE);

				for (j = 0; j < BLOCK_SIZE; j++)
					ciphertext[BLOCK_SIZE * i + j] = block_text[j]; // ��ȣȭ�� ����� ciphertext�� ����.
			}
			printf("��ȣȭ�� �Ϸ�Ǿ����ϴ�.\n\n");
			printf("��ȣ��: \n");
			for (i = 0; i < padded_length; i++)
				printf("%c", ciphertext[i]); // ��ȣ�� ���.
			printf("\n\n");

			// ��ȣ���� ���Ϸ� �����ϱ�.
			SaveCyphertext(ciphertext, &padded_length, ciphertext_file);

			free(plaintext); // ���� �� ���� �Ҵ� ����.
			free(ciphertext);
			plaintext = NULL;
			ciphertext = NULL;
			break;

		// ��ȣȭ �۾�.
		case DECRYPT:
			// Ű�� �ҷ��Դ��� Ȯ��.
			if (!key_loaded) {
				printf("Ű�� �����ϴ�. ���� Ű�� �ҷ����ʽÿ�.\n");
				break; // ���� �� �ǳʶٱ�.
			}

			// ��ȣ�� ���� �ҷ�����.
			if (LoadCyphertext(text, &text_length, ciphertext_file)) // �ҷ����⸦ ������ ���.
				break; // ���� �۾� �ǳʶٱ�.

			// ���ڿ� ���̿� ���� ��� �� ��� �� ���� �Ҵ�.
			if (text_length % BLOCK_SIZE) // ��� �� ���.
				block = text_length / BLOCK_SIZE + 1; // ���� �������� ���� ��� + 1 ���.
			else
				block = text_length / BLOCK_SIZE; // ���� �������� ���� ��� + 0 ���.
			padded_length = block * BLOCK_SIZE; // �� ���� ���.
			plaintext = (unsigned char *)calloc(padded_length, 1); // ������ ũ���� ���� �Ҵ� �� 0���� �ʱ�ȭ.
			ciphertext = (unsigned char *)calloc(padded_length, 1); // ������ ũ���� ���� �Ҵ� �� 0���� �ʱ�ȭ.
			for (i = 0; i < text_length; i++)
				ciphertext[i] = text[i]; // �ҷ����� ��ȣ���� ciphertext�� ����.

			// ECB ��� ��ȣ ��� ����. ��� ����ŭ �ݺ�.
			for (i = 0; i < block; i++) {
				unsigned char block_text[BLOCK_SIZE] = { 0 };
				for (j = 0; j < BLOCK_SIZE; j++)
					block_text[j] = ciphertext[BLOCK_SIZE * i + j]; // ������ ��ȣ�� ����� block_text�� ����.

				// Initial Round. ���� �ݺ� �� �켱 �۾�.
				AddRoundKey(block_text, word, CYCLE); // AddRoundKey ����.
				// Rounds. ������ ���� �������� ����.
				for (j = CYCLE - 1; j > 0; j--) { // 1 ~ 9����.
					ShiftRows(block_text, -1); // Inverse Shift Rows. ��ȣ�� ����� ���� ����Ʈ ������ ���� ȸ��.
					SubBytes(block_text, inverse_s_box); // Inverse Sub Bytes. S-Box�� �̿��Ͽ� ������ ġȯ.
					AddRoundKey(block_text, word, j); // AddRoundKey. i ���忡 �ش��ϴ� ���� Ű �̿�.
					MixColumns(block_text, -1); // Inverse Mix Columns. ��ȣ�� ����� ���� ����Ʈ ������ Ư�� ����.
				}
				// Final Round. ������ ���� ����. ��, Inverse Mix Columns�� ���� �� ��.
				ShiftRows(block_text, -1);
				SubBytes(block_text, inverse_s_box);
				AddRoundKey(block_text, word, 0);

				for (j = 0; j < BLOCK_SIZE; j++)
					plaintext[BLOCK_SIZE * i + j] = block_text[j]; // ��ȣȭ�� ����� plaintext�� ����.
			}
			printf("��ȣȭ�� �Ϸ�Ǿ����ϴ�.\n\n");
			printf("��ȣ��: \n");
			for (i = 0; i < padded_length; i++)
				printf("%c", plaintext[i]); // ��ȣ�� ���.
			printf("\n\n");

			// ��ȣ���� ���Ϸ� �����ϱ�.
			SavePlaintext(plaintext, &padded_length, plaintext_file);

			free(plaintext); // ���� �� ���� �Ҵ� ����.
			free(ciphertext);
			plaintext = NULL;
			ciphertext = NULL;
			break;

		// ����.
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
		key[i] = (unsigned char)((float)rand() / RAND_MAX * 256); // 1����Ʈ ������ ���� ����.
	fopen_s(&key_file, "key.txt", "wb");
	for (i = 0; i < KEY_SIZE; i++)
		fprintf(key_file, "%c", key[i]); // Ű ���Ϸ� ����.
	fclose(key_file);
	printf("������ Ű�� \'key.bin\' ���Ͽ� �����մϴ�.\n");
}
void LoadKey(unsigned char *key, FILE *key_file) {
	char c = 0;
	int i = 0;
	if (fopen_s(&key_file, "key.txt", "rb")) { // Ű ������ ���� ���.
		printf("������ \'key.txt\' ������ �����ϴ�.\n");
		GenerateKey(key, key_file);
	}
	else { // Ű ������ ���� ���.
		for (i = 0; i < KEY_SIZE; i++)
			fscanf_s(key_file, "%c", &key[i], 1); // Ű�� �ҷ��� �� key �迭�� ����.
		fclose(key_file);
	}
	printf("����� \'key.txt\' ������ �ҷ��ɴϴ�.\n\n");
	printf("Ű: ");
	for (i = 0; i < KEY_SIZE; i++)
		printf("%c", key[i]); // Ű�� ���ڷ� ���.
	printf("\n\n");
	printf("16���� Ű: ");
	for (i = 0; i < KEY_SIZE; i++)
		printf("%02X ", key[i]); // Ű�� 16������ ���.
	printf("\n\n");
}
void GeneratePlaintext(unsigned char *text, unsigned int *text_length, FILE *plaintext_file) {
	unsigned int i = 0;
	printf("�ҷ��� \'plaintext.txt\' ������ �����ϴ�.\n");
	printf("������ ���� �����մϴ�.\n\n");
	printf("�� �Է�\n>>");
	gets_s((char *)text, TEXT_SIZE - 1); // �� �Է�.
	*text_length = strlen((char *)text); // �� ���� ����.
	for (i = *text_length; i < TEXT_SIZE; i++)
		text[i] = 0; // ������ text ���Ҵ� 0���� �ʱ�ȭ.
	fopen_s(&plaintext_file, "plaintext.txt", "w");
	fputs((char *)text, plaintext_file); // �� ���Ϸ� ����.
	fclose(plaintext_file);
	printf("\n���� \'plaintext.txt\' ���Ͽ� �����߽��ϴ�.\n");
}
int LoadPlaintext(unsigned char *text, unsigned int *text_length, FILE *plaintext_file) {
	unsigned int i = 0;
	printf("����� \'plaintext.txt\' ������ �ҷ��ɴϴ�.\n");
	if (fopen_s(&plaintext_file, "plaintext.txt", "rb")) // ������ ���� ���.
		return 1;
	// ���� ������ ���� ���.
	for (i = 0; i < TEXT_SIZE; i++)
		if (fscanf_s(plaintext_file, "%c", &text[i], 1) == EOF) // �� �ҷ�����.
			break;
	fclose(plaintext_file);
	*text_length = i; // �� ���� ����.
	for (i = *text_length; i < TEXT_SIZE; i++)
		text[i] = 0; // ������ text ���Ҵ� 0���� �ʱ�ȭ.
	printf("\n��: \n");
	for (i = 0; i < *text_length; i++)
		printf("%c", text[i]); // �ҷ��� �� ���.
	printf("\n\n");
	return 0;
}
int LoadCyphertext(unsigned char *text, unsigned int *text_length, FILE *ciphertext_file) {
	unsigned int i = 0;
	printf("����� \'ciphertext.txt\' ������ �ҷ��ɴϴ�.\n");
	if (fopen_s(&ciphertext_file, "ciphertext.txt", "rb")) { // ������ ���� ���.
		printf("�ҷ��� \'ciphertext.txt\' ������ �����ϴ�.\n");
		printf("��ȣȭ �۾����� �������ּ���.\n");
		return 1;
	}
	// ���� ������ ���� ���.
	for (i = 0; i < TEXT_SIZE; i++)
		if (fscanf_s(ciphertext_file, "%c", &text[i], 1) == EOF) // ��ȣ�� �ҷ�����.
			break;
	fclose(ciphertext_file);
	*text_length = i; // ��ȣ�� ���� ����.
	for (i = *text_length; i < TEXT_SIZE; i++)
		text[i] = 0; // ������ text ���Ҵ� 0���� �ʱ�ȭ.
	printf("\n��ȣ��: \n");
	for (i = 0; i < *text_length; i++)
		printf("%c", text[i]); // �ҷ��� ��ȣ�� ���.
	printf("\n\n");
	return 0;
}
void SaveCyphertext(unsigned char *ciphertext, unsigned int *padded_length, FILE *ciphertext_file) {
	unsigned int i = 0;
	fopen_s(&ciphertext_file, "ciphertext.txt", "wb");
	for (i = 0; i < *padded_length; i++)
		fprintf(ciphertext_file, "%c", ciphertext[i]); // ��ȣ���� ���Ϸ� ����.
	fclose(ciphertext_file);
	printf("��ȣ���� \'ciphertext.txt\' ���Ͽ� �����մϴ�.\n");
}
void SavePlaintext(unsigned char *plaintext, unsigned int *padded_length, FILE *plaintext_file) {
	unsigned int i = 0;
	fopen_s(&plaintext_file, "plaintext.txt", "wb");
	for (i = 0; i < *padded_length; i++)
		fprintf(plaintext_file, "%c", plaintext[i]); // ��ȣ���� ���Ϸ� ����.
	fclose(plaintext_file);
	printf("��ȣ���� \'plaintext.txt\' ���Ͽ� �����մϴ�.\n");
}
void KeyExpansions(unsigned char *key, unsigned char(*word)[4][4], unsigned char *s_box, unsigned char *round_constant) {
	unsigned char before_word[4] = { 0 }; // word[4n - 1]�� ������ ����α� ���� �ӽ� �迭(before_word)�� �̿�.
	int i = 0, j = 0, k = 0;

	// ó�� �װ��� ����� �̸� ����� �� 128��Ʈ(16����Ʈ) Ű�κ��� ����.
	for (i = 0; i < 4; i++)
		for (j = 0; j < 4; j++)
			word[0][i][j] = key[i * 4 + j]; // 1����Ʈ�� �� 16����Ʈ ����.

	// word[1][4][4]���ʹ� �Ʒ� ������ ����.
	for (i = 1; i < ROUND_KEY_SIZE; i++) {

		// 4n��° word�� �Ʒ� ������ ��ģ��.
		// RotWord. (4n - 1)��° word�� 1 ����Ʈ ���� ȸ���Ͽ� before_word�� ����.
		for (j = 0; j < 4; j++)
			before_word[j] = word[i - 1][3][(j + 1) % 4];

		// SubWord. S-Box�� �̿��Ͽ� 1����Ʈ ������ before_word ��ȯ.
		for (j = 0; j < 4; j++)
			before_word[j] = s_box[(int)(before_word[j] >> 4) * BLOCK_SIZE + (before_word[j] & 0x0f)]; // S-Box�� 16 * 16 ����̹Ƿ� (���� 4��Ʈ * 16 + ������ 4��Ʈ)�� ����Ͽ� ã�ư� �� ����.

		// XOR with Rcon[]. Round constant�� �̿��� before_word�� XOR.
		before_word[0] ^= round_constant[i - 1]; // �ش� �� ���� �ش��ϴ� round_constant�� ���ҿ� XOR.
		before_word[1] ^= 0x00; // �������� 0�� XOR�Ͽ� 1�� ����.
		before_word[2] ^= 0x00;
		before_word[3] ^= 0x00;

		// ��ȯ�� before_word�� 4n��° word�� XOR.
		for (j = 0; j < 4; j++)
			word[i][0][j] = before_word[j] ^ word[i - 1][0][j];

		// 4n��° word�� ������ ������ word�� (n - 1)��° word�� XOR.
		for (j = 1; j < 4; j++)
			for (k = 0; k < 4; k++)
				word[i][j][k] = word[i - 1][j][k] ^ word[i][j - 1][k];
	}
}
void AddRoundKey(unsigned char *text, unsigned char(*word)[4][4], int round) {
	int i = 0, j = 0;
	for (i = 0; i < 4; i++)
		for (j = 0; j < 4; j++)
			text[i * 4 + j] ^= word[round][i][j]; // 1����Ʈ ������ ���� Ű�� �� XOR.
}
void SubBytes(unsigned char *text, unsigned char *s_box) {
	int i = 0;
	for (i = 0; i < BLOCK_SIZE; i++)
		text[i] = s_box[(int)(text[i] >> 4) * BLOCK_SIZE + (text[i] & 0x0f)]; // S-Box�� 16 * 16 ����̹Ƿ� (���� 4��Ʈ * 16 + ������ 4��Ʈ)�� ����Ͽ� ã�ư� �� ����.
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
	return column << 1 ^ (column >> 7) * 0x1B; // 2 ���ϱ� ����. ��, �����÷ο찡 ���� �� 0x1B�� �߰��� XOR.
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