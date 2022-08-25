#pragma once
#include<iostream>
#include<fstream>

namespace Line__Crypt
{
	static int lwz(int offset, int src)
	{
		return _byteswap_ulong(*reinterpret_cast<int*>(src + offset));
	}

	static int lwbrx(int offset, int src)
	{
		return *reinterpret_cast<int*>(src + offset);
	}

	static void stw(int val, unsigned int offset, unsigned int des)
	{
		*reinterpret_cast<int*>(des + offset) = _byteswap_ulong(val);
	}

	static int mulhwu(unsigned int val1, unsigned int val2)
	{
		long long result = (long long)val1 * (long long)val2;
		result >>= 32;
		return (int)result;
	}

	static int rlwinm(int src, int shift, int maskBeg, int maskEnd)
	{   //inspired by rygorous' example
		int maskBegBin = 0xffffffff >> maskBeg;
		int maskEndBin = 0xffffffff << (31 - maskEnd);
		int bitMask = (maskBeg <= maskEnd) ? maskBegBin & maskEndBin : maskBegBin | maskEndBin;

		return ((src << shift) | (src >> ((32 - shift) & 31))) & bitMask;
	}


	static int LoadEncrypted(std::wstring& filePath, void** out)
	{
		std::ifstream file;
		file.open(filePath, std::ios::binary | std::ios::in);

		if (!file.is_open())
		{
			return 0;
		}

		file.seekg(0, std::ios::end);
		uint64_t size = file.tellg();
		file.seekg(0, std::ios::beg);
		uint64_t sizeWithPadding = (size % 0x20 == 0) ? size : size + 0x20;
	
		*out = calloc(1, sizeWithPadding);

		if (!file.read((char*)*out, size))
		{
			return 0;
		}

		file.close();
		return size;
	}

	static void Decrypt(void* file, uint32_t fileSize)
	{
		//prepare key values and parameters
		int key0 = 0x000cd8f3;
		int key1 = 0x9b36bb94;
		int key2 = 0xaf8910be;
		int salt = 0;
		int fileSizeExtended = (fileSize + 0x1f) & ~0; //filesize next multiple of 0x20
		int fileLocation = reinterpret_cast<int>(file);
		int r8 = rlwinm(fileSizeExtended, 30, 2, 31);
		int cryptedWords = 0;
		int r11 = 0;
		int r12 = 0;
		int r3 = r8 - 1;
		int rwLocation = fileLocation;
		r3 = rlwinm(r3, 29, 3, 31);

		for (int i = r3; i > 0; --i)
		{
			//decrypting 1st 4 bytes of 0x20 bytes block
			int keyProd = key2 * key1;				//mullw r10, r31, r5 ;r10 = 2c8c77d8
			salt = 0x180a;				//li r4, 0x180a; r4 = 0000180a
			r3 = lwz(0, rwLocation);			//lwz r3, 0(r7); load(first) 4 bytes of encrypted file
			int r29 = keyProd + key0;	//addc r29, r10, r0; r29 = 2c9950cb(0x2c8c77d8 + 0x000cd8f3)
			r3 ^= r29;					//xor r3, r3, r29; xor 4 bytes of file with r29(0x2c9950cb).r3 = 0x0bd80f00
			stw(r3, 0, rwLocation);				//stw r3, 0(r7); store xored 4 bytes where they originated from

			//decrypting 2nd 4 bytes of 0x20 bytes block
			r12 = mulhwu(key2, key1);		//mulhwu r12, r31, r5; r12 = 0x6a6d84ab (af8910be * 9b36bb94)
			int val = lwz(4, rwLocation);			//lwz r10, 4(r7); load next 4 encrypted bytes.r10 = 0x4e63f64f
			r3 = 0;				//mullw r3, r6, r5; r3 = 0 (0 * 0x9b36bb94)
			r11 = mulhwu(r29, key1);		//mulhwu r11, r29, r5; r11 = 0x1b0a5cef (0x2c9950cb * 0x>9b36bb94)
			int r26 = r12;				//add r26, r12, r3; r26 = 6a6d84ab(0x6a6d84ab + 0x00000000)
			int r27 = key2 * salt;				//mullw r27, r31, r4; r27 = 0xb4ec776c (af8910be, 0000180a)
			r12 = r11;				//add r12, r11, r3; r12 = 0x1b0a5cef (1b0a5cef, 00000000)
			r26 += r27;					//add r26, r26, r27; r26 = 1f59fc17(6a6d84ab, b4ec776c)
			r11 = r29 * salt;				//mullw r11, r29, r4; r11 = 1d902fee(2c9950cb, 0000180a)
			r27 = r29 * key1;				//mullw r27, r29, r5; r27 = ba78fe5c(2c9950cb, 9b36bb94)
			r12 += r11;					//add r12, r12, r11; r12 = 389a8cdd(1b0a5cef, 1d902fee)
			r29 = r27 + key0;	//addc r29, r27, r0; r29 = ba85d74f(ba78fe5c, 000cd8f3)
			r12 = r29 * key1;				//mullw r12, r29, r5; r12 = d9512eac(ba85d74f, 9b36bb94)
			val ^= r29;					//xor r10, r10, r29; r10 = f4e62100(4E63F64F(loaded from file), ba85d74f)
			stw(val, 4, rwLocation);			//stw r10, 4(r7); store xored 4 bytes where they originated from

			//decrypting 3rd 4 bytes of 0x20 bytes block
			val = lwz(8, rwLocation);			//lwz r10, 8(r7); load next 4 encrypted bytes.r10 = 0x73b3f79e
			key2 = r12 + key0;	//addc r31, r12, r0; r31 = d95e079f(d9512eac, 000cd8f3)
			r11 = mulhwu(r29, key1);		//mulhwu r11, r29, r5; r11 = 7116ea43(ba85d74f, 9b36bb94)
			val ^= key2;					//xor r10, r10, r31; r10 = aaedf001(73b3f79e, d95e079f)
			stw(val, 8, rwLocation);			//stw r10, 8(r7); store xored 4 bytes where they originated from

			//decrypting 4th 4 bytes of 0x20 bytes block
			val = lwz(0xC, rwLocation);			//lwz r10, 0xc(r7); load next 4 encrypted bytes.r10 = 0xdc7c7732
			r12 = r29 * salt;				//mullw r12, r29, r4; r12 = d569d116(ba85d74f, 0000180a)
			r27 = r11;				//add r27, r11, r3; r27 = 7116ea43(7116ea43, 00000000)
			r12 = key2 * key1;				//mullw r12, r31, r5; r12 = 3a778cec(d95e079f, 9b36bb94)
			r29 = r12 + key0;	//addc r29, r12, r0; r29 = 3a8465df(3a778cec, 000cd8f3)
			r11 = mulhwu(key2, key1);		//mulhwu r11, r31, r5; r11 = 83ca67b8(d95e079f, 9b36bb94)
			val ^= r29;					//xor r10, r10, r29; r10 e6f812ed = (dc7c7732, 3a8465df)
			stw(val, 0xC, rwLocation);			//stw r10, 0xc(r7); store xored 4 bytes where they originated from

			//decrypting 5th 4 bytes of 0x20 bytes block
			val = lwz(0x10, rwLocation);		//lwz r10, 0x10(r7); load next 4 encrypted bytes.r10 = 0xfd47482b //ERROR?????????????
			r12 = key2 * salt;				//mullw r12, r31, r4; r12 = 4e633436 (d95e079f, 0000180a)
			r27 = r11;				//add r27, r11, r3; r27 = 83ca67b8(83ca67b8, 00000000)
			r12 = r29 * key1;				//mullw r12, r29, r5; r12 = 0cfec9ec(3a8465df, 9b36bb94)
			key2 = r12 + key0;	//addc r31, r12, r0; r31 = 0d0ba2df(0cfec9ec, 000cd8f3)
			r11 = mulhwu(r29, key1);		//mulhwu r11, r29, r5; r11 = 237aac7c(3a8465df, 9b36bb94)
			val ^= key2;					//xor r10, r10, r31; r10 = f04ceaf4(fd47482b, 0d0ba2df)
			stw(val, 0x10, rwLocation);			//stw r10, 0x10(r7); store xored 4 bytes where they originated from

			//decrypting 6th 4 bytes of 0x20 bytes block
			val = lwz(0x14, rwLocation);		//lwz r10, 0x14(r7); load next 4 encrypted bytes.r10 = 0x4a370b2f
			r12 = r29 * salt;				//mullw r12, r29, r4; r12 = b2b8e2b6(3a8465df, 0000180a)
			r27 = r11;				//add r27, r11, r3; r27 = 237aac7c(237aac7c, 00000000)
			r12 = key2 * key1;				//mullw r12, r31, r5; r12 = 6abd0dec(0d0ba2df, 9b36bb94)
			r27 = r12 + key0;	//addc r27, r12, r0; r27 = 6ac9e6df(6abd0dec, 000cd8f3)
			r11 = mulhwu(key2, key1);		//mulhwu r11, r31, r5; r11 = 07e8d5a0(0d0ba2df, 9b36bb94)
			val ^= r27;					//xor r10, r10, r27; r10 = 20feedf0(4a370b2f, 6ac9e6df)
			stw(val, 0x14, rwLocation);			//stw r10, 0x14(r7); store xored 4 bytes where they originated from

			//decrypting 7th 4 bytes of 0x20 bytes block
			val = lwz(0x18, rwLocation);		//lwz r10, 0x18(r7); load next 4 encrypted bytes.r10 = 0xf3753e21
			r12 = key2 * salt;				//mullw r12, r31, r4; r12 = 99b944b6(0d0ba2df, 0000180a)
			r29 = r11;				//add r29, r11, r3; r29 = 07e8d5a0(07e8d5a0, 00000000)
			r12 = r27 * key1;				//mullw r12, r27, r5; r12 = f0685dec(6ac9e6df, 9b36bb94)
			r29 = r12 + key0;	//addc r29, r12, r0; r29 = f07536df(f0685dec, 000cd8f3)
			r11 = mulhwu(r27, key1);		//mulhwu r11, r27, r5; r11 = 40bf139e(6ac9e6df, 9b36bb94)
			val ^= r29;					//xor r10, r10, r29; r10 = 030008fe(f3753e21, f07536df)
			stw(val, 0x18, rwLocation);			//stw r10, 0x18(r7); store xored 4 bytes where they originated from

			//decrypting 8th 4 bytes of 0x20 bytes block
			val = lwz(0x1C, rwLocation);		//lwz r10, 0x1c(r7); load next 4 encrypted bytes.r10 = 0x9eef6df4
			r12 = r27 * salt;				//mullw r12, r27, r4; r12 = 1987ecb6(6ac9e6df, 0000180a)
			key2 = r11;				//add r31, r11, r3; r31 = 40bf139e(40bf139e, 00000000)
			r12 += key2;					//add r12, r31, r12; r12 = 5a470054(40bf139e, 1987ecb6)
			r11 = mulhwu(r29, key1);		//mulhwu r11, r29, r5; r11 = 91ca6123(f07536df, 9b36bb94)
			r12 = r29 * key1;				//mullw r12, r29, r5; r12 = 3ae29dec(f07536df, 9b36bb94)
			r11 += r3;					//add r11, r11, r3; r11 = 91ca6123(91ca6123, 00000000)
			key2 = r12 + key0;	//addc r31, r12, r0; r31 = 3aef76df(3ae29dec, 000cd8f3)
			r3 = val ^ key2;				//xor r3, r10, r31; r3 = a4001b2b(9eef6df4, 3aef76df)
			stw(r3, 0x1C, rwLocation);			//stw r3, 0x1c(r7); store xored 4 bytes where they originated from

			//prepare salt and rwLocation for next iteration
			salt *= r29;					//mullw r4, r29, r4; r4 = 61b90cb6(f07536df, 0000180a)
			rwLocation += 0x20;		//addi r7, r7, 0x20; increment r7 for next read / write sector of encrypted file.r7 = 8145caa0
			r3 = r11 + salt;				//add r3, r11, r4; r3 = f3836dd9(91ca6123, 61b90cb6)
			cryptedWords += 8;			//addi r9, r9, 8; (r9 = 8) 0 + 8
		}

		if (cryptedWords >= r8)
			return;

		//set parameters for last block processing
		r3 = 0x9b370000;
		int r4 = rlwinm(cryptedWords, 2, 0, 29);		//slwi r4, r9, 2; rlwinm	r4, r9, 2, 0, 29 (3fffffff). (r9 = 0003f600), r4 = 000fd800
		r11 = r3, (short)0xbb94;			//addi r11, r3, 0xbb94; r11 = 9b36bb94
		r3 = 0x000d0000;				//lis r3, 0xd; r3 = 000d0000
		int r0 = r8 - cryptedWords;					//subf r0, r9, r8; r0 = 00000008 (0003f600, 0003f608)
		rwLocation = fileLocation + r4;					//add r26, r28, r4; 8155a280(8145ca80, 000fd800). address of last bytes
		r3 += (short)0xd8f3;			//addi r3, r3, 0xd8f3; 000cd8f3
		salt = 0x180a;					//li r10, 0x180a; 0000180a
	
		//crypt last block
		for (int i = r0; i > 0; --i)
		{
			r4 = mulhwu(key2, r11);		//mulhwu r4, r31, r11; r4 = 7cdc9f97(cdf076df, 9b36bb94)
			r0 = lwz(0, rwLocation);			//lwz r0, 0(r26); load first remaining undecrypted word.r0 = 5f20c231
			int r7 = key2 * r11;				//mullw r7, r31, r11; r7 = cde39dec(cdf076df, 9b36bb94)
			int r5 = r4;				//add r5, r4, r6; r5 = 7cdc9f97(7cdc9f97, 00000000)
			r4 = key2, salt;				//mullw r4, r31, r10; r4 = 96898cb6(cdf076df, 0000180a)
			key2 = r7 + r3;		//addc r31, r7, r3; 31 = cdf076df(cde39dec, 000cd8f3)
			r0 ^= key2;					//xor r0, r0, r31; r0 = 92d0b4ee(5f20c231, cdf076df)
			stw(r0, 0, rwLocation);			//stw r0, 0(r26); store xored 4 bytes where they originated from
			rwLocation += 4;			//addi r26, r26, 4; increment r26 pointer for next read / write
			r0 = r5 + r4;				//add r0, r5, r4; r0 = 13662c4d(7cdc9f97, 96898cb6)
		}								//bdnz 0x360; go to; label_loopDecryptFileEnd.loop ends after 3 more writes(might be unused).same value written for 00 (df cdf076df cdf076df cdf076df)

		return;
	}

	static bool SaveBinary(std::wstring& filePath, void* data, uint64_t size)
	{
		std::ofstream file(filePath, std::ios::binary);
		if(!file)
			return false;

		file.write((char*)data, size);
		file.close();
		return true;
	}
}