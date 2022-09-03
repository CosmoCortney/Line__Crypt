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

	static void Decrypt(void* file, uint32_t fileSize, bool isJPN)
	{
		//prepare key values and parameters
		int saltUSA = 0x180a;
		int saltJPN = 0x0ce0;
		int salt = 0;
		int key0USA = 0x000cd8f3;
		int key0JPN = 0x0004f107;
		int key0 = isJPN ? key0JPN : key0USA;
		int key1USA = 0x9b36bb94;
		int key1JPN = 0xb5fb6483;
		int key1 = isJPN ? key1JPN : key1USA;
		int key2USA = 0xaf8910be;
		int key2JPN = 0xdeaddead;
		int key2 = isJPN ? key2JPN : key2USA;
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
			int keyProd = key2 * key1;
			salt = isJPN ? saltJPN : saltUSA;
			r3 = lwz(0, rwLocation);
			int r29 = keyProd + key0;
			r3 ^= r29;
			stw(r3, 0, rwLocation);

			//decrypting 2nd 4 bytes of 0x20 bytes block
			r12 = mulhwu(key2, key1);
			int val = lwz(4, rwLocation);
			r3 = 0;
			r11 = mulhwu(r29, key1);
			int r26 = r12;
			int r27 = key2 * salt;
			r12 = r11;
			r26 += r27;
			r11 = r29 * salt;
			r27 = r29 * key1;
			r12 += r11;
			r29 = r27 + key0;
			r12 = r29 * key1;
			val ^= r29;
			stw(val, 4, rwLocation);

			//decrypting 3rd 4 bytes of 0x20 bytes block
			val = lwz(8, rwLocation);
			key2 = r12 + key0;
			r11 = mulhwu(r29, key1);
			val ^= key2;
			stw(val, 8, rwLocation);

			//decrypting 4th 4 bytes of 0x20 bytes block
			val = lwz(0xC, rwLocation);
			r12 = r29 * salt;
			r27 = r11;
			r12 = key2 * key1;
			r29 = r12 + key0;
			r11 = mulhwu(key2, key1);
			val ^= r29;
			stw(val, 0xC, rwLocation);

			//decrypting 5th 4 bytes of 0x20 bytes block
			val = lwz(0x10, rwLocation);
			r12 = key2 * salt;
			r27 = r11;
			r12 = r29 * key1;
			key2 = r12 + key0;
			r11 = mulhwu(r29, key1);
			val ^= key2;
			stw(val, 0x10, rwLocation);

			//decrypting 6th 4 bytes of 0x20 bytes block
			val = lwz(0x14, rwLocation);
			r12 = r29 * salt;
			r27 = r11;
			r12 = key2 * key1;
			r27 = r12 + key0;
			r11 = mulhwu(key2, key1);
			val ^= r27;
			stw(val, 0x14, rwLocation);

			//decrypting 7th 4 bytes of 0x20 bytes block
			val = lwz(0x18, rwLocation);
			r12 = key2 * salt;
			r29 = r11;
			r12 = r27 * key1;
			r29 = r12 + key0;
			r11 = mulhwu(r27, key1);
			val ^= r29;
			stw(val, 0x18, rwLocation);

			//decrypting 8th 4 bytes of 0x20 bytes block
			val = lwz(0x1C, rwLocation);
			r12 = r27 * salt;
			key2 = r11;
			r12 += key2;
			r11 = mulhwu(r29, key1);
			r12 = r29 * key1;
			r11 += r3;
			key2 = r12 + key0;
			r3 = val ^ key2;
			stw(r3, 0x1C, rwLocation);

			//prepare salt and rwLocation for next iteration
			salt *= r29;
			rwLocation += 0x20;
			r3 = r11 + salt;
			cryptedWords += 8;
		}

		if (cryptedWords >= r8)
			return;

		//set parameters for last block processing
		r3 = isJPN ? 0xb5fb0000 : 0x9b370000;
		int r4 = rlwinm(cryptedWords, 2, 0, 29);
		r11 = r3 + isJPN ? (short)0x6483 : (short)0xbb94;
		r3 = 0x000d0000;
		int r0 = r8 - cryptedWords;
		rwLocation = fileLocation + r4;
		r3 += isJPN ? (short)0xf107 : (short)0xd8f3;
		salt = isJPN ? saltJPN : saltUSA;
	
		//crypt last block
		for (int i = r0; i > 0; --i)
		{
			r4 = mulhwu(key2, r11);
			r0 = lwz(0, rwLocation);
			int r7 = key2 * r11;
			int r5 = r4;
			r4 = key2, salt;
			key2 = r7 + r3;
			r0 ^= key2;
			stw(r0, 0, rwLocation);
			rwLocation += 4;
			r0 = r5 + r4;
		}

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