#include"Line__Crypt.h"

int wmain(int argc, wchar_t** argv)
{
	if (argc <= 1)
	{
		std::cout << "empty argument";
		return 3;
	}

	std::wstring path(argv[1]);
	void* file = nullptr;

	int size = Line__Crypt::LoadEncrypted(path, &file);

	if (size == 0)
	{
		std::wcout << "Error loading file: " << path;
		return 1;
	}

	Line__Crypt::Decrypt(file, size);

	std::wcout << "bleh " << path.substr(0, path.length() - 3);
	if (!path.substr(path.length() - 3).compare(L"bin"))
	{
		path = path.substr(0, path.length() - 3).append(L"rel.lz");
	}
	else if (!path.substr(path.length() - 6).compare(L"rel.lz"))
	{
		path = path.substr(0, path.length() - 6).append(L"bin");
	}
	else
	{
		path.append(L"_");
	}

	if (!Line__Crypt::SaveBinary(path, file, size))
	{
		std::wcout << "Error saving file: " << path;
		free(file);
		return 2;
	}

	std::cout << "File processed";
	free(file);
	return 0;
}