#include "XELF.h"


//可以是不经检查的fd
XELF::XELF(FILE *fd)
{
	try
	{
		if (fd == NULL)
		{
			throw "file error";
		}
		fseek(fd, 0L, SEEK_END);
		long length;
		length = ftell(fd);
		fileCache = malloc(length);
		if (fileCache == NULL)
		{
			fclose(fd);
			throw "file error";

		}
		fseek(fd, 0L, SEEK_SET);
		fread(fileCache, length, 1, fd);
		fclose(fd);


		char mag[5];
		memcpy(mag, fileCache, 4);
		mag[4] = 0;
		if (strcmp(mag, ELFMAG)!=0)
		{
			throw "file error";
		}
		doAnalysis();
	}
	catch (const char* msg)
	{
		if (fd!=NULL)
		{
			//fclose(fd);文件fd由外部传递，应该由外部检查关闭
		}
		if (fileCache!=NULL)
		{
			free(fileCache);
		}
		throw;
	}
	
}

//外部应该保证这是elf的cache
XELF::XELF(void *cache)
{
	fileCache = cache;
	doAnalysis();
}

XELF::~XELF()
{

	if (fileCache!=NULL)
	{
		free(fileCache);

	}
}

//开始解析cache
void XELF::doAnalysis()
{
	//判断位数
	switch ((((Elf_Byte*)fileCache)[4]))
	{
	case 1:
		type = e32;
		break;
	case 2:
		type = e64;
		break;
	default:
		type = eunknow;
		break;
	} 

	if (type==e64)
	{
		elf64->header = (Elf64_Ehdr *)fileCache;
	}

	if (type==e32)
	{

	}





}




void XELF::showHeader()
{
	if (type == e64)
	{
		printf("header:\n");
		printf("magic:");
		for (int i=0;i< EI_NIDENT;i++)
		{
			printf("%02X", elf64->header->e_ident[i]);
		}
		printf("\n");
		printf("type:%X\n", elf64->header->e_type);
		printf("machine:%X\n", elf64->header->e_machine);
		printf("version:%X\n", elf64->header->e_version);
		printf("entry:%X\n", elf64->header->e_entry);
		printf("phoff:%X\n", elf64->header->e_phoff);
		printf("shoff:%X\n", elf64->header->e_shoff);
		printf("flags:%X\n", elf64->header->e_flags);
		printf("ehsize:%X\n", elf64->header->e_ehsize);
		printf("phentsize:%X\n", elf64->header->e_phentsize);
		printf("phnum:%X\n", elf64->header->e_phnum);
		printf("shentsize:%X\n", elf64->header->e_shentsize);
		printf("shnum:%X\n", elf64->header->e_shnum);
		printf("shstrndx:%X\n", elf64->header->e_shstrndx);
	}

	if (type == e32)
	{

	}
}