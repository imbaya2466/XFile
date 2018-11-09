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
		fileCache = (Elf_Byte*)malloc(length);
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
	fileCache = (Elf_Byte*)cache;
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
		elf64 = new Elf64;
		elf64->header = (Elf64_Ehdr *)fileCache;
		elf64->sectionHeader = (Elf64_Shdr *)(fileCache+elf64->header->e_shoff);
		elf64->sectionName = fileCache+elf64->sectionHeader[elf64->header->e_shstrndx].sh_offset;
		elf64->programHeader = (Elf64_Phdr *)(fileCache+elf64->header->e_phoff);




	}

	if (type==e32)
	{
		elf32 = new Elf32;


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
			printf("%02X ", elf64->header->e_ident[i]);
		}
		printf("\n");
		printf("type:0x%X\n", elf64->header->e_type);
		printf("machine:0x%X\n", elf64->header->e_machine);
		printf("version:0x%X\n", elf64->header->e_version);
		printf("entry:0x%X\n", elf64->header->e_entry);
		printf("phoff:0x%X\n", elf64->header->e_phoff);
		printf("shoff:0x%X\n", elf64->header->e_shoff);
		printf("flags:0x%X\n", elf64->header->e_flags);
		printf("ehsize:0x%X\n", elf64->header->e_ehsize);
		printf("phentsize:0x%X\n", elf64->header->e_phentsize);
		printf("phnum:0x%X\n", elf64->header->e_phnum);
		printf("shentsize:0x%X\n", elf64->header->e_shentsize);
		printf("shnum:0x%X\n", elf64->header->e_shnum);
		printf("shstrndx:0x%X\n", elf64->header->e_shstrndx);
	}

	if (type == e32)
	{

	}
}

void XELF::showSectionList()
{
	if (type==e64)
	{
		Elf64_Shdr *sectionlist = elf64->sectionHeader;
		Elf_Byte *sectionname = elf64->sectionName;
		int num = elf64->header->e_shnum;
		printf("sectionList:\n");
		for (int i=0;i<num;i++)
		{
			Elf64_Shdr lssection = sectionlist[i];
			printf("section0x%02X: name:0x%X(%-15s) ",i,lssection.sh_name,&sectionname[lssection.sh_name]);
			printf("type:0x%X  flag:0x%X  addr:0x%X  offset:0x%X \n\t size:0x%X  link:0x%X  info:0x%X  addralign:0x%X  ensize:0x%X\n"
				,lssection.sh_type,lssection.sh_flags,lssection.sh_addr,lssection.sh_offset,lssection.sh_size,lssection.sh_link,lssection.sh_info,lssection.sh_addralign,lssection.sh_entsize
			);

		}
	}
}

void XELF::showSegmentList()
{
	if (type==e64)
	{
		Elf64_Phdr *segmentlist = elf64->programHeader;
		int num = elf64->header->e_phnum;
		printf("segmentList:\n");
		for (int i=0;i<num;i++)
		{
			Elf64_Phdr ls = segmentlist[i];
			printf("segment0x%X:  type:0x%X  flag:0x%X  offset:0x%X  vaddr:0x%X  paddr:0x%X  filesz:0x%X  memsz:0x%X  align:0x%X\n"
				,i,ls.p_type,ls.p_flags,ls.p_offset,ls.p_vaddr,ls.p_paddr,ls.p_filesz,ls.p_memsz,ls.p_align
			);



		}


	}
}