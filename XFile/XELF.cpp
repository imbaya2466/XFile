#include "XELF.h"


//�����ǲ�������fd
//���캯���ﲻҪ�׳��쳣����������
//TODO:ʹ��mmap���죬�������Ӧ����linux���õ�fd
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
			//fclose(fd);�ļ�fd���ⲿ���ݣ�Ӧ�����ⲿ���ر�
		}
		if (fileCache!=NULL)
		{
			free(fileCache);
		}
		throw;
	}
	
}

//�ⲿӦ�ñ�֤����elf��cache
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

//����cache
void XELF::doAnalysis()
{
	//�ж�λ��
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
		elf._64 = new Elf64;

		doAnalysis(elf._64);
	}

	if (type==e32)
	{
		elf._32 = new Elf32;
		doAnalysis(elf._32);
	}

}

template<typename elfT>
 void XELF::doAnalysis(elfT *elf)
{
	 elf->header = (decltype (elf->header))fileCache;
	 elf->sectionHeader = (decltype (elf->sectionHeader))(fileCache + elf->header->e_shoff);
	 elf->sectionName = fileCache + elf->sectionHeader[elf->header->e_shstrndx].sh_offset;
	 elf->programHeader = (decltype (elf->programHeader))(fileCache + elf->header->e_phoff);
	 for (int i = 0; i < elf->header->e_phnum; i++)
	 {
		 if (elf->programHeader[i].p_type == PT_DYNAMIC)
		 {
			 elf->dynamicSegment = (decltype (elf->dynamicSegment))(fileCache + elf->programHeader[i].p_offset);
		 }
	 }

	 for (int i = 0; elf->dynamicSegment[i].d_tag != DT_NULL; i++)
	 {

		 if (elf->dynamicSegment[i].d_tag == DT_STRTAB)
		 {
			 
			 for (int j = 0; j < elf->header->e_phnum; j++)
			 {
				 auto paddr = elf->programHeader[j].p_vaddr;
				 auto memsz = elf->programHeader[j].p_memsz;
				 auto offset = elf->programHeader[j].p_offset;
				 auto ptr = elf->dynamicSegment[i].d_un.d_ptr;

				 if (paddr <= ptr&&ptr<=paddr+ memsz)
				 {
					 elf->dyn_strtab = (fileCache+offset +  ptr- paddr);
					 goto A;//goto������ѭ��
				 }
			 }

		 }

	 }
	 A:
	 for (int i = 0; elf->dynamicSegment[i].d_tag != DT_NULL; i++)
	 {

		 if (elf->dynamicSegment[i].d_tag == DT_SYMTAB)
		 {

			 for (int j = 0; j < elf->header->e_phnum; j++)
			 {
				 auto paddr = elf->programHeader[j].p_vaddr;
				 auto memsz = elf->programHeader[j].p_memsz;
				 auto offset = elf->programHeader[j].p_offset;
				 auto ptr = elf->dynamicSegment[i].d_un.d_ptr;

				 if (paddr <= ptr && ptr <= paddr + memsz)
				 {
					 elf->dyn_symtab =(decltype (elf->dyn_symtab)) (fileCache + offset + ptr - paddr);
					 goto B;//goto������ѭ��
				 }
			 }

		 }

	 }
	 B:


	 return;


}

 //չʾͷ
void XELF::showHeader()
{
	if (type==e64)
	{
		showHeader<Elf64>(elf._64);
	}
	else if(type==e32)
	{
		showHeader<Elf32>(elf._32);
	}
	
}
template<typename elfT>
void XELF::showHeader(elfT *elf)
{

		printf("header:\n");
		printf("magic:");
		for (int i=0;i< EI_NIDENT;i++)
		{
			printf("%02X ", elf->header->e_ident[i]);
		}
		printf("\n");
		printf("type:0x%X\n", elf->header->e_type);
		printf("machine:0x%X\n", elf->header->e_machine);
		printf("version:0x%X\n", elf->header->e_version);
		printf("entry:0x%X\n", elf->header->e_entry);
		printf("phoff:0x%X\n", elf->header->e_phoff);
		printf("shoff:0x%X\n", elf->header->e_shoff);
		printf("flags:0x%X\n", elf->header->e_flags);
		printf("ehsize:0x%X\n", elf->header->e_ehsize);
		printf("phentsize:0x%X\n", elf->header->e_phentsize);
		printf("phnum:0x%X\n", elf->header->e_phnum);
		printf("shentsize:0x%X\n", elf->header->e_shentsize);
		printf("shnum:0x%X\n", elf->header->e_shnum);
		printf("shstrndx:0x%X\n", elf->header->e_shstrndx);
}

//չʾ�ڱ�
void XELF::showSectionList()
{
	if (type == e64)
	{
		showSectionList<Elf64>(elf._64);
	}
	else if (type == e32)
	{
		showSectionList<Elf32>(elf._32);
	}
}

template<typename elfT>
void XELF::showSectionList(elfT *elf)
{

		auto sectionlist = elf->sectionHeader;
		Elf_Byte *sectionname = elf->sectionName;
		int num = elf->header->e_shnum;
		printf("sectionList:\n");
		for (int i=0;i<num;i++)
		{
			auto lssection = sectionlist[i];
			printf("section0x%02X: name:0x%X(%-15s) ",i,lssection.sh_name,&sectionname[lssection.sh_name]);
			printf("type:0x%X  flag:0x%X  addr:0x%X  offset:0x%X \n\t size:0x%X  link:0x%X  info:0x%X  addralign:0x%X  ensize:0x%X\n"
				,lssection.sh_type,lssection.sh_flags,lssection.sh_addr,lssection.sh_offset,lssection.sh_size,lssection.sh_link,lssection.sh_info,lssection.sh_addralign,lssection.sh_entsize
			);

		}
	
}




void XELF::showSegmentList()
{
	if (type == e64)
	{
		showSegmentList<Elf64>(elf._64);
	}
	else if (type == e32)
	{
		showSegmentList<Elf32>(elf._32);
	}
}


template<typename elfT>
void XELF::showSegmentList(elfT *elf)
{

		auto segmentlist = elf->programHeader;
		int num = elf->header->e_phnum;
		printf("segmentList:\n");
		for (int i=0;i<num;i++)
		{
			auto ls = segmentlist[i];
			printf("segment0x%X:  type:0x%X  flag:0x%X  offset:0x%X  vaddr:0x%X  paddr:0x%X  filesz:0x%X  memsz:0x%X  align:0x%X\n"
				,i,ls.p_type,ls.p_flags,ls.p_offset,ls.p_vaddr,ls.p_paddr,ls.p_filesz,ls.p_memsz,ls.p_align
			);

		}

}




void XELF::showdynsym()
{
	if (type == e64)
	{
		showdynsym<Elf64>(elf._64);
	}
	else if (type == e32)
	{
		showdynsym<Elf32>(elf._32);
	}
}

template<typename elfT>
void XELF::showdynsym(elfT *elf)
{
//����ʱ����Ҫ��̬���ű�Ĵ�С���޷���ͨ���α������С��������ýڱ�ȡ��
//���ֶ�ʵ��so����ؼ���ʱȥ���ڱ���Եõ��ܺõı���Ч�����Ѽ��ز���Ҫ����Ϣȫ��ȥ����
	auto dynsymls = elf->dyn_symtab;
	Elf_Byte *dynstr = elf->dyn_strtab;
	auto sectionlist = elf->sectionHeader;
	Elf_Byte *sectionname = elf->sectionName;
	int num = elf->header->e_shnum;
	int symnum;
	for (int i = 0; i < num; i++)
	{
		auto lssection = sectionlist[i];
		if (lssection.sh_type== SHT_DYNSYM)
		{
			symnum = lssection.sh_size/lssection.sh_entsize;
			break;

		}

	}
	printf("dynsym:\n"
		"Num:   Value    Size     Type    Bind     Ndx    Name \n"
	);
	for (int i=0;i<symnum;i++)
	{

		printf("%2d: 0x%5X  %3d  0x%X  0x%X  0x%X  %s \n",
			i, dynsymls[i].st_value,dynsymls[i].st_size, ELF_ST_TYPE(dynsymls[i].st_info), ELF_ST_BIND(dynsymls[i].st_info),
			dynsymls[i].st_shndx,&dynstr[dynsymls[i].st_name]
			);
	}




}