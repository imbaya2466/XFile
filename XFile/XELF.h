#pragma once
#include <string>
#include <stdio.h>
#include "elf.h"
#include <exception>  
#include <iostream>
using namespace std;


typedef struct {
	Elf64_Ehdr *header;
	Elf64_Shdr *sectionHeader;
	Elf_Byte   *sectionName;
	Elf64_Phdr *programHeader;

	Elf64_Dyn  *dynamicSegment;

	//dynamic�е����ݣ�
	Elf_Byte *dyn_strtab;
	Elf64_Sym *dyn_symtab;

} Elf64;
typedef struct {
	Elf32_Ehdr *header;
	Elf32_Shdr *sectionHeader;
	Elf_Byte   *sectionName;
	Elf32_Phdr *programHeader;
	Elf32_Dyn  *dynamicSegment;

	//dynamic�е����ݣ�
	Elf_Byte *dyn_strtab;
	Elf32_Sym *dyn_symtab;
} Elf32;

//ELF�ļ��ṹ��ʱ��д64λ�ģ�32λ���ټӣ�
//������ELF��صĲ�����Ӧ���������к���
class XELF
{
private:
	Elf_Byte *fileCache;

	

	union elf_ {
		Elf32 *_32;
		Elf64 *_64;
		void *p;
	} elf;
	enum type_ {e64,e32,eunknow}type;
	
	void doAnalysis();
	template<typename elfT>
	void doAnalysis(elfT *elf);

	template<typename elfT>
	void showHeader(elfT *elf);

	template<typename elfT>
	void showSectionList(elfT *elf);

	template<typename elfT>
	void showSegmentList(elfT *elf);

	template<typename elfT>
	void showdynsym(elfT *elf);

public:
	XELF(FILE *fd);
	XELF( void *cache);
	~XELF();



	void showHeader();
	void showSectionList();
	void showSegmentList();
	void showdynsym();





};

