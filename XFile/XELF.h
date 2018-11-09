#pragma once
#include <string>
#include <stdio.h>
#include "elf.h"
#include <exception>  
#include <iostream>
using namespace std;


typedef struct {
	Elf64_Ehdr *header;
} Elf64;
typedef struct {

} Elf32;

//ELF�ļ��ṹ��ʱ��д64λ�ģ�32λ���ټӣ�
//Ŀǰ��ͬ������Ԥ�����Զ��������ṹ��ר�Ŵ洢�����ֵ�ָ�룬ÿ����so�Ĳ�������������ķ�����
//�ɱ��ฺ���ж�32/64֮��ȥѡ�����Ǹ��ṹ��ȥ��������һ��ָ��ָ�������ṹ��֮һ���ɣ��ڽ���ʱ�Ͷ���
//������ELF��صĲ�����Ӧ���������к���
class XELF
{
private:
	void *fileCache;

	void doAnalysis();

	Elf64 *elf64=new Elf64;
	Elf32 *elf32=new Elf32;
	enum type_ {e64,e32,eunknow}type;
	


public:
	XELF(FILE *fd);
	XELF( void *cache);
	~XELF();

	void showHeader();



};

